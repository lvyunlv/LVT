#include "emp-aby/lvt.h"
#include "emp-aby/io/multi-io.hpp"
#include "testLLM/FixedPointConverter.h"
#include <memory>
#include <atomic>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string_view>
using namespace emp;

int party, port;
const static int threads = 32;
int num_party;
int m_bits = 24; // 表值比特数，在B2L和L2B中为1，在非线性函数计算调用时为24（表示Q8.16定点整数）
int m_size = 1 << m_bits; // 表值大小
int num = 24;
int tb_size = 1ULL << num; // 表的大小

// 并行读取和处理输入文件
std::vector<Plaintext> parallel_load_input(const std::string& input_file, int party, int m_bits, ThreadPool& pool) {
    if (!fs::exists(input_file)) {
        std::cerr << "Error: input file does not exist: " << input_file << std::endl;
        return {};
    }
    
    // 首先读取整个文件内容
    std::vector<std::string> lines;
    {
        std::ifstream in_file(input_file);
        std::string line;
        while (std::getline(in_file, line)) {
            lines.push_back(line);
        }
    }
    
    // 预分配结果向量
    size_t line_count = lines.size();
    std::vector<Plaintext> x_share(line_count);
    
    // 并行处理每一行
    std::vector<std::future<void>> futures;
    size_t block_size = (line_count + threads - 1) / threads;
    
    for (size_t t = 0; t < threads && t * block_size < line_count; t++) {
        size_t start = t * block_size;
        size_t end = std::min(line_count, start + block_size);
        
        futures.push_back(pool.enqueue([&, start, end, party, m_bits]() {
            for (size_t i = start; i < end; i++) {
                if (party == 1) {
                    float xval = std::stod(lines[i]);
                    uint64_t xval_int = FixedPointConverter::encode(xval);
                    
                    if (xval_int > (1ULL << m_bits) - 1) {
                        std::cout << "Warning: input value exceeds table size: " << xval_int << std::endl;
                        // 截断为表大小
                        xval_int = (1ULL << m_bits) - 1;
                    }
                    
                    x_share[i].assign(xval_int);
                } else {
                    x_share[i].assign("0");
                }
            }
        }));
    }
    
    // 等待所有处理完成
    for (auto& fut : futures) fut.get();
    
    return x_share;
}

// 并行生成密文
std::vector<Ciphertext> parallel_encrypt(const std::vector<Plaintext>& x_share, 
                                        const ELGL_PK& global_pk, 
                                        ThreadPool& pool) {
    size_t x_size = x_share.size();
    std::vector<Ciphertext> x_cipher(x_size);
    
    std::vector<std::future<void>> futures;
    size_t block_size = (x_size + threads - 1) / threads;
    
    for (size_t t = 0; t < threads && t * block_size < x_size; t++) {
        size_t start = t * block_size;
        size_t end = std::min(x_size, start + block_size);
        
        futures.push_back(pool.enqueue([&, start, end]() {
            for (size_t i = start; i < end; i++) {
                x_cipher[i] = global_pk.encrypt(x_share[i]);
            }
        }));
    }
    
    // 等待所有加密完成
    for (auto& fut : futures) fut.get();
    
    return x_cipher;
}

// 并行处理结果
std::vector<float> parallel_process_results(std::vector<Plaintext>& out, 
                                           ELGL<MultiIOBase>* elgl, 
                                           MPIOChannel<MultiIOBase>* io,
                                           int party, 
                                           int num_party, 
                                           const Plaintext& value_field,
                                           ThreadPool& pool) {
    size_t x_size = out.size();
    std::vector<float> out_sum_float(x_size);
    std::vector<Plaintext> out_sum(x_size);
    
    // 第1阶段: 所有方交换shares并计算总和
    for (int i = 0; i < x_size; ++i) {
        out_sum[i] = out[i];
    }
    
    // 批量序列化本地shares为一个字符串流
    std::stringstream shares_stream;
    for (int i = 0; i < x_size; ++i) {
        out[i].pack(shares_stream);
    }
    
    // 获取序列化数据
    std::string shares_str = shares_stream.str();
    const char* shares_data = shares_str.c_str();
    int shares_size = shares_str.size();
    
    // 并行发送shares给其他方
    std::vector<std::future<void>> send_futures;
    for (int j = 1; j <= num_party; j++) {
        if (j != party) {
            send_futures.push_back(pool.enqueue([io, j, shares_data, shares_size]() {
                io->send_data(j, shares_data, shares_size);
            }));
        }
    }
    
    // 并行接收和处理其他方的shares
    std::vector<std::future<void>> recv_futures;
    std::mutex out_sum_mutex;
    
    for (int j = 1; j <= num_party; j++) {
        if (j != party) {
            recv_futures.push_back(pool.enqueue([&out_sum, &out_sum_mutex, io, j, x_size, &value_field]() {
                // 接收数据
                int data_len = 0;
                void* recv_data = io->recv_data(j, data_len);
                
                if (recv_data) {
                    // 反序列化接收到的数据
                    std::stringstream ss;
                    ss.write(static_cast<char*>(recv_data), data_len);
                    free(recv_data);
                    
                    // 逐一解包并累加
                    std::vector<Plaintext> recv_shares(x_size);
                    for (int i = 0; i < x_size; ++i) {
                        recv_shares[i].unpack(ss);
                        
                        // 线程安全地累加到out_sum
                        std::lock_guard<std::mutex> lock(out_sum_mutex);
                        out_sum[i] += recv_shares[i];
                        out_sum[i] = out_sum[i] % value_field;
                    }
                }
            }));
        }
    }
    
    // 等待所有发送和接收完成
    for (auto& fut : send_futures) fut.get();
    for (auto& fut : recv_futures) fut.get();
    
    // 第2阶段: 验证所有方的结果一致性并转换为float
    // 批量序列化结果
    std::stringstream result_stream;
    for (int i = 0; i < x_size; ++i) {
        out_sum[i].pack(result_stream);
    }
    
    // 获取序列化数据
    std::string result_str = result_stream.str();
    const char* result_data = result_str.c_str();
    int result_size = result_str.size();
    
    // 并行发送结果给其他方
    send_futures.clear();
    for (int j = 1; j <= num_party; j++) {
        if (j != party) {
            send_futures.push_back(pool.enqueue([io, j, result_data, result_size]() {
                io->send_data(j, result_data, result_size);
            }));
        }
    }
    
    // 接收并验证结果
    recv_futures.clear();
    std::atomic<bool> results_match(true);
    
    for (int j = 1; j <= num_party; j++) {
        if (j != party) {
            recv_futures.push_back(pool.enqueue([&results_match, io, j, x_size, &out_sum]() {
                // 接收数据
                int data_len = 0;
                void* recv_data = io->recv_data(j, data_len);
                
                if (recv_data) {
                    // 反序列化接收到的数据
                    std::stringstream ss;
                    ss.write(static_cast<char*>(recv_data), data_len);
                    free(recv_data);
                    
                    // 逐一解包并验证
                    std::vector<Plaintext> recv_results(x_size);
                    for (int i = 0; i < x_size; ++i) {
                        recv_results[i].unpack(ss);
                        
                        if (recv_results[i].get_message().getUint64() != out_sum[i].get_message().getUint64()) {
                            results_match = false;
                        }
                    }
                }
            }));
        }
    }
    
    // 等待所有发送和接收完成
    for (auto& fut : send_futures) fut.get();
    for (auto& fut : recv_futures) fut.get();
    
    if (!results_match) {
        std::cerr << "Error: Results don't match across parties" << std::endl;
    }
    
    // 并行转换结果为float
    std::vector<std::future<void>> convert_futures;
    size_t block_size = (x_size + threads - 1) / threads;
    
    for (size_t t = 0; t < threads && t * block_size < x_size; t++) {
        size_t start = t * block_size;
        size_t end = std::min(x_size, start + block_size);
        
        convert_futures.push_back(pool.enqueue([&out_sum_float, &out_sum, start, end]() {
            for (size_t i = start; i < end; i++) {
                out_sum_float[i] = FixedPointConverter::decode(out_sum[i].get_message().getUint64());
            }
        }));
    }
    
    // 等待所有转换完成
    for (auto& fut : convert_futures) fut.get();
    
    return out_sum_float;
}

int main(int argc, char** argv) {
    BLS12381Element::init();
    if (argc < 5) {
        std::cout << "Format: <PartyID> <port> <num_parties> <func_name> [file_format]" << std::endl;
        return 0;
    }
    parse_party_and_port(argv, &party, &port);
    num_party = std::stoi(argv[3]);
    std::string func_name = argv[4];
    
    // Default to text format if not specified
    std::string file_format = "txt";
    if (argc >= 6) {
        file_format = argv[5];
    }
    bool use_binary = (file_format == "bin");

    std::vector<std::pair<std::string, unsigned short>> net_config;
    if (argc >= 7) {
        const char* file = argv[6];
        FILE* f = fopen(file, "r");
        for (int i = 0; i < num_party; ++i) {
            char* c = (char*)malloc(15 * sizeof(char));
            uint p;
            fscanf(f, "%s %d\tb_size", c, &p);
            net_config.push_back(std::make_pair(std::string(c), p));
            fflush(f);
        }
        fclose(f);
    } else {
        for (int i = 0; i < num_party; ++i) {
            net_config.push_back({ "127.0.0.1", port + 4 * num_party * i });
        }
    }

    ThreadPool pool(threads);
    auto io = std::make_unique<MultiIO>(party, num_party, net_config);
    auto elgl = std::make_unique<ELGL<MultiIOBase>>(num_party, io.get(), &pool, party);

    // 测试时间和通信
    int bytes_start = io.get()->get_total_bytes_sent();
    auto t1 = std::chrono::high_resolution_clock::now();

    Fr alpha_fr = alpha_init(num);
    std::unique_ptr<LVT<MultiIOBase>> lvt;
    LVT<MultiIOBase>* lvt_raw = nullptr;

    LVT<MultiIOBase>::initialize_fake(func_name, lvt_raw, num_party, party, io.get(), &pool, elgl.get(), alpha_fr, num, m_bits);
    lvt.reset(lvt_raw);
    Plaintext tb_field = Plaintext(tb_size);
    Plaintext value_field = Plaintext(m_size);

    int bytes_end = io->get_total_bytes_sent();
    auto t2 = std::chrono::high_resolution_clock::now();
    float comm_kb = float(bytes_end - bytes_start) / 1024.0 / 1024.0;
    float time_ms = std::chrono::duration<float, std::milli>(t2 - t1).count() / 1000.0;
    cout << "Offline time: " << time_ms << " s, comm: " << comm_kb << " MB" << std::endl;

    // 准备输入和输出文件路径
    std::string input_base = "/workspace/Baghaw/LVT/LVT/build/Input/Input-P";
    std::string input_file = use_binary ? input_base + ".bin" : input_base + ".txt";
    
    // 读取输入数据
    std::vector<Plaintext> x_share;
    int x_size = 0;
    
    if (use_binary) {
        // 二进制模式读取（使用mmap优化）
        int fd = open(input_file.c_str(), O_RDONLY);
        if (fd < 0) {
            std::cerr << "Error: Cannot open binary input file: " << input_file << std::endl;
            return 1;
        }
        struct stat sb;
        if (fstat(fd, &sb) < 0) {
            std::cerr << "Error: fstat failed on input file: " << input_file << std::endl;
            close(fd);
            return 1;
        }
        void* mapped = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (mapped == MAP_FAILED) {
            std::cerr << "Error: mmap failed on input file: " << input_file << std::endl;
            close(fd);
            return 1;
        }
        // 先读取长度信息（int32_t），再读取float数据
        int32_t* len_ptr = reinterpret_cast<int32_t*>(mapped);
        int32_t length = *len_ptr;
        float* values = reinterpret_cast<float*>((char*)mapped + sizeof(int32_t));
        x_size = length;
        x_share.resize(x_size);
        // 转换为Plaintext
        for (int i = 0; i < x_size; ++i) {
            if (party == 1) {
                uint64_t xval_int = FixedPointConverter::encode(values[i]);
                if (xval_int > (1ULL << m_bits) - 1) {
                    std::cout << "Warning: input value exceeds table size: " << xval_int << std::endl;
                    xval_int = (1ULL << m_bits) - 1;
                }
                x_share[i].assign(xval_int);
            } else {
                x_share[i].assign("0");
            }
        }
        munmap(mapped, sb.st_size);
        close(fd);
        std::cout << "Read " << x_size << " values from binary file" << std::endl;
    } else {
        // 文本模式读取
        x_share = parallel_load_input(input_file, party, m_bits, pool);
        if (x_share.empty()) {
            return 1; // 加载输入失败
        }
        x_size = x_share.size();
    }
    
    // 每个参与方广播自己的输入个数，并验证一致性
    Plaintext x_size_pt; x_size_pt.assign(x_size);
    elgl.get()->serialize_sendall(x_size_pt);
    for (int i = 1; i <= num_party; i++) {
        if (i != party) {
            Plaintext x_size_pt_recv;
            elgl.get()->deserialize_recv(x_size_pt_recv, i);
            if (int(x_size_pt_recv.get_message().getUint64()) != x_size) {
                std::cerr << "Error: input size does not match in Party: " << party << std::endl;
                return 1;
            }
        }
    }
    
    //  ************* ************* 正式测试内容 ************* ************* 
    // 并行生成密文
    std::vector<Ciphertext> x_cipher = parallel_encrypt(x_share, lvt->global_pk, pool);

    int bytes_start1 = io->get_total_bytes_sent();
    auto t3 = std::chrono::high_resolution_clock::now();
    // 准备空的x_ciphers向量
    std::vector<std::vector<Ciphertext>> x_ciphers(x_size);
    auto [out, out_ciphers] = lvt->lookup_online_batch(x_share, x_cipher, x_ciphers);
    //  ************* ************* 测试内容结束 ************* ************* 

    int bytes_end1 = io->get_total_bytes_sent();
    auto t4 = std::chrono::high_resolution_clock::now();
    float comm_kb1 = float(bytes_end1 - bytes_start1) / 1024.0 / 1024.0;
    float time_ms1 = std::chrono::duration<float, std::milli>(t4 - t3).count() / 1000.0;
    cout << "Online time: " << time_ms1 << " s, comm: " << comm_kb1 << " MB" << std::endl;

    // 并行处理和验证结果
    std::vector<float> out_sum_float = parallel_process_results(out, elgl.get(), io.get(), party, num_party, value_field, pool);

    // 输出结果
    if (party == 1) {
        std::string output_base = "/workspace/Baghaw/LVT/LVT/build/Output/Output";
        std::string output_file = use_binary ? output_base + ".bin" : output_base + ".txt";
        
        if (use_binary) {
            // 二进制模式输出（优化：一次性写入长度和数据）
            std::ofstream outfile(output_file, std::ios::binary | std::ios::trunc);
            if (!outfile) {
                std::cerr << "Error: Cannot open binary output file: " << output_file << std::endl;
                return 1;
            }
            int32_t length = static_cast<int32_t>(out_sum_float.size());
            outfile.write(reinterpret_cast<const char*>(&length), sizeof(int32_t)); // 写入长度头
            if (!out_sum_float.empty()) {
                outfile.write(reinterpret_cast<const char*>(out_sum_float.data()), out_sum_float.size() * sizeof(float)); // 批量写入float数据
            }
            std::cout << "Wrote " << out_sum_float.size() << " values to binary file" << std::endl;
        } else {
            // 文本模式输出
            std::stringstream output_content;
            for (int i = 0; i < x_size; ++i) {
                output_content << out_sum_float[i] << std::endl;
            }
            
            std::ofstream out_file(output_file, std::ios::trunc);
            if (!out_file) {
                std::cerr << "Error: Cannot open text output file: " << output_file << std::endl;
                return 1;
            }
            out_file << output_content.str();
        }
    }

    return 0;
}
