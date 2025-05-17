#include "emp-aby/lvt.h"
#include "emp-aby/io/multi-io.hpp"
#include "testLYL/L2B.hpp"
#include "testLYL/B2L.hpp"
#include "testLYL/A2L_spdz2k.hpp"
#include "testLYL/L2A_spdz2k.hpp"
#include "testLLM/FixedPointConverter.h"
#include <memory>
#include <filesystem>
#include <bitset>
#include <string>
#include <cmath>

using namespace emp;
namespace fs = std::filesystem;

// GELU 函数实现

// 原函数示例：Sigmoid 和 Tanh
static double sigmoid(double x) { return 1.0/(1.0+std::exp(-x)); }
static double tanh_f(double x)    { return std::tanh(x); }

int num_party, party, port;
const static int threads = 8;
const int m_bits = 24; // 表值比特数，在B2L和L2B中为1，在非线性函数计算调用时为24（表示Q8.16定点整数）
const int m_size = 1UL << m_bits; // 表值大小
const int num = 12;
const size_t tb_size = 1ULL << num; // 表的大小
const int frac = 16; // 截断
const int bitN = 1;


int main(int argc, char** argv) {
    BLS12381Element::init();
    if (argc < 5) {
        std::cout << "Format: <PartyID> <port> <num_parties> <func_name>" << std::endl;
        return 0;
    }
    parse_party_and_port(argv, &party, &port);
    num_party = std::stoi(argv[3]);
    std::string func_name = argv[4];
    std::string filebit = "2";
    std::string fileA = func_name + "_A";
    std::string fileB = func_name + "_delta";
    std::string input_file = "../../TestLLM/Input/Input-P" + std::to_string(party) + ".txt";

    std::vector<std::pair<std::string, unsigned short>> net_config;
    if (argc == 6) {
        const char* file = argv[5];
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
    TinyMAC<MultiIOBase> tiny(elgl.get());
    SPDZ2k<MultiIOBase> spdz2k(elgl.get());
    mcl::Vint modulo = m_size;
    Fr alpha_fr_bit = alpha_init(bitN);
    Fr alpha_frA = alpha_init(num);
    Fr alpha_frB = alpha_init(num);
    std::unique_ptr<LVT<MultiIOBase>> lvt_bit, lvtA, lvtB;
    LVT<MultiIOBase>* lvt_raw_bit = nullptr; LVT<MultiIOBase>* lvt_rawA = nullptr; LVT<MultiIOBase>* lvt_rawB = nullptr;

    LVT<MultiIOBase>::initialize(filebit, lvt_raw_bit, num_party, party, io.get(), &pool, elgl.get(), alpha_fr_bit, bitN, m_bits);
    lvt_bit.reset(lvt_raw_bit);
    LVT<MultiIOBase>::initialize(fileA, lvt_rawA, num_party, party, io.get(), &pool, elgl.get(), alpha_frA, num, m_bits);
    lvtA.reset(lvt_rawA);
    LVT<MultiIOBase>::initialize(fileB, lvt_rawB, num_party, party, io.get(), &pool, elgl.get(), alpha_frB, num, m_bits);
    lvtB.reset(lvt_rawB);
    // lvt_bit->global_pk.get_pk().print_str();
    // lvtA->global_pk.get_pk().print_str();
    // lvtB->global_pk.get_pk().print_str();

    // 输入是一个向量，每个元素是一个double类型的值，编码为24比特定点整数（精度为16比特）
    std::vector<Plaintext> x_share;
    {
        // 判断文件是否存在
        if (!fs::exists(input_file)) {
            std::cerr << "Error: input file does not exist: " << input_file << std::endl;
            return 1;
        }
        std::ifstream in_file(input_file);
        std::string line;
        while (std::getline(in_file, line)) {
            double xval = std::stod(line);
            uint64_t xval_int = FixedPointConverter::encode(xval);

            Plaintext x;
            x.assign(xval_int);
            x_share.push_back(x);
            if (x.get_message().getUint64() > (1ULL << m_bits) - 1) {
                std::cerr << "Error: input value exceeds table size in Party: " << party << std::endl;
                cout << "Error value: " << x.get_message().getUint64() << ", tb_size = " << (1ULL << m_bits) << endl;
                return 1;
            }
        }
    }
    int x_size = x_share.size();
    // 每个参与方广播自己的输入个数，判断所有参与方的输入个数是否一致
    Plaintext x_size_pt; x_size_pt.assign(x_size);
    elgl->serialize_sendall(x_size_pt);
    for (int i = 1; i <= num_party; i++) {
        if (i != party) {
            Plaintext x_size_pt_recv;
            elgl->deserialize_recv(x_size_pt_recv, i);
            if (x_size_pt_recv.get_message().getUint64() != x_size) {
                std::cerr << "Error: input size does not match in Party: " << party << std::endl;
                return 1;
            }
        }
    }

    // 计算当前party自己x的share的密文，共同恢复x明文
    std::vector<Ciphertext> x_cipher(x_size);
    std::vector<uint64_t> x_int(x_size);
    for (int i = 0; i < x_size; ++i) {
        x_cipher[i] = lvtA->global_pk.encrypt(x_share[i]);
        x_int[i] = lvtA->Reconstruct_interact(x_share[i], x_cipher[i], elgl.get(), lvtA->global_pk, lvtA->user_pk, io.get(), &pool, party, num_party, modulo).get_message().getUint64();
    }

    // 对x明文进行解码并进行tanh计算，作为基准，后续进行误差测试
    std::vector<double> x_real, real_fx;
    for (int i = 0; i < x_size; ++i) {
        x_real.push_back(FixedPointConverter::decode(x_int[i]));
        double tanh = tanh_f(x_real[i]); 
        real_fx.push_back(tanh);
    }

    // 利用L2B协议，对x的share进行布尔化
    std::vector<std::vector<TinyMAC<MultiIOBase>::LabeledShare>> lut_input_bool_first(x_size, std::vector<TinyMAC<MultiIOBase>::LabeledShare>(num));
    std::vector<std::vector<TinyMAC<MultiIOBase>::LabeledShare>> lut_input_bool_last(x_size, std::vector<TinyMAC<MultiIOBase>::LabeledShare>(num));
    std::vector<std::vector<Ciphertext>> x_cips(x_size, std::vector<Ciphertext>(num_party));
    // 计算L2B的输入
    for (int i = 0; i < x_size; ++i) {
        x_cips[i][party - 1] = lvtA->global_pk.encrypt(x_share[i]);
        elgl->serialize_sendall(x_cips[i][party - 1]);
        for (int j = 0; j < num_party; ++j) {
            if (j != party - 1) {
                elgl->deserialize_recv(x_cips[i][j], j + 1);
            }
        }
    }
    // 使用L2B协议计算布尔化后的x的share，然后利用extract_first_12_shares算法把x的share拆分为2个12比特长度的share
    for (int i = 0; i < x_size; ++i) {
        auto x_bool = L2B::L2B(elgl.get(), lvt_bit.get(), tiny, party, num_party, io.get(), &pool, m_size, m_bits, x_share[i], x_cips[i]);
        tiny.extract_first_12_shares(lut_input_bool_first[i], x_bool);
        tiny.extract_last_12_shares(lut_input_bool_last[i], x_bool); 
    }

    // 由于lvt的share形式是明文和密文的组合，因此需要把x的share拆分为2个12比特长度的share，通过B2L协议得到lvt形式的share：（X_H，X_H_cips）。这样就可以把（X_H，X_H_cips）作为输入调用lvt协议分别查找2个表值。
    std::vector<Plaintext> X_H(x_size);
    std::vector<std::vector<Ciphertext>> X_H_cips(x_size, std::vector<Ciphertext>(num_party));
    for (int i = 0; i < x_size; ++i) {
        auto [plain, cips] = B2L::B2L(elgl.get(), lvt_bit.get(), tiny, party, num_party, io.get(), &pool, lut_input_bool_first[i], tb_size);
        X_H[i] = plain; X_H_cips[i] = cips;
    }
    // 从修正值的布尔share lut_input_bool_last恢复出修正值的明文x_l，并进行解码
    vector<uint64_t> x_l(x_size);
    vector<double> x_l_real;
    for (int i = 0; i < x_size; ++i) {
        x_l[i] = tiny.bits_to_decimal(lut_input_bool_last[i], modulo.getLow32bit());
        x_l_real.push_back(FixedPointConverter::decode(x_l[i]));
    }

    // 利用lvt的lookup_online协议，（X_H，X_H_cips）作为输入调用lvt协议分别查找2个表值，输出为lvt share形式，A_share的和就以及B_share的和就是真正的查表结果的24定点整数编码。
    std::vector<Plaintext> A_share(x_size), B_share(x_size);
    std::vector<std::vector<Ciphertext>> A_cips(x_size, std::vector<Ciphertext>(num_party));
    std::vector<std::vector<Ciphertext>> B_cips(x_size, std::vector<Ciphertext>(num_party));
    for (int i = 0; i < x_size; ++i) {
        auto [out1, out2] = lvtA->lookup_online(X_H[i], X_H_cips[i][party-1], X_H_cips[i]);
        auto [out3, out4] = lvtB->lookup_online(X_H[i], X_H_cips[i][party-1], X_H_cips[i]);
        A_share[i] = out1; B_share[i] = out3;
        A_cips[i] = out2; B_cips[i] = out4;
    }

    // 计算插值
    std::vector<double> interpolated_result(x_size);
    for (int i = 0; i < x_size; ++i) {
        // 从A_share和B_share恢复出他们的和A_和B_
        Plaintext A_ = lvtA->Reconstruct(A_share[i], A_cips[i], elgl.get(), lvtA->global_pk, lvtA->user_pk, io.get(), &pool, party, num_party, modulo);
        Plaintext B_ = lvtB->Reconstruct(B_share[i], B_cips[i], elgl.get(), lvtB->global_pk, lvtB->user_pk, io.get(), &pool, party, num_party, modulo);

        // 解码A_和B_，得到A_val和B_val，然后计算插值结果
        double A_val = FixedPointConverter::decode(A_.get_message().getUint64());
        double B_val = FixedPointConverter::decode(B_.get_message().getUint64());
        
        // 利用之前计算的修正值计算插值的值
        interpolated_result[i] = A_val + B_val * x_l_real[i];

        cout << "[INTERPOLATED] f(x_" << i << ") = " << interpolated_result[i] << endl;
    }

    // 进行误差测试
    std::vector<double> abs_error(x_size);
    double max_error = 0, total_error = 0;
    for (int i = 0; i < x_size; ++i) {
        abs_error[i] = std::fabs(interpolated_result[i] - real_fx[i]);
        max_error = std::max(max_error, abs_error[i]);
        total_error += abs_error[i];
        cout << "[ERROR] f_true(x_" << i << ") = " << real_fx[i] 
            << ", f_interp = " << interpolated_result[i]
            << ", abs_error = " << abs_error[i] << endl;
    }
    cout << "\n====== Interpolation Error Summary ======\n";
    cout << "Max Error: " << max_error << endl;
    cout << "Mean Error: " << total_error / x_size << endl;

    // // std::string output_file = "../../TestLYL/Output/Output-P" + std::to_string(party) + ".txt";
    // // {
    // //     std::ofstream out_file(output_file, std::ios::trunc);
    // //     for (int i = 0; i < x_size; ++i) {
    // //         out_file << X_H[i].get_message().getStr() << X_L[i].get_message().getStr() << std::endl;
    // //     }
    // // }

    return 0;
}
