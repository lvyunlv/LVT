#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <map>
#include <iomanip>
#include <random>
#include <chrono>

#include "emp-aby/io/multi-io.hpp"
#include "emp-tool/utils/ThreadPool.h"
#include "emp-aby/elgl_interface.hpp"
#include "emp-aby/lvt.h"

using namespace emp;
// 全局参数：PartyID, Port, 总参与方数
int party, port;
int num_party;
const static int threads = 8;

// 声明测试函数，用于预生成查表所需分享表
template<typename IO>
void test_generate_shares(LVT<IO>* lut);

int main(int argc, char** argv) {
    if (argc != 6) {
        std::cerr << "Usage: <party> <port> <num_party> <input_file> <output_file>\n";
        return 1;
    }
    // 初始化 BLS 秘钥系统，解析网络参数
    BLS12381Element::init();
    parse_party_and_port(argv, &party, &port);
    num_party = std::stoi(argv[3]);
    std::string input_file = argv[4];
    std::string output_file = argv[5];
    int table_bits = 1; // 只需查0,1两项表，大小为2
    size_t tb_size = 1ULL << table_bits;

    // 网络配置：127.0.0.1 + 端口连续
    std::vector<std::pair<std::string, unsigned short>> net_config;
    for (int i = 1; i <= num_party; ++i) {
        net_config.emplace_back("127.0.0.1", static_cast<unsigned short>(port + i - 1));
    }
    // 使用MultiIOBase作为IO类型
    ThreadPool pool(threads);
    MultiIO* io = new MultiIO(party, num_party, net_config);
    // ELGL模板的IO参数应为MultiIOBase
    ELGL<MultiIOBase>* elgl = new ELGL<MultiIOBase>(num_party, io, &pool, party);

    // 构造解密映射表
    std::map<std::string, Fr> P_to_m;
    size_t tbs = 1ULL << 12;
    build_safe_P_to_m(P_to_m, num_party, tbs);

    // 初始化LVT，分发公钥生成global_pk和user_pk
    Plaintext alpha;
    const mcl::Vint p("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
    const mcl::Vint g("5"); 
    mcl::Vint n = mcl::Vint(1) << table_bits;
    mcl::Vint alpha_vint;
    mcl::gmp::powMod(alpha_vint, g, (p - 1) / n, p);
    alpha.assign(alpha_vint.getStr());
    // std::cout << "alpha: " << alpha.get_message().getStr() << std::endl;
    Fr alpha_fr = alpha.get_message();
    LVT<MultiIOBase>* lvt = new LVT<MultiIOBase>(num_party, party, io, &pool, elgl, "../../build/bin/table.txt", alpha_fr, table_bits);
    lvt->DistKeyGen();
    // 预生成查表所需的分享表
    test_generate_shares(lvt);

    // 读取布尔比特串输入，每行一个参与方
    std::ifstream fin(input_file);
    if (!fin) { std::cerr << "无法打开 " << input_file << std::endl; return 1; }
    std::vector<std::vector<int>> all_bits;
    std::string line;
    while (std::getline(fin, line)) {
        std::istringstream iss(line);
        std::vector<int> bits;
        int b;
        while (iss >> b) {
            bits.push_back(b);
        }
        all_bits.push_back(bits);
    }
    if (party < 1 || party > all_bits.size()) {
        std::cerr << "Error: 输入行数不足，无法为 Party " << party << " 读取位串" << std::endl;
        return 1;
    }
    // 当前方的布尔输入向量
    std::vector<int> bool_bits = all_bits[party - 1];
    int l = bool_bits.size();
    // 1. 各方按位拆分：x_bits 直接来自输入，r_bits 随机生成
    std::vector<int> x_bits = bool_bits;
    std::vector<int> r_bits(l);
    // 使用C++11随机库生成布尔r_bits
    std::mt19937_64 rng(std::random_device{}());
    rng.seed(rng() + party);
    std::uniform_int_distribution<int> dist(0, 1);
    for (int j = 0; j < l; ++j) {
        r_bits[j] = dist(rng);
    }
    // 统计起始通信字节和时间
    int bytes_start = io->get_total_bytes_sent();
    auto t1 = std::chrono::high_resolution_clock::now();

    // 保存各方加密值 c_r[j][i], c_x[j][i]
    std::vector<std::vector<Ciphertext>> c_r(l, std::vector<Ciphertext>(num_party));
    std::vector<std::vector<Ciphertext>> c_x(l, std::vector<Ciphertext>(num_party));
    for (int j = 0; j < l; ++j) {
        // 本方加密并广播
        Plaintext prj(Fr(std::to_string(r_bits[j])));
        Plaintext pxj(Fr(std::to_string(x_bits[j])));
        Ciphertext crj = elgl->kp.get_pk().encrypt(prj);
        Ciphertext cxj = elgl->kp.get_pk().encrypt(pxj);
        elgl->serialize_sendall(crj);
        elgl->serialize_sendall(cxj);
        c_r[j][party-1] = crj;
        c_x[j][party-1] = cxj;
        // 接收其他方
        for (int i = 1; i <= num_party; ++i) {
            if (i == party) continue;
            Ciphertext crj_i, cxj_i;
            elgl->deserialize_recv(crj_i, i);
            elgl->deserialize_recv(cxj_i, i);
            c_r[j][i-1] = crj_i;
            c_x[j][i-1] = cxj_i;
        }
    }
    // 2. 聚合 c_rj, c_xj
    std::vector<Ciphertext> C_rj(l), C_xj(l);
    for (int j = 0; j < l; ++j) {
        C_rj[j] = c_r[j][0];
        C_xj[j] = c_x[j][0];
        for (int i = 1; i < num_party; ++i) {
            C_rj[j] = C_rj[j] + c_r[j][i];
            C_xj[j] = C_xj[j] + c_x[j][i];
        }
    }
    // 3. 各方生成 d_{j,i} = C_rj[j]*x_bits[j] 加随机盲
    std::vector<std::vector<Ciphertext>> d_j_i(l, std::vector<Ciphertext>(num_party));
    for (int j = 0; j < l; ++j) {
        for (int i = 0; i < num_party; ++i) {
            // 本方生成
            if (i == party-1) {
                // 若 x_bits[j]==1 则 d = C_rj[j] + Enc(0, s); 否则 d = Enc(0, s)
                // 盲值通过重随机化实现
                Plaintext zero(Fr("0"));
                Ciphertext blind = elgl->kp.get_pk().encrypt(zero);
                if (x_bits[j] == 1)
                    d_j_i[j][i] = C_rj[j] + blind;
                else
                    d_j_i[j][i] = blind;
                // 广播
                elgl->serialize_sendall(d_j_i[j][i]);
            } else {
                // 接收
                Ciphertext dij;
                elgl->deserialize_recv(dij, i+1);
                d_j_i[j][i] = dij;
            }
        }
    }
    // 4. 聚合 d_j 并阈值解密 u'_j
    std::vector<Fr> u_prime(l);
    for (int j = 0; j < l; ++j) {
        Ciphertext D_j = d_j_i[j][0];
        for (int i = 1; i < num_party; ++i) D_j = D_j + d_j_i[j][i];
        u_prime[j] = threshold_decrypt_easy<MultiIOBase>(D_j, elgl, lvt->global_pk, lvt->user_pk, io, &pool, party, num_party, P_to_m);
    }
    // 5. 校验 m_j = TDec(C_rj + C_xj - 2*D_j) == 0
    for (int j = 0; j < l; ++j) {
        Ciphertext tmp = C_rj[j] + C_xj[j];
        Ciphertext twoDj = d_j_i[j][0] + d_j_i[j][0];
        for (int i = 1; i < num_party; ++i) twoDj = twoDj + d_j_i[j][i] + d_j_i[j][i];
        tmp = tmp - twoDj;
        Fr m_j = threshold_decrypt_easy<MultiIOBase>(tmp, elgl, lvt->global_pk, lvt->user_pk, io, &pool, party, num_party, P_to_m);
        if (m_j.getStr() != "0") {
            std::cerr << "Consistency check failed at j=" << j << std::endl;
            return 1;
        }
    }
    // 6. 调用 lookup_online 获得算术分享并输出结果
    Fr x_a_share(Fr("0"));
    for (int j = 0; j < l; ++j) {
        Plaintext xb_share_pt;
        xb_share_pt.assign(std::to_string(x_bits[j]));
        Plaintext out;
        Ciphertext cj = c_x[j][party-1]; // 任意一份 x 加密
        lvt->lookup_online(out, xb_share_pt, cj);
        Fr share_j = out.get_message();
        // 加权累加
        Fr weight;
        Fr::pow(weight, Fr("2"), Fr(std::to_string(j)));
        Fr::mul(weight, weight, share_j);
        Fr::add(x_a_share, x_a_share, weight);
    }
    // 输出算术分享 x^a
    std::cout << "Arithmetic share x^a: " << x_a_share.getStr() << std::endl;
    // cif_i 可按类似逻辑累加各方的 e_{j,i} 实现
    
    // 统计结束通信字节和时间
    auto t2 = std::chrono::high_resolution_clock::now();
    int bytes_end = io->get_total_bytes_sent();
    double comm_kb = double(bytes_end - bytes_start) / 1024.0;
    double time_ms = std::chrono::duration<double, std::milli>(t2 - t1).count();
    std::cout << std::fixed << std::setprecision(3)
              << "Communication: " << comm_kb << " KB, "
              << "Time: " << time_ms << " ms" << std::endl;
    
    return 0;
} 