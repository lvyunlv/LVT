#include "emp-aby/io/multi-io.hpp"
#include "emp-aby/io/mp_io_channel.h"
#include "emp-aby/lvt.h"
#include "emp-aby/elgl_interface.hpp"
#include "emp-aby/tiny.hpp"
#include <iostream>
#include <vector>
#include <thread>
#include <cassert>
#include <mcl/vint.hpp>
#include <random>

using namespace emp;
using namespace std;

// 参数
int party, port;
const static int threads = 8;
int num_party;
const int l = 8; // 比特长度，可根据q调整
const uint64_t FIELD_SIZE = (1ULL << l);

int main(int argc, char** argv) {
    BLS12381Element::init();
    if (argc < 4) {
        std::cout << "Usage: <party> <port> <num_party>" << std::endl;
        return 0;
    }
    parse_party_and_port(argv, &party, &port);
    num_party = std::stoi(argv[3]);
    
    std::vector<std::pair<std::string, unsigned short>> net_config;
    for (int i = 1; i <= num_party; ++i) {
        net_config.emplace_back("127.0.0.1", static_cast<unsigned short>(port + i - 1));
    }

    ThreadPool pool(threads);
    MultiIO* io = new MultiIO(party, num_party, net_config);
    ELGL<MultiIOBase>* elgl = new ELGL<MultiIOBase>(num_party, io, &pool, party);

    // LUT查表表大小为2，0->0, 1->1
    vector<int64_t> lut_table = {0, 1};
    Fr alpha("2"); // 只需2阶根
    LVT<MultiIOBase>* lvt = new LVT<MultiIOBase>(num_party, party, io, &pool, elgl, alpha, 1);
    lvt->table = lut_table;
    std::map<std::string, Fr> P_to_m;
    size_t tbs = 1ULL << 12;
    build_safe_P_to_m(P_to_m, num_party, tbs);
    lvt->DistKeyGen();

    // 随机数生成器
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> dis(0, FIELD_SIZE-1);
    std::uniform_int_distribution<int> bit_dis(0, 1);

    // 生成本地算术份额
    mcl::Vint x_share = dis(gen);
    Plaintext px;
    px.assign(x_share.getStr());
    Ciphertext cx = lvt->global_pk.encrypt(px);
    // 广播密文
    elgl->serialize_sendall(cx);
    vector<Ciphertext> all_cx(num_party);
    all_cx[party-1] = cx;
    for (int i = 1; i <= num_party; ++i) {
        if (i != party) {
            Ciphertext tmp;
            elgl->deserialize_recv(tmp, i);
            all_cx[i-1] = tmp;
        }
    }
    // 生成布尔随机份额 r_bits
    vector<uint8_t> r_bits(l);
    for (int i = 0; i < l; ++i) r_bits[i] = bit_dis(gen);
    // 调用B2A得到r的算术份额和密文
    vector<Plaintext> r_plain(l);
    vector<Ciphertext> cr(l);
    for (int j = 0; j < l; ++j) {
        Plaintext pr;
        pr.assign(to_string(r_bits[j]));
        cr[j] = lvt->global_pk.encrypt(pr);
        r_plain[j] = pr;
    }
    // 广播r的密文
    for (int j = 0; j < l; ++j) elgl->serialize_sendall(cr[j]);
    // 收集所有r的密文
    vector<vector<Ciphertext>> all_cr(l, vector<Ciphertext>(num_party));
    for (int j = 0; j < l; ++j) {
        all_cr[j][party-1] = cr[j];
        for (int i = 1; i <= num_party; ++i) {
            if (i != party) {
                Ciphertext tmp;
                elgl->deserialize_recv(tmp, i);
                all_cr[j][i-1] = tmp;
            }
        }
    }
    // 解密所有密文之和，得到u
    Ciphertext sum_c = all_cx[0];
    for (int i = 1; i < num_party; ++i) sum_c = sum_c + all_cx[i];
    for (int j = 0; j < l; ++j) {
        for (int i = 0; i < num_party; ++i) sum_c = sum_c + all_cr[j][i];
    }
    Fr u = threshold_decrypt_easy(sum_c, elgl, lvt->global_pk, lvt->user_pk, io, &pool, party, num_party, P_to_m);
    // P1做bit-decomposition
    vector<uint8_t> u_bits(l, 0);
    if (party == 1) {
        mcl::Vint uval(u.getStr());
        for (int j = 0; j < l; ++j) u_bits[j] = (uval.testBit(j) != 0);
    }
    // 广播u_bits
    for (int j = 0; j < l; ++j) {
        io->send_data(reinterpret_cast<const void*>(&u_bits[j]), 1, 1);
        for (int i = 1; i <= num_party; ++i) {
            if (i != party) {
                uint8_t tmp;
                io->recv_data(reinterpret_cast<void*>(&tmp), 1, i);
                u_bits[j] ^= tmp;
            }
        }
    }
    // 用LinComb和r_bits异或，得到x_bits
    vector<uint8_t> x_bits(l);
    for (int j = 0; j < l; ++j) x_bits[j] = u_bits[j] ^ r_bits[j];
    // 输出布尔份额
    cout << "A2B success, my boolean share: ";
    for (int j = 0; j < l; ++j) cout << int(x_bits[j]);
    cout << endl;
    // 清理
    delete elgl;
    delete io;
    delete lvt;
    return 0;
}
