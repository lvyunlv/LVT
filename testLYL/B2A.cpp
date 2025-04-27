#include "emp-aby/io/multi-io.hpp"
#include "emp-aby/io/mp_io_channel.h"
#include "emp-aby/lvt.h"
#include "emp-aby/elgl_interface.hpp"
#include "emp-aby/tiny.hpp"
#include "emp-aby/spdz2k.hpp"
#include <iostream>
#include <vector>
#include <thread>
#include <cassert>
#include <mcl/vint.hpp>
#include <random>
#include <sstream>

using namespace emp;
using namespace std;

// 参数
int party, port;
const static int threads = 8;
int num_party;
const int l = 8; // 比特长度，可根据q调整
const uint64_t FIELD_SIZE = (1ULL << l);

Fr alpha_init(int num) {
    Plaintext alpha;
    const mcl::Vint p("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
    const mcl::Vint g("5"); 
    mcl::Vint n = mcl::Vint(1) << num;
    mcl::Vint alpha_vint;
    mcl::gmp::powMod(alpha_vint, g, (p - 1) / n, p);
    alpha.assign(alpha_vint.getStr());
    // std::cout << "alpha: " << alpha.get_message().getStr() << std::endl;
    Fr alpha_fr = alpha.get_message();
    vector<int64_t> lut_table = {0, 1};
    serializeTable(lut_table, "table.txt", lut_table.size());
    return alpha_fr;
}

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
    int num = 1;
    Fr alpha_fr = alpha_init(num);
    LVT<MultiIOBase>* lvt = new LVT<MultiIOBase>(num_party, party, io, &pool, elgl, "../../build/bin/table.txt", alpha_fr, num);

    std::map<std::string, Fr> P_to_m;
    size_t tbs = 1ULL << 12;
    build_safe_P_to_m(P_to_m, num_party, tbs);

    lvt->DistKeyGen();
    TinyMAC<MultiIOBase> tiny(elgl);
    SPDZ2k<MultiIOBase> spdz2k(elgl);
    lvt->generate_shares(lvt->lut_share, lvt->rotation, lvt->table);

    // ====================== setup 结束 ==========================

    // input generation
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> bit_dis(0, 1);
    vector<TinyMAC<MultiIOBase>::LabeledShare> x_bits(l);
    for (int i = 0; i < l; ++i) x_bits[i] = tiny.distributed_share(bit_dis(gen));

    // choose random r_bits
    vector<TinyMAC<MultiIOBase>::LabeledShare> r_bits(l);
    vector<TinyMAC<MultiIOBase>::LabeledShare> u_bits(l);
    
    for (int i = 0; i < l; ++i) r_bits[i] = tiny.distributed_share(bit_dis(gen));
    for (int i = 0; i < l; ++i) u_bits[i] = tiny.add(x_bits[i], r_bits[i]);

    // B2L
    vector<Ciphertext> x_cipher(l), r_cipher(l);
    vector<Plaintext> x_plain(l), r_plain(l), u_plain(l);
    for (int i = 0; i < l; ++i) {
        Plaintext plain_i;
        plain_i.assign(to_string(x_bits[i].value));
        lvt->lookup_online(x_plain[i], plain_i, x_cipher[i]);
        plain_i.assign(to_string(r_bits[i].value));
        lvt->lookup_online(r_plain[i], plain_i, r_cipher[i]);
        u_plain[i] = x_plain[i] + r_plain[i];
        stringstream ss;
        uint64_t u_plain_i = u_plain[i].get_message().getUint64();
        ss << u_plain_i;
        elgl->serialize_sendall_with_tag(ss, party, 1000 * party + party);
    }

    vector<uint64_t> u_sum(l);
    for (int i = 0; i < l; ++i) {
        u_sum[i] = u_plain[i].get_message().getUint64();
        for (int j = 1; j < num_party; ++j) {
            if (j == party) continue;
            stringstream ss_recv;
            elgl->deserialize_recv_with_tag(ss_recv, j, 1000 * j + j);
            uint64_t u_plain_i;
            ss_recv >> u_plain_i;
            u_sum[i] += u_plain_i;
        }
    }
    
    // L2A
    vector<SPDZ2k<MultiIOBase>::LabeledShare> shared_x(l), shared_r(l), shared_u(l);
    vector<uint64_t> op_u(l);
    for (int i = 0; i < l; ++i) {
        shared_x[i] = spdz2k.distributed_share(x_plain[i].get_message().getUint64());
        shared_r[i] = spdz2k.distributed_share(r_plain[i].get_message().getUint64());
        shared_u[i] = spdz2k.add(shared_x[i], shared_r[i]);
        op_u[i] = spdz2k.reconstruct(shared_u[i]);
        if (op_u[i] != u_sum[i]) {
            std::cout << "u_sum[i] != op_u[i]" << std::endl;
            return 0;
        }
    }

    vector<SPDZ2k<MultiIOBase>::LabeledShare> m(l); 
    for (int i = 0; i < l; ++i) {
        m[i] = spdz2k.multiply(shared_x[i], shared_r[i]);
        m[i] = spdz2k.mul_const(m[i], 2);
        m[i].value = spdz2k_field_size - m[i].value;
        m[i].mac = spdz2k_field_size *  - m[i].mac;
        m[i] = spdz2k.add(shared_u[i], m[i]);
    }

    vector<Ciphertext> c_cipher(l);
    vector<Plaintext> c_plain(l);
    


    delete elgl;
    delete io;
    delete lvt;
    return 0;
}
