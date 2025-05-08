#include "emp-aby/io/multi-io.hpp"
#include "emp-aby/io/mp_io_channel.h"
#include "emp-aby/lvt.h"
#include "emp-aby/elgl_interface.hpp"
#include "emp-aby/tiny.hpp"
#include "emp-aby/spdz2k.hpp"
#include "B2A_spdz2k.hpp"
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
const int num_bits = 32;
const uint64_t FIELD_SIZE = (1ULL << num_bits);
int m_bits = 32; // bits of message

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
    LVT<MultiIOBase>* lvt = new LVT<MultiIOBase>(num_party, party, io, &pool, elgl, "../../build/bin/table.txt", alpha_fr, num, m_bits);

    lvt->DistKeyGen();
    TinyMAC<MultiIOBase> tiny(elgl);
    SPDZ2k<MultiIOBase> spdz2k(elgl);
    lvt->generate_shares_fake(lvt->lut_share, lvt->rotation, lvt->table);

    // ====================== setup 结束 ==========================

    // input generation
    vector<TinyMAC<MultiIOBase>::LabeledShare> x_bits(l);
    for (int i = 0; i < l; ++i) 
    {
        uint8_t bit_dis = tiny.rng() % 2;
        x_bits[i] = tiny.distributed_share(bit_dis);
    }

    // B2A_spdz2k output
    double total_time = 0;
    double total_comm = 0;
    double online_time = 0;
    double online_comm = 0;
    int times = 1;
    for (int i = 0; i < times; ++i) {
        auto shared_x = B2A_spdz2k::B2A(elgl, lvt, tiny, spdz2k, party, num_party, io, &pool, FIELD_SIZE, x_bits, online_time, online_comm);
        total_time += online_time;
        total_comm += online_comm;
    }
    std::cout << "Average time: " << (total_time/times) << "ms && Average communication: " << (total_comm/times) << "KB" << std::endl;

    delete elgl;
    delete io;
    delete lvt;
    return 0;
}
