#include "emp-aby/io/multi-io.hpp"
#include "emp-aby/io/mp_io_channel.h"
#include "emp-aby/lvt.h"
#include "emp-aby/elgl_interface.hpp"
#include "emp-aby/tiny.hpp"
#include "emp-aby/spdz2k.hpp"
#include "A2B_spdz2k.hpp"
#include <iostream>
#include <vector>
#include <thread>
#include <cassert>
#include <mcl/vint.hpp>
#include <random>
#include <sstream>

using namespace emp;
using namespace std;

int party, port;
const static int threads = 8;
int num_party;
const int l = 24;
const int num_bits = 24;
const uint64_t FIELD_SIZE = (1ULL << 63);
int m_bits = 1; // bits of message

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

    int num = 1;
    Fr alpha_fr = alpha_init(num);
    LVT<MultiIOBase>* lvt = new LVT<MultiIOBase>(num_party, party, io, &pool, elgl, "2", alpha_fr, num, m_bits);

    lvt->DistKeyGen();
    TinyMAC<MultiIOBase> tiny(elgl);
    SPDZ2k<MultiIOBase> spdz2k(elgl);
    lvt->generate_shares_fake(lvt->lut_share, lvt->rotation, lvt->table);

    // 输入：算术份额
    uint64_t x_spdz2k = spdz2k.rng() % FIELD_SIZE;
    SPDZ2k<MultiIOBase>::LabeledShare x_arith;
    x_arith = spdz2k.distributed_share(x_spdz2k);

    // 调用A2B
    double total_time = 0;
    double total_comm = 0;
    double online_time = 0;
    double online_comm = 0;
    int times = 1;
    for (int i = 0; i < times; ++i) {
        auto x_bool = A2B_spdz2k::A2B(elgl, lvt, tiny, spdz2k, party, num_party, io, &pool, FIELD_SIZE, num_bits, x_arith, online_time, online_comm);
        total_time += online_time;
        total_comm += online_comm;
    }
    std::cout << "Average time: " << (total_time/times) << "ms && Average communication: " << (total_comm/times) << "KB" << std::endl;
    
    delete elgl;
    delete io;
    delete lvt;
    return 0;
}