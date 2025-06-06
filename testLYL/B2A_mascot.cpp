#include "emp-aby/io/multi-io.hpp"
#include "emp-aby/io/mp_io_channel.h"
#include "emp-aby/lvt.h"
#include "emp-aby/elgl_interface.hpp"
#include "emp-aby/tiny.hpp"
#include "emp-aby/mascot.hpp"
#include "B2A_mascot.hpp"
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
const int l = 32; // 比特长度，可根据q调整
const int num_bits = 32;
// const mcl::Vint FIELD_SIZE = (1 << num_bits);
const mcl::Vint FIELD_SIZE("340282366920938463463374607431768211297");
// const mcl::Vint FIELD_SIZE("4294967296");
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

    // LUT查表表大小为2，0->0, 1->1
    int num = 1;
    Fr alpha_fr = alpha_init(num);
    LVT<MultiIOBase>* lvt = new LVT<MultiIOBase>(num_party, party, io, &pool, elgl, "2", alpha_fr, num, m_bits);

    lvt->DistKeyGen();
    TinyMAC<MultiIOBase> tiny(elgl);
    MASCOT<MultiIOBase> mascot(elgl);
    lvt->generate_shares_fake(lvt->lut_share, lvt->rotation, lvt->table);

    // B2A_mascot input generation
    vector<TinyMAC<MultiIOBase>::LabeledShare> x_bits(l);
    for (int i = 0; i < l; ++i) 
    {
        uint8_t bit_dis = tiny.rng() % 2;
        x_bits[i] = tiny.distributed_share(bit_dis);
    }
    
    // B2A_mascot output
    double total_time = 0;
    double total_comm = 0;
    double online_time = 0;
    double online_comm = 0;
    int times = 1;
    for (int i = 0; i < times; ++i) {
        auto shared_x = B2A_mascot::B2A(elgl, lvt, tiny, mascot, party, num_party, io, &pool, FIELD_SIZE, x_bits, online_time, online_comm);
        total_time += online_time;
        total_comm += online_comm;
    }
    std::cout << "Average time: " << (total_time/times) << "ms && Average communication: " << (total_comm/times) << "KB" << std::endl;

    delete elgl;
    delete io;
    delete lvt;
    return 0;
}
