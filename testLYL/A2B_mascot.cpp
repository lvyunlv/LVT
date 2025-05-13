#include "emp-aby/io/multi-io.hpp"
#include "emp-aby/io/mp_io_channel.h"
#include "emp-aby/lvt.h"
#include "emp-aby/elgl_interface.hpp"
#include "emp-aby/tiny.hpp"
#include "emp-aby/mascot.hpp"
#include "A2B_mascot.hpp"
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
const int l = 32;
const int num_bits = 32;
// const mcl::Vint FIELD_SIZE = (1 << num_bits);
const mcl::Vint FIELD_SIZE("4294967296");
int m_bits = 1; // bits of message
Fr alpha_init(int num) {
    Plaintext alpha;
    const mcl::Vint p("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
    const mcl::Vint g("5"); 
    mcl::Vint n = mcl::Vint(1) << num;
    mcl::Vint alpha_vint;
    mcl::gmp::powMod(alpha_vint, g, (p - 1) / n, p);
    alpha.assign(alpha_vint.getStr());
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

    int num = 1;
    Fr alpha_fr = alpha_init(num);
    LVT<MultiIOBase>* lvt = new LVT<MultiIOBase>(num_party, party, io, &pool, elgl, "../../build/bin/table_2.txt", alpha_fr, num, m_bits);

    lvt->DistKeyGen();
    TinyMAC<MultiIOBase> tiny(elgl);
    MASCOT<MultiIOBase> mascot(elgl);
    lvt->generate_shares_fake(lvt->lut_share, lvt->rotation, lvt->table);

    // cout << "开始生成算术份额" << endl;
    // 输入：算术份额
    mcl::Vint x_mascot;
    x_mascot.setRand(FIELD_SIZE); // 128位大素数域足够
    MASCOT<MultiIOBase>::LabeledShare x_arith;
    x_arith = mascot.distributed_share(x_mascot);
    // cout << "算术份额生成完成" << endl;
    // 调用A2B
    double total_time = 0;
    double total_comm = 0;
    double online_time = 0;
    double online_comm = 0;
    int times = 1;
    for (int i = 0; i < times; ++i) {
        auto x_bool = A2B_mascot::A2B(elgl, lvt, tiny, mascot, party, num_party, io, &pool, FIELD_SIZE, num_bits, x_arith, online_time, online_comm);
        total_time += online_time;
        total_comm += online_comm;
    }
    std::cout << "Average time: " << (total_time/times) << "ms && Average communication: " << (total_comm/times) << "KB" << std::endl;

    delete elgl;
    delete io;
    delete lvt;
    return 0;
}