#include "emp-aby/io/multi-io.hpp"
#include "emp-aby/io/mp_io_channel.h"
#include "emp-aby/lvt.h"
#include "emp-aby/elgl_interface.hpp"
#include "emp-aby/tiny.hpp"
#include "B2L.hpp"
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
const int l = 24; // 比特长度，可根据q调整
int m_bits = 1; // bits of message

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
    serializeTable(lut_table, "table_2.txt", lut_table.size());
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

    // 测试时间和通信

    ThreadPool pool(threads);
    MultiIO* io = new MultiIO(party, num_party, net_config);
    ELGL<MultiIOBase>* elgl = new ELGL<MultiIOBase>(num_party, io, &pool, party);

    int skip_bytes_start = io->get_total_bytes_sent();
    auto skip_t1 = std::chrono::high_resolution_clock::now();

    // LUT查表表大小为2，0->0, 1->1
    int num = 1;
    Fr alpha_fr = alpha_init(num);
    LVT<MultiIOBase>* lvt = new LVT<MultiIOBase>(num_party, party, io, &pool, elgl, "../../build/bin/table_2.txt", alpha_fr, num, m_bits);
    lvt->DistKeyGen();
    lvt->generate_shares(lvt->lut_share, lvt->rotation, lvt->table);

    TinyMAC<MultiIOBase> tiny(elgl);
    // input generation
    vector<TinyMAC<MultiIOBase>::LabeledShare> x_bits(l);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> bit_dis(0, 1);
    for (int i = 0; i < l; ++i) {
        x_bits[i] = tiny.distributed_share(bit_dis(gen));
    }

    // 调用B2L函数
    // tuple<Plaintext, vector<Ciphertext>> B2L(ELGL<MultiIOBase>* elgl, LVT<MultiIOBase>* lvt, TinyMAC<MultiIOBase>& tiny, int party, int num_party, MultiIO* io, ThreadPool* pool, const vector<TinyMAC<MultiIOBase>::LabeledShare>& x_bits)
    auto [shared_x, cips] = B2L::B2L(elgl, lvt, tiny, party, num_party, io, &pool, x_bits, 1ULL << l);

    int skip_bytes_end = io->get_total_bytes_sent();
    auto skip_t2 = std::chrono::high_resolution_clock::now();
    double skip_comm_kb = double(skip_bytes_end - skip_bytes_start) / 1024.0;
    double skip_time_ms = std::chrono::duration<double, std::milli>(skip_t2 - skip_t1).count();
    // cout << "time: " << skip_time_ms << " ms, comm: " << skip_comm_kb << " KB" << std::endl;

    delete elgl;
    delete io;
    delete lvt;
    return 0;
}
