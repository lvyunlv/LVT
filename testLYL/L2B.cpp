#include "emp-aby/io/multi-io.hpp"
#include "emp-aby/io/mp_io_channel.h"
#include "emp-aby/lvt.h"
#include "emp-aby/elgl_interface.hpp"
#include "emp-aby/tiny.hpp"
#include "L2B.hpp"
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
const int num = 1;
const int num_bits = 24;
const uint64_t FIELD_SIZE = (1ULL << num_bits);
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

    ThreadPool pool(threads);
    MultiIO* io = new MultiIO(party, num_party, net_config);
    ELGL<MultiIOBase>* elgl = new ELGL<MultiIOBase>(num_party, io, &pool, party);

    Fr alpha_fr = alpha_init(num);
    LVT<MultiIOBase>* lvt = new LVT<MultiIOBase>(num_party, party, io, &pool, elgl, "../../build/bin/table_2.txt", alpha_fr, num, m_bits);

    lvt->DistKeyGen();
    TinyMAC<MultiIOBase> tiny(elgl);
    lvt->generate_shares(lvt->lut_share, lvt->rotation, lvt->table);

    // 输入：算术份额
    Plaintext x_arith;
    x_arith.set_random(FIELD_SIZE);
    // cout << "arith share: " << x_arith.get_message().getUint64() << endl;
    vector<Ciphertext> x_cips(num_party);
    x_cips[party - 1] = elgl->kp.get_pk().encrypt(x_arith);
    elgl->serialize_sendall(x_cips[party - 1]);
    for (int i = 0; i < num_party; ++i) {
        if (i != party - 1) {
            elgl->deserialize_recv(x_cips[i], i + 1);
        }
    }
    
    // 调用L2B
    // vector<TinyMAC<MultiIOBase>::LabeledShare> L2B(ELGL<MultiIOBase>* elgl, LVT<MultiIOBase>* lvt, TinyMAC<MultiIOBase>& tiny, int party, int num_party, MultiIO* io, ThreadPool* pool, const uint64_t& FIELD_SIZE, int l, Plaintext& x_arith, vector<Ciphertext>& x_cips);
    auto x_bool = A2B_spdz2k::L2B(elgl, lvt, tiny, party, num_party, io, &pool, FIELD_SIZE, num_bits, x_arith, x_cips);
    
    delete elgl;
    delete io;
    delete lvt;
    return 0;
}