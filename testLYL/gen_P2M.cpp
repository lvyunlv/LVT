#include "emp-aby/io/multi-io.hpp"
#include "emp-aby/io/mp_io_channel.h"
#include "emp-aby/lvt.h"
#include "emp-aby/elgl_interface.hpp"
#include "emp-aby/mascot.hpp"
#include <iostream>
#include <vector>
#include <thread>
#include <cassert>

using namespace emp;
using namespace std;

int party, port, num, num_party;
const static int threads = 8;

int main(int argc, char** argv) {

    BLS12381Element::init();
    if (argc < 5) {
        std::cout << "Usage: <party> <port> <num_party> <num>" << std::endl;
        return 0;
    }
    parse_party_and_port(argv, &party, &port);
    num_party = std::stoi(argv[3]);
    num = std::stoi(argv[4]);
    std::vector<std::pair<std::string, unsigned short>> net_config;
    for (int i = 1; i <= num_party; ++i) {
        net_config.emplace_back("127.0.0.1", static_cast<unsigned short>(port + i - 1));
    }

    ThreadPool pool(threads);
    MultiIO* io = new MultiIO(party, num_party, net_config);
    ELGL<MultiIOBase>* elgl = new ELGL<MultiIOBase>(num_party, io, &pool, party);

    Plaintext alpha;
    const mcl::Vint p("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
    const mcl::Vint g("5"); 
    mcl::Vint n = mcl::Vint(1) << num;
    mcl::Vint alpha_vint;
    mcl::gmp::powMod(alpha_vint, g, (p - 1) / n, p);
    alpha.assign(alpha_vint.getStr());
    // std::cout << "alpha: " << alpha.get_message().getStr() << std::endl;
    Fr alpha_fr = alpha.get_message();
    LVT<MultiIOBase>* lvt = new LVT<MultiIOBase>(num_party, party, io, &pool, elgl, "../../build/bin/table.txt", alpha_fr, num);
    std::map<std::string, Fr> P_to_m;
    size_t tbs = 1ULL << num;
    build_safe_P_to_m(P_to_m, num_party, tbs);

    std::ofstream fout("P_to_m_table.txt");
    for (const auto& kv : P_to_m) {
        fout << kv.first << " " << kv.second.getStr() << "\n";
    }
    fout.close();
    printf("P_to_m_table.txt generated!\n");
    return 0;
}