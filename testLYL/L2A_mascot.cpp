#include "emp-aby/io/multi-io.hpp"
#include "emp-aby/io/mp_io_channel.h"
#include "emp-aby/lvt.h"
#include "emp-aby/elgl_interface.hpp"
#include "emp-aby/mascot.hpp"
#include "L2A_mascot.hpp"
#include <iostream>
#include <vector>
#include <thread>
#include <cassert>
#include <mcl/vint.hpp>

using namespace emp;
using namespace std;

// Test constants
int party, port;
const static int threads = 8;
int num_party;
// const mcl::Vint FIELD_SIZE("340282366920938463463374607431768211297");
const mcl::Vint FIELD_SIZE = (1ULL << 28) ;
const int num = 12; 

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

    lvt->DistKeyGen();

    MASCOT<MultiIOBase> mascot(elgl);
    
    // std::cout << "Party " << party << " initialized" << std::endl;
    
    // 同步所有参与方
    if(party == 1) {
        for(int i = 2; i <= num_party; i++) {
            elgl->wait_for(i);
        }
        // std::cout << "All parties connected!" << std::endl;
    } else {
        elgl->send_done(1);
    }
    
    // input 声明
    mcl::Vint x_mascot; 
    x_mascot.setRand(FIELD_SIZE);
    Plaintext x;
    x.assign(x_mascot.getStr());
    Ciphertext cx;
    cx = lvt->global_pk.encrypt(x);

    vector<Ciphertext> vec_cx(num_party);
    vec_cx[party - 1] = cx;

    elgl->serialize_sendall(cx);
    for(int i = 1; i <= num_party; i++) {
        if(i != party) {
            Ciphertext cx_i;
            elgl->deserialize_recv(cx_i, i);
            vec_cx[i - 1] = cx_i;
        }
    }

    // output 声明
    MASCOT<MultiIOBase>::LabeledShare shared_x;

    // 调用L2A
    double total_time = 0;
    double total_comm = 0;
    for (int i = 0; i < 5; ++i) {
        int bytes_start = io->get_total_bytes_sent();
        auto t1 = std::chrono::high_resolution_clock::now();

        shared_x = L2A_mascot::L2A(elgl, lvt, mascot, party, num_party, io, &pool, x, vec_cx, FIELD_SIZE);

        auto t2 = std::chrono::high_resolution_clock::now();
        int bytes_end = io->get_total_bytes_sent();
        double comm_kb = double(bytes_end - bytes_start) / 1024.0;
        double time_ms = std::chrono::duration<double, std::milli>(t2 - t1).count();
        total_time += time_ms;
        total_comm += comm_kb;
    }
    std::cout << "Average time: " << (total_time/5) << "ms && Average communication: " << (total_comm/5) << "KB" << std::endl;

    // 清理资源
    delete elgl;
    delete io;
    delete lvt;
    return 0;
}