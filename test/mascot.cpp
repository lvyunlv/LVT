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

// Test constants
int party, port;
const static int threads = 8;
int num_party;
const int FIELD_SIZE = 1000000007; // A prime number for modular arithmetic

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

    int num = 12; 
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


////////////////////////////////////////////////////
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
    
    std::cout << "\n==== Testing MASCOT Protocol ====\n" << std::endl;
    
    // 测试秘密共享和重构
    int64_t test_input = 3;
    MASCOT<MultiIOBase>::LabeledShare shared_value;
    shared_value = mascot.distributed_share(test_input);

    int64_t reconstructed = mascot.reconstruct(shared_value);
    
    std::cout << "Reconstructed value: " << std::to_string(reconstructed) << std::endl;
    
    // 测试加法
    int64_t x1 = party, x2 = 2 + party;
    MASCOT<MultiIOBase>::LabeledShare x1_share, x2_share;
    
    std::cout << "\nTesting addition: " << std::to_string(x1) << " + " << std::to_string(x2) << std::endl;
    x1_share = mascot.distributed_share(x1);
    x2_share = mascot.distributed_share(x2);
    
    auto sum_share = mascot.add(x1_share, x2_share);
    int64_t sum_result = mascot.reconstruct(sum_share);
    
    std::cout << "Addition result: " << std::to_string(sum_result) << std::endl;
    
    // 测试标量乘法
    int64_t scalar = 5;
    
    auto scalar_mul_share = mascot.mul_const(x1_share, scalar);
    int64_t scalar_mul_result = mascot.reconstruct(scalar_mul_share);
    
    std::cout << "\nTesting scalar multiplication: " << std::to_string(x1) << " * " << std::to_string(scalar) << std::endl;
    std::cout << "Scalar multiplication result: " << std::to_string(scalar_mul_result) << std::endl;
    
    // 测试乘法
    std::cout << "\nTesting multiplication..." << std::endl;
    auto mul_share = mascot.multiply(x1_share, x2_share);

    int64_t k1 = mascot.reconstruct(x1_share);
    int64_t k2 = mascot.reconstruct(x2_share);
    int64_t k3 = mascot.reconstruct(mul_share);
    
    std::cout << "\nTesting multiplication: " << std::to_string(k1) << " * " << std::to_string(k2) << std::endl;
    std::cout << "Multiplication result: " << std::to_string(k3) << std::endl;
    
    // 清理资源
    delete elgl;
    delete io;
    delete lvt;
    return 0;
}