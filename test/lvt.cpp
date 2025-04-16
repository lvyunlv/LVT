#include "emp-aby/lvt.h"
#include "emp-aby/io/multi-io.hpp"
using namespace emp;

#include <typeinfo>
#include <cstdlib>

int party, port;

const static int threads = 8;

int num_party;

// template <typename IO>

template <typename IO>
void test_generate_shares(LVT<IO>* lut){
    lut->generate_shares(lut->lut_share, lut->rotation, lut->table);
}

template <typename IO>
void test_lookup_online(LVT<IO>* lut, Plaintext& x_share, Ciphertext& x_cipher){
    Plaintext out;
    lut->lookup_online(out, x_share, x_cipher);
}

int main(int argc, char** argv) {
    BLS12381Element::init();
    if (argc < 4) {
        std::cout << "Format: lut PartyID port num_parties" << std::endl;
        return 0;
    }
    parse_party_and_port(argv, &party, &port);
     num_party = std::stoi(argv[3]);

    std::vector<std::pair<std::string, unsigned short>> net_config;

    if (argc == 5) {
        const char* file = argv[4];
        FILE* f          = fopen(file, "r");
        for (int i = 0; i < num_party; ++i) {
            char* c = (char*)malloc(15 * sizeof(char));
            uint p;
            fscanf(f, "%s %d\n", c, &p);
            std::string s(c);
            net_config.push_back(std::make_pair(s, p));
            fflush(f);
        }
        fclose(f);
    }
    else {
        for (int i = 0; i < num_party; ++i) {
            std::string s = "127.0.0.1";
            uint p        = (port + 4 * num_party * i);
            net_config.push_back(std::make_pair(s, p));
        }
    }

    ThreadPool pool(threads);

    MultiIO* io = new MultiIO(party, num_party, net_config);

    std::cout << "io setup" << std::endl;

    ELGL<MultiIOBase>* elgl = new ELGL<MultiIOBase>(num_party, io, &pool, party);

    // table has been loaded from a file
    Plaintext alpha;
    alpha.assign("3465144826073652318776269530687742778270252468765361963008");
    Fr alpha_fr = alpha.get_message();
    LVT<MultiIOBase>* lvt = new LVT<MultiIOBase>(num_party, party, io, &pool, elgl, "../../table.txt", alpha_fr, 4);
    // std::cout << "dist key gen" << std::endl;
    // dist key gen
    lvt->DistKeyGen();

    auto start = clock_start();
    test_generate_shares(lvt);
    std::cout << "test_generate_shares time: " 
          << std::fixed << std::setprecision(3) 
          << time_from(start)/1e6 << " seconds" << std::endl;


    Plaintext x_share;
    Ciphertext x_cipher;


    x_share.set_random();
    x_cipher = lvt->global_pk.encrypt(x_share);
    auto start2 = clock_start();
    test_lookup_online(lvt, x_share, x_cipher);
    std::cout << "test_lookup_online time: " 
          << std::fixed << std::setprecision(3) 
          << time_from(start2)/1e6 << " seconds" << std::endl;
    delete io;
    delete elgl;
    delete lvt;
    return 0;
}
