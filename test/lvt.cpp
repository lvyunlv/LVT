#include "emp-aby/lvt.h"
#include "emp-aby/io/multi-io.hpp"
using namespace emp;

#include <typeinfo>
#include <cstdlib>

int party, port;

const static int threads = 4;

int num_party;

// template <typename IO>

template <typename IO>
void test_generate_shares(ELGL<IO>* he, LVT<IO>* lut, MPIOChannel<IO>* io){
    Plaintext rotation;
    lut->generate_shares(lut->lut_share, rotation, lut->table);
}

template <typename IO>
void test_lookup_online(ELGL<IO>* he, LVT<IO>* lut, MPIOChannel<IO>* io, vector<Plaintext>& x_share, vector<Ciphertext>& x_cipher){
    Plaintext rotation, out;
    lut->lookup_online(out, lut->lut_share, rotation, x_share, x_cipher);
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

    auto start = clock_start();
    ELGL<MultiIOBase>* elgl = new ELGL<MultiIOBase>(num_party, io, &pool, party);

    // table has been loaded from a file
    Plaintext alpha;
    alpha.assign("3465144826073652318776269530687742778270252468765361963008");
    Fr alpha_fr = alpha.get_message();
    LVT<MultiIOBase>* lvt = new LVT<MultiIOBase>(num_party, party, io, &pool, elgl, "/Users/lvbao/Desktop/ScalableMixedModeMPC/table.txt",alpha_fr, 2);
    // std::cout << "dist key gen" << std::endl;
    // dist key gen
    lvt->DistKeyGen();

    test_generate_shares(elgl, lvt, io);

    vector<Plaintext> x_share;
    vector<Ciphertext> x_cipher;
    x_share.resize(lvt->table.size());
    x_cipher.resize(lvt->table.size());
    for(size_t i = 0; i < lvt->num_party; i++){
        x_share[i].set_random();
        x_cipher[i] = lvt->global_pk.encrypt(x_share[i]);
    }
    test_lookup_online(elgl, lvt, io, x_share, x_cipher);

    
    return 0;
}
