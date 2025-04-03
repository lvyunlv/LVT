#include "emp-aby/lvt.h"
#include "emp-aby/io/multi-io.hpp"
using namespace emp;

#include <typeinfo>
#include <cstdlib>

int party, port;

const static int threads = 4;

int num_party;

// template <typename IO>

int main(int argc, char** argv) {
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
    LVT<MultiIOBase>* lvt = new LVT<MultiIOBase>(num_party, party, io, &pool, elgl);
    for (int i = 0; i < party; ++i) {
        // receive broadcast
    }
    // encrypt LUT (only party 0) and rotate
    if (party == 0) {
        // encrypt LUT
        
    }
    
}
