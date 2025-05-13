
#include "emp-aby/lvt.h"
#include "emp-aby/io/multi-io.hpp"
using namespace emp;

int party, port;
const static int threads = 8;
int num_party;
int num = 18; 
int m_bits = 24; // bits of message

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
    return alpha_fr;
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
        FILE* f = fopen(file, "r");
        for (int i = 0; i < num_party; ++i) {
            char* c = (char*)malloc(15 * sizeof(char));
            uint p;
            fscanf(f, "%s %d\n", c, &p);
            net_config.push_back(std::make_pair(std::string(c), p));
            fflush(f);
        }
        fclose(f);
    } else {
        for (int i = 0; i < num_party; ++i) {
            net_config.push_back({"127.0.0.1", port + 4 * num_party * i});
        }
    }

    ThreadPool pool(threads);
    MultiIO* io = new MultiIO(party, num_party, net_config);
    ELGL<MultiIOBase>* elgl = new ELGL<MultiIOBase>(num_party, io, &pool, party);
    
    int n = 1ULL << num;
    Fr alpha_fr = alpha_init(num);
    LVT<MultiIOBase>* lvt = new LVT<MultiIOBase>(num_party, party, io, &pool, elgl, "../../build/bin/table.txt", alpha_fr, num, m_bits);

    lvt->DistKeyGen();

    auto start = clock_start();
    lvt->generate_shares_fake(lvt->lut_share, lvt->rotation, lvt->table);
    std::cout << "test_generate_shares time: "
              << std::fixed << std::setprecision(3)
              << time_from(start) / 1e3 << " milionseconds" << std::endl;

    Plaintext x_share;
    Ciphertext x_cipher;
    x_share.set_random(n);
    x_cipher = lvt->global_pk.encrypt(x_share);
    vector<Ciphertext> x_ciphers(num_party);
    auto start2 = clock_start();
    
    Plaintext out;
    vector<Ciphertext> out_ciphers;
    out_ciphers.resize(num_party);
    std::make_tuple(out, out_ciphers) = lvt->lookup_online(x_share, x_cipher, x_ciphers);

    std::cout << "test_lookup_online time: "
              << std::fixed << std::setprecision(3)
              << time_from(start2) / 1e3 << " milionseconds" << std::endl;

    delete io;
    delete elgl;
    delete lvt;
    return 0;
}