#include "emp-aby/lvt.h"
#include "emp-aby/io/multi-io.hpp"
#include "testLYL/L2B.hpp"
#include "testLYL/B2L.hpp"
#include "testLYL/A2L_spdz2k.hpp"
#include "testLYL/L2A_spdz2k.hpp"
#include <memory>
#include <filesystem>

using namespace emp;
namespace fs = std::filesystem;

const std::string tablefile = "../../testLLM/tables/table.txt";
int party, port;
const static int threads = 8;
int num_party;
int m_bits = 24; // 表值比特数，在B2L和L2B中为1，在非线性函数计算调用时为24（表示Q8.16定点整数）
int m_size = 1 << m_bits; // 表值大小
int num = 12;
size_t tb_size = 1ULL << num; // 表的大小
int frac = 16; // 截断

int main(int argc, char** argv) {
    BLS12381Element::init();
    if (argc < 5) {
        std::cout << "Format: <PartyID> <port> <num_parties>" << std::endl;
        return 0;
    }
    parse_party_and_port(argv, &party, &port);
    num_party = std::stoi(argv[3]);
    std::string func_name = argv[4];
    std::string base = "../../testLLM/tables/table_" + func_name;
    std::string fileA = base + "_A.txt";
    std::string fileB = base + "_B.txt";

    std::vector<std::pair<std::string, unsigned short>> net_config;
    if (argc == 6) {
        const char* file = argv[4];
        FILE* f = fopen(file, "r");
        for (int i = 0; i < num_party; ++i) {
            char* c = (char*)malloc(15 * sizeof(char));
            uint p;
            fscanf(f, "%s %d\tb_size", c, &p);
            net_config.push_back(std::make_pair(std::string(c), p));
            fflush(f);
        }
        fclose(f);
    } else {
        for (int i = 0; i < num_party; ++i) {
            net_config.push_back({ "127.0.0.1", port + 4 * num_party * i });
        }
    }

    ThreadPool pool(threads);
    MultiIO* io = new MultiIO(party, num_party, net_config);
    ELGL<MultiIOBase>* elgl = new ELGL<MultiIOBase>(num_party, io, &pool, party);
    Fr alpha_fr = alpha_init(num);
    emp::LVT<MultiIOBase>* lvt = new LVT<MultiIOBase>(num_party, party, io, &pool, elgl, tablefile, alpha_fr, num, m_bits);
    lvt->DistKeyGen();
    TinyMAC<MultiIOBase> tiny(elgl);
    SPDZ2k<MultiIOBase> spdz2k(elgl);
    lvt->generate_shares(lvt->lut_share, lvt->rotation, lvt->table);
    const std::string input_file = "../../TestLLM/Input/Input-P" + std::to_string(party) + ".txt";

    emp::LVT<MultiIOBase>* lvtA = new LVT<MultiIOBase>(num_party, party, io, &pool, elgl, fileA, alpha_fr, num, m_bits);
    lvtA->DistKeyGen();
    lvtA->generate_shares(lvtA->lut_share, lvtA->rotation, lvtA->table);

    emp::LVT<MultiIOBase>* lvtB = new LVT<MultiIOBase>(num_party, party, io, &pool, elgl, fileB, alpha_fr, num, m_bits);
    lvtB->DistKeyGen();
    lvtB->generate_shares(lvtB->lut_share, lvtB->rotation, lvtB->table);

    std::vector<Plaintext> x_share;
    {
        std::ifstream in_file(input_file);
        std::string line;
        while (std::getline(in_file, line)) {
            Plaintext x;
            x.assign(line);
            x_share.push_back(x);
            if (x.get_message().getUint64() > (1ULL << m_bits) - 1) {
                std::cerr << "Error: input value exceeds table size in Party: " << party << std::endl;
                return 1;
            }
        }
    }
    int x_size = x_share.size();
    
    std::vector<Ciphertext> x_cipher(x_size);
    for (int i = 0; i < x_size; ++i) {
        x_cipher[i] = lvt->global_pk.encrypt(x_share[i]);
    }

    std::vector<std::vector<TinyMAC<MultiIOBase>::LabeledShare>> lut_input_bool_first(x_size, std::vector<TinyMAC<MultiIOBase>::LabeledShare>(num));
    std::vector<std::vector<TinyMAC<MultiIOBase>::LabeledShare>> lut_input_bool_last(x_size, std::vector<TinyMAC<MultiIOBase>::LabeledShare>(num));
    std::vector<std::vector<Ciphertext>> x_cips(x_size, std::vector<Ciphertext>(num_party));
    for (int i = 0; i < x_size; ++i) {
        x_cips[i][party - 1] = lvt->global_pk.encrypt(x_share[i]);
        elgl->serialize_sendall(x_cips[i][party - 1]);
        for (int j = 0; j < num_party; ++j) {
            if (j != party - 1) {
                elgl->deserialize_recv(x_cips[i][j], j + 1);
            }
        }
    }
    for (int i = 0; i < x_size; ++i) {
        auto x_bool = L2B::L2B(elgl, lvt, tiny, party, num_party, io, &pool, m_size, m_bits, x_share[i], x_cips[i]);
        tiny.extract_first_12_shares(lut_input_bool_first[i], x_bool);
        tiny.extract_last_12_shares(lut_input_bool_last[i], x_bool); 
    }

    std::vector<Plaintext> X_H(x_size), X_L(x_size);
    std::vector<std::vector<Ciphertext>> X_H_cips(x_size, std::vector<Ciphertext>(num_party));
    std::vector<std::vector<Ciphertext>> X_L_cips(x_size, std::vector<Ciphertext>(num_party));
    for (int i = 0; i < x_size; ++i) {
        auto [plain, cips] = B2L::B2L(elgl, lvt, tiny, party, num_party, io, &pool, lut_input_bool_first[i], tb_size);
        X_H[i] = plain; X_H_cips[i] = cips;
    }
    for (int i = 0; i < x_size; ++i) {
        auto [plain, cips] = B2L::B2L(elgl, lvt, tiny, party, num_party, io, &pool, lut_input_bool_last[i], tb_size);
        X_L[i] = plain; X_L_cips[i] = cips;
    }

    std::vector<Plaintext> A_share(x_size), B_share(x_size);
    std::vector<std::vector<Ciphertext>> A_cips(x_size, std::vector<Ciphertext>(num_party));
    std::vector<std::vector<Ciphertext>> B_cips(x_size, std::vector<Ciphertext>(num_party));
    for (int i = 0; i < x_size; ++i) {
        auto [out1, out2] = lvtA->lookup_online(X_H[i], X_H_cips[i][party-1], X_H_cips[i]);
        auto [out3, out4] = lvtB->lookup_online(X_H[i], X_H_cips[i][party-1], X_H_cips[i]);
        A_share[i] = out1; B_share[i] = out3;
        A_cips[i] = out2; B_cips[i] = out4;
    }

    std::vector<SPDZ2k<MultiIOBase>::LabeledShare> A_spdz2k(x_size), B_spdz2k(x_size), X_L_spdz2k(x_size);
    double online_time = 0, online_comm = 0;
    for (int i = 0; i < x_size; ++i) {
        A_spdz2k[i] = L2A_spdz2k::L2A(elgl, lvt, spdz2k, party, num_party, io, &pool, A_share[i], A_cips[i], m_size, online_time, online_comm);
        B_spdz2k[i] = L2A_spdz2k::L2A(elgl, lvt, spdz2k, party, num_party, io, &pool, B_share[i], B_cips[i], m_size, online_time, online_comm);
        X_L_spdz2k[i] = L2A_spdz2k::L2A(elgl, lvt, spdz2k, party, num_party, io, &pool, X_L[i], X_L_cips[i], m_size, online_time, online_comm);
    }

    auto M_shares = spdz2k.elementwise_multiply(B_spdz2k, X_L_spdz2k, frac);
    auto Y_shares = spdz2k.vector_add(A_spdz2k, M_shares);

    for (int i = 0; i < x_size; ++i) {
        cout << spdz2k.reconstruct(Y_shares[0]) << endl;
    }

    // std::string output_file = "../../TestLYL/Output/Output-P" + std::to_string(party) + ".txt";
    // {
    //     std::ofstream out_file(output_file, std::ios::trunc);
    //     for (int i = 0; i < x_size; ++i) {
    //         out_file << X_H[i].get_message().getStr() << X_L[i].get_message().getStr() << std::endl;
    //     }
    // }

    delete lvt;
    delete elgl;
    delete io;
    return 0;
}
