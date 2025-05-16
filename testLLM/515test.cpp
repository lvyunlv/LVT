#include "emp-aby/lvt.h"
#include "emp-aby/io/multi-io.hpp"
#include "testLYL/L2B.hpp"
#include "testLYL/B2L.hpp"
#include "testLYL/A2L_spdz2k.hpp"
#include "testLYL/L2A_spdz2k.hpp"
#include "testLLM/FixedPointConverter.h"
#include <memory>
#include <filesystem>
#include <bitset>
#include <string>

using namespace emp;
namespace fs = std::filesystem;

int num_party, party, port;
const static int threads = 8;
const int m_bits = 24; // 表值比特数，在B2L和L2B中为1，在非线性函数计算调用时为24（表示Q8.16定点整数）
const int m_size = 1UL << m_bits; // 表值大小
const int num = 12;
const size_t tb_size = 1ULL << num; // 表的大小
const int frac = 16; // 截断
const int bitN = 1;


int main(int argc, char** argv) {
    BLS12381Element::init();
    if (argc < 5) {
        std::cout << "Format: <PartyID> <port> <num_parties>" << std::endl;
        return 0;
    }
    parse_party_and_port(argv, &party, &port);
    num_party = std::stoi(argv[3]);
    std::string func_name = argv[4];
    std::string filebit = "2";
    std::string fileA = func_name + "A";
    std::string fileB = func_name + "B";
    std::string input_file = "../../TestLLM/Input/Input-P" + std::to_string(party) + ".txt";

    std::vector<std::pair<std::string, unsigned short>> net_config;
    if (argc == 6) {
        const char* file = argv[5];
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
    auto io = std::make_unique<MultiIO>(party, num_party, net_config);
    auto elgl = std::make_unique<ELGL<MultiIOBase>>(num_party, io.get(), &pool, party);
    TinyMAC<MultiIOBase> tiny(elgl.get());
    SPDZ2k<MultiIOBase> spdz2k(elgl.get());
    mcl::Vint modulo = m_size;
    Fr alpha_frA = alpha_init(num);
    Fr alpha_frB = alpha_init(num);
    Fr alpha_fr_bit = alpha_init(bitN);
    std::unique_ptr<LVT<MultiIOBase>> lvt_bit, lvtA, lvtB;
    LVT<MultiIOBase>* lvt_raw_bit = nullptr; LVT<MultiIOBase>* lvt_rawA = nullptr; LVT<MultiIOBase>* lvt_rawB = nullptr;

    LVT<MultiIOBase>::initialize(filebit, lvt_raw_bit, num_party, party, io.get(), &pool, elgl.get(), alpha_fr_bit, bitN, bitN);
    lvt_bit.reset(lvt_raw_bit);
    LVT<MultiIOBase>::initialize(fileA, lvt_rawA, num_party, party, io.get(), &pool, elgl.get(), alpha_frA, num, m_bits);
    lvtA.reset(lvt_rawA);
    LVT<MultiIOBase>::initialize(fileB, lvt_rawB, num_party, party, io.get(), &pool, elgl.get(), alpha_frB, num, m_bits);
    lvtB.reset(lvt_rawB);

    std::vector<Plaintext> x_share;
    {
        std::ifstream in_file(input_file);
        std::string line;
        while (std::getline(in_file, line)) {
            double xval = std::stod(line);
            uint64_t xval_int = FixedPointConverter::encode(xval);

            Plaintext x;
            x.assign(xval_int);
            x_share.push_back(x);
            if (x.get_message().getUint64() > (1ULL << m_bits) - 1) {
                std::cerr << "Error: input value exceeds table size in Party: " << party << std::endl;
                cout << "Error value: " << x.get_message().getUint64() << ", tb_size = " << (1ULL << m_bits) << endl;
                return 1;
            }
        }
    }
    int x_size = x_share.size();
    
    // lvtA->global_pk.get_pk().print_str();
    // lvtB->global_pk.get_pk().print_str();
    // lvt_bit->global_pk.get_pk().print_str();

    std::vector<Ciphertext> x_cipher(x_size);
    for (int i = 0; i < x_size; ++i) {
        x_cipher[i] = lvtA->global_pk.encrypt(x_share[i]);
        cout << "x_share: " << x_share[i].get_message().getStr() << endl;
        cout << "plaintext: " << lvtA->Reconstruct_interact(x_share[i], x_cipher[i], elgl.get(), lvtA->global_pk, lvtA->user_pk, io.get(), &pool, party, num_party, modulo).get_message().getUint64() << endl;
    }

    std::vector<std::vector<TinyMAC<MultiIOBase>::LabeledShare>> lut_input_bool_first(x_size, std::vector<TinyMAC<MultiIOBase>::LabeledShare>(num));
    std::vector<std::vector<TinyMAC<MultiIOBase>::LabeledShare>> lut_input_bool_last(x_size, std::vector<TinyMAC<MultiIOBase>::LabeledShare>(num));
    std::vector<std::vector<Ciphertext>> x_cips(x_size, std::vector<Ciphertext>(num_party));
    for (int i = 0; i < x_size; ++i) {
        x_cips[i][party - 1] = lvtA->global_pk.encrypt(x_share[i]);
        elgl->serialize_sendall(x_cips[i][party - 1]);
        for (int j = 0; j < num_party; ++j) {
            if (j != party - 1) {
                elgl->deserialize_recv(x_cips[i][j], j + 1);
            }
        }
    }
    for (int i = 0; i < x_size; ++i) {
        auto x_bool = L2B::L2B(elgl.get(), lvt_bit.get(), tiny, party, num_party, io.get(), &pool, m_size, m_bits, x_share[i], x_cips[i]);

        std::vector<int> bits1; // 用于存储 24 个比特
        for (int j = 0; j < 24; ++j) {
            int bit = tiny.reconstruct(x_bool[j]);
            cout << bit;
            bits1.push_back(bit);
        }
        uint64_t decimal_value1 = bits_to_decimal(bits1, m_size);
        cout << endl << "Decimal decimal_value1 : " << decimal_value1 << endl;

        tiny.extract_first_12_shares(lut_input_bool_first[i], x_bool);
        tiny.extract_last_12_shares(lut_input_bool_last[i], x_bool); 
        
        std::vector<int> bits; // 用于存储 24 个比特

        // 收集第一个 12 比特
        for (int j = 0; j < 12; ++j) {
            int bit = tiny.reconstruct(lut_input_bool_first[i][j]);
            cout << bit;
            bits.push_back(bit);
        }

        // 收集第二个 12 比特
        for (int j = 0; j < 12; ++j) {
            int bit = tiny.reconstruct(lut_input_bool_last[i][j]);
            cout << bit;
            bits.push_back(bit);
        }

        // 将 24 个比特转换为十进制数
        uint64_t decimal_value = bits_to_decimal(bits, m_size);
        cout << endl << "Decimal: " << decimal_value << endl;
    }
    cout << endl;

    std::vector<Plaintext> X_H(x_size), X_L(x_size);
    std::vector<std::vector<Ciphertext>> X_H_cips(x_size, std::vector<Ciphertext>(num_party));
    std::vector<std::vector<Ciphertext>> X_L_cips(x_size, std::vector<Ciphertext>(num_party));
    for (int i = 0; i < x_size; ++i) {
        auto [plain, cips] = B2L::B2L(elgl.get(), lvt_bit.get(), tiny, party, num_party, io.get(), &pool, lut_input_bool_first[i], tb_size);
        X_H[i] = plain; X_H_cips[i] = cips;
    }
    for (int i = 0; i < x_size; ++i) {
        auto [plain, cips] = B2L::B2L(elgl.get(), lvt_bit.get(), tiny, party, num_party, io.get(), &pool, lut_input_bool_last[i], tb_size);
        X_L[i] = plain; X_L_cips[i] = cips;
    }


    for (int i = 0; i < x_size; ++i) {
        double a,b;
        Plaintext A_ = lvtA->Reconstruct(X_H[i], X_H_cips[i], elgl.get(), lvtA->global_pk, lvtA->user_pk, io.get(), &pool, party, num_party, modulo);
        Plaintext B_ = lvtB->Reconstruct(X_L[i], X_L_cips[i], elgl.get(), lvtB->global_pk, lvtB->user_pk, io.get(), &pool, party, num_party, modulo);
        a = FixedPointConverter::decode(A_.get_message().getUint64());
        b = FixedPointConverter::decode(B_.get_message().getUint64());
        cout << "A: " << a << " B: " << b << endl;
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

    // for (int i = 0; i < x_size; ++i) {
    //     double a,b;
    //     Plaintext A_ = lvtA->Reconstruct(A_share[i], A_cips[i]);
    //     Plaintext B_ = lvtB->Reconstruct(B_share[i], B_cips[i]);
    //     a = FixedPointConverter::decode(A_.get_message().getUint64());
    //     b = FixedPointConverter::decode(B_.get_message().getUint64());
    //     cout << "A: " << a << " B: " << b << endl;
    // }

    // std::vector<SPDZ2k<MultiIOBase>::LabeledShare> A_spdz2k(x_size), B_spdz2k(x_size), X_L_spdz2k(x_size);
    // double online_time = 0, online_comm = 0;
    // for (int i = 0; i < x_size; ++i) {
    //     A_spdz2k[i] = L2A_spdz2k::L2A(elgl.get(), lvtA.get(), spdz2k, party, num_party, io.get(), &pool, A_share[i], A_cips[i], m_size, online_time, online_comm);
    //     B_spdz2k[i] = L2A_spdz2k::L2A(elgl.get(), lvtB.get(), spdz2k, party, num_party, io.get(), &pool, B_share[i], B_cips[i], m_size, online_time, online_comm);
    //     X_L_spdz2k[i] = L2A_spdz2k::L2A(elgl.get(), lvtA.get(), spdz2k, party, num_party, io.get(), &pool, X_L[i], X_L_cips[i], m_size, online_time, online_comm);
    // }

    // auto M_shares = spdz2k.elementwise_multiply(B_spdz2k, X_L_spdz2k, frac);
    // auto Y_shares = spdz2k.vector_add(A_spdz2k, M_shares);

    // for (int i = 0; i < x_size; ++i) {
    //     cout << spdz2k.reconstruct(Y_shares[0]) << endl;
    // }

    // std::string output_file = "../../TestLYL/Output/Output-P" + std::to_string(party) + ".txt";
    // {
    //     std::ofstream out_file(output_file, std::ios::trunc);
    //     for (int i = 0; i < x_size; ++i) {
    //         out_file << X_H[i].get_message().getStr() << X_L[i].get_message().getStr() << std::endl;
    //     }
    // }

    return 0;
}
