#include "secret_tensor.hpp"
#include "FixedPointConverter.h"
#include "emp-aby/emp-aby.h"
#include <iostream>

using namespace emp;
int party, port;
const static int threads = 8;
int num_party;
// const uint64_t FIELD_SIZE("340282366920938463463374607431768211297");
const uint64_t FIELD_SIZE = (1ULL << 63) - 1;
int m_bits = 32; // bits of message - 已在 secret_tensor.hpp 中定义

Fr alpha_init(int num) {
    Plaintext alpha;
    const mcl::Vint p("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
    const mcl::Vint g("5"); 
    mcl::Vint n = uint64_t(1) << num;
    mcl::Vint alpha_vint;
    mcl::gmp::powMod(alpha_vint, g, (p - 1) / n, p);
    alpha.assign(alpha_vint.getStr());
    Fr alpha_fr = alpha.get_message();
    vector<int64_t> lut_table = {0, 1};
    serializeTable(lut_table, "table.txt", lut_table.size());
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

    int num = 1;
    Fr alpha_fr = alpha_init(num);
    LVT<MultiIOBase>* lvt = new LVT<MultiIOBase>(num_party, party, io, &pool, elgl, "../../build/bin/table.txt", alpha_fr, num, m_bits);

    lvt->DistKeyGen();

    SPDZ2k<MultiIOBase> spdz2k(elgl);

    // 测试张量初始化
    std::vector<size_t> shape = {2, 2};
    std::vector<uint64_t> plain_values = {1, 2, 3, 4};

    using ST = SecretTensor<MultiIOBase>;
    auto tensor = ST::from_plaintext(shape, plain_values, spdz2k, elgl, lvt, static_cast<MPIOChannel<MultiIOBase>*>(io), &pool, party, num_party, FIELD_SIZE);

    if (party == ALICE) std::cout << "[*] SPDZ2k init done." << std::endl;

    // 转为 LUT share
    tensor.to_lut();
    if (party == ALICE) std::cout << "[*] Converted to LUT share." << std::endl;

    // 转回 SPDZ2k
    tensor.to_spdz2k();
    if (party == ALICE) std::cout << "[*] Converted back to SPDZ2k." << std::endl;

    // Reveal 检查
    std::vector<uint64_t> revealed;
    for (const auto& share : tensor.data_spdz2k) {
        revealed.push_back(spdz2k.reconstruct(share));
    }
    // if (party == ALICE) {
    //     std::cout << "Reconstructed values: ";
    //     for (auto& v : revealed) std::cout << v << " ";
    //     std::cout << std::endl;
    // }

    if (party == ALICE) std::cout << "\n[*] Testing add and matmul...\n";

    std::vector<uint64_t> A_current_share = {
        FixedPointConverter::encode(1.0),
        FixedPointConverter::encode(2.0),
        FixedPointConverter::encode(-3.0),
        FixedPointConverter::encode(-4.5)
    }; // shape: 2x2

    std::vector<uint64_t> B_current_share = {
        FixedPointConverter::encode(1.0),
        FixedPointConverter::encode(2.0),
        FixedPointConverter::encode(-3.0),
        FixedPointConverter::encode(-4.5)
    }; // shape: 2x2

    auto A_current = SecretTensor<MultiIOBase>::from_plaintext({2, 2}, A_current_share, spdz2k, elgl, lvt, io, &pool, party, num_party, FIELD_SIZE);
    auto B_current = SecretTensor<MultiIOBase>::from_plaintext({2, 2}, B_current_share, spdz2k, elgl, lvt, io, &pool, party, num_party, FIELD_SIZE);

    auto C_add = A_current.add(B_current); 
    auto C_mul = A_current.matmul(B_current); 
    std::cout << "Revealed A + B: ";
    for (const auto& s : C_add.data_spdz2k){
        uint64_t v = spdz2k.reconstruct(s) % FixedPoint_SIZE;
        // std::cout << v << " ";
        std::cout << FixedPointConverter::decode(v) << " ";
    }
    std::cout << "\n";

    std::cout << "Revealed A x B: ";
    for (const auto& s : C_mul.data_spdz2k){
        uint64_t raw_value = spdz2k.reconstruct(s);
        std::cout << FixedPointConverter::decode(raw_value % FixedPoint_SIZE) << " ";
    }
    std::cout << "\n";

    // cout << "data_spdz2k_a: " << A_current.data_spdz2k[0].value << " " << A_current.data_spdz2k[0].mac << std::endl;
    // cout << "data_spdz2k_b: " << B_current.data_spdz2k[0].value << " " << B_current.data_spdz2k[0].mac << std::endl;
    // SPDZ2k<MultiIOBase>::LabeledShare xx = spdz2k.multiply_with_trunc(A_current.data_spdz2k[0], B_current.data_spdz2k[0], 16);
    // uint64_t raw_value = spdz2k.reconstruct(xx);
    // std::cout << "Revealed multiply: Raw: " << raw_value << " Decoded: " << FixedPointConverter::decode(raw_value % FixedPoint_SIZE) << std::endl;

    delete io;
    return 0;
}
