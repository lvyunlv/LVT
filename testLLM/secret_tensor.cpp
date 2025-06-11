#include "secret_tensor.hpp"
#include "FixedPointConverter.h"
#include "emp-aby/emp-aby.h"
#include <iostream>

using namespace emp;
int party, port;
const static int threads = 8;
int num_party;
// const uint64_t FIELD_SIZE("52435875175126190479447740508185965837690552500527637822603658699938581184512");
// const uint64_t FIELD_SIZE = (1ULL << 63) - 1;
// int m_bits = 32; // bits of message - 已在 secret_tensor.hpp 中定义
int fixedpoint_bits = 24;

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

    Fr alpha_fr = alpha_init(fixedpoint_bits);
    LVT<MultiIOBase>* lvt = new LVT<MultiIOBase>(num_party, party, io, &pool, elgl, "init", alpha_fr, fixedpoint_bits, fixedpoint_bits);
    lvt->DistKeyGen();
    SPDZ2k<MultiIOBase> spdz2k(elgl);

    // 测试张量初始化
    std::vector<size_t> shape = {2, 2};
    std::vector<uint64_t> plain_values = {1, 2, 3, 4};

    using ST = SecretTensor<MultiIOBase>;
    auto tensor = ST::from_plaintext(shape, plain_values, spdz2k, elgl, lvt, static_cast<MPIOChannel<MultiIOBase>*>(io), &pool, party, num_party, fixedpoint_bits);

    tensor.to_lut();
    tensor.to_spdz2k();
    
    std::vector<uint64_t> revealed;
    for (const auto& share : tensor.data_spdz2k) {
        revealed.push_back(spdz2k.reconstruct(share));
    }

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

    auto A_current = SecretTensor<MultiIOBase>::from_plaintext({2, 2}, A_current_share, spdz2k, elgl, lvt, io, &pool, party, num_party, fixedpoint_bits);
    auto B_current = SecretTensor<MultiIOBase>::from_plaintext({2, 2}, B_current_share, spdz2k, elgl, lvt, io, &pool, party, num_party, fixedpoint_bits);

    auto C_add = A_current.add(B_current); 
    auto C_mul = A_current.matmul(B_current); 
    std::cout << "Revealed A + B: "; //应当为 4 8 -12 -18 
    for (const auto& s : C_add.data_spdz2k){
        uint64_t v = spdz2k.reconstruct(s) % FixedPoint_SIZE;
        // std::cout << v << " ";
        std::cout << FixedPointConverter::decode(v) << " ";
    }
    std::cout << "\n";

    std::cout << "Revealed A x B: "; //应当为 -20 -28 42 57 
    for (const auto& s : C_mul.data_spdz2k){
        uint64_t raw_value = spdz2k.reconstruct(s);
        std::cout << FixedPointConverter::decode(raw_value % FixedPoint_SIZE) << " ";
    }
    std::cout << "\n";

    auto C_sub = A_current.sub(B_current);
    std::cout << "Revealed A - B: "; //应当为 0 0 0 0
    for (const auto& s : C_sub.data_spdz2k){
        uint64_t v = spdz2k.reconstruct(s) % FixedPoint_SIZE;
        std::cout << FixedPointConverter::decode(v) << " ";
    }
    std::cout << "\n";

    auto C_elemul = A_current.mul(B_current);
    std::cout << "Revealed A .* B: "; //应当为 4 16 36 81
    for (const auto& s : C_elemul.data_spdz2k){
        uint64_t v = spdz2k.reconstruct(s) % FixedPoint_SIZE;
        std::cout << FixedPointConverter::decode(v) << " ";
    }
    std::cout << "\n";

    // auto C_relu = A_current.relu();
    // std::cout << "Revealed relu(A): ";
    // for (const auto& v : C_relu.data_lut_plain){
    //     std::cout << FixedPointConverter::decode(v.get_message().getUint64() % FixedPoint_SIZE) << " ";
    // }
    // std::cout << "\n";
    
    // auto C_sigmoid = A_current.sigmoid();
    // std::cout << "Revealed sigmoid(A): ";
    // for (const auto& v : C_sigmoid.data_lut_plain){
    //     std::cout << FixedPointConverter::decode(v.get_message().getUint64() % FixedPoint_SIZE) << " ";
    // }
    // std::cout << "\n";


    // auto C_sqrt = A_current.sqrt();
    // std::cout << "Revealed sqrt(A): ";
    // for (const auto& v : C_sqrt.data_lut_plain){
    //     std::cout << FixedPointConverter::decode(v.get_message().getUint64() % FixedPoint_SIZE) << " ";
    // }
    // std::cout << "\n";

    // auto C_sum = A_current.sum();
    // auto C_mean = A_current.mean();
    // if (C_sum.data_spdz2k.size() > 0) {
    //     uint64_t v_sum = spdz2k.reconstruct(C_sum.data_spdz2k[0]) % FixedPoint_SIZE;
    //     std::cout << "Revealed sum(A): " << FixedPointConverter::decode(v_sum) << std::endl;
    // }
    // if (C_mean.data_lut_plain.size() > 0) {
    //     std::cout << "Revealed mean(A): " << FixedPointConverter::decode(C_mean.data_lut_plain[0].get_message().getUint64() % FixedPoint_SIZE) << std::endl;
    // }

    // auto C_reshape = A_current.reshape({4});
    // std::cout << "Revealed reshape(A) to 1D: ";
    // for (const auto& s : C_reshape.data_spdz2k){
    //     uint64_t v = spdz2k.reconstruct(s) % FixedPoint_SIZE;
    //     std::cout << FixedPointConverter::decode(v) << " ";
    // }
    // std::cout << "\n";

    // auto C_slice = A_current.slice({1}, {3});
    // std::cout << "Revealed slice(A)[1:3]: ";
    // for (const auto& s : C_slice.data_spdz2k){
    //     uint64_t v = spdz2k.reconstruct(s) % FixedPoint_SIZE;
    //     std::cout << FixedPointConverter::decode(v) << " ";
    // }
    // std::cout << "\n";

    // auto stacked = SecretTensor<MultiIOBase>::stack({A_current, B_current}, 0);
    // std::cout << "Revealed stack(A, B): ";
    // for (const auto& s : stacked.data_spdz2k){
    //     uint64_t v = spdz2k.reconstruct(s) % FixedPoint_SIZE;
    //     std::cout << FixedPointConverter::decode(v) << " ";
    // }
    // std::cout << "\n";

    // auto concated = SecretTensor<MultiIOBase>::concat({A_current, B_current}, 0);
    // std::cout << "Revealed concat(A, B): ";
    // for (const auto& s : concated.data_spdz2k){
    //     uint64_t v = spdz2k.reconstruct(s) % FixedPoint_SIZE;
    //     std::cout << FixedPointConverter::decode(v) << " ";
    // }
    // std::cout << "\n";

    // auto C_div = A_current.div(B_current);
    // std::cout << "Revealed A / B: ";
    // for (const auto& v : C_div.data_lut_plain){
    //     std::cout << FixedPointConverter::decode(v.get_message().getUint64() % FixedPoint_SIZE) << " ";
    // }
    // std::cout << "\n";

    delete io;
    return 0;
}
