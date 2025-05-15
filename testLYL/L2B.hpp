#pragma once
#include "emp-aby/io/multi-io.hpp"
#include "emp-aby/io/mp_io_channel.h"
#include "emp-aby/lvt.h"
#include "emp-aby/elgl_interface.hpp"
#include "emp-aby/tiny.hpp"
#include "B2L.hpp"
#include <vector>
#include <mcl/vint.hpp>
#include <map>
#include <chrono>

namespace A2B_spdz2k {
using namespace emp;
using std::vector;

// 输入：算术份额（SPDZ2k），输出：布尔份额（TinyMAC）
inline vector<TinyMAC<MultiIOBase>::LabeledShare> L2B(ELGL<MultiIOBase>* elgl, LVT<MultiIOBase>* lvt, TinyMAC<MultiIOBase>& tiny, int party, int num_party, MultiIO* io, ThreadPool* pool, const uint64_t& FIELD_SIZE, int l, Plaintext& x_arith, vector<Ciphertext>& x_cips) {
    int bytes_start = io->get_total_bytes_sent();
    auto t1 = std::chrono::high_resolution_clock::now();
    Plaintext fd(FIELD_SIZE);

    vector<TinyMAC<MultiIOBase>::LabeledShare> x_bool(l);
    vector<TinyMAC<MultiIOBase>::LabeledShare> r_bits(l);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> bit_dis(0, 1);
    for (int i = 0; i < l; ++i) {
        r_bits[i] = tiny.distributed_share(bit_dis(gen));
        // cout << "r_bits[" << i << "] = " << int(r_bits[i].value) << std::endl;
    }

    // 2. B2A: r_bits -> r_arith
    auto [r_arith, r_cips] = B2A_spdz2k::B2L_for_L2B(elgl, lvt, tiny, party, num_party, io, pool, r_bits);
    // cout << "r_arith = " << r_arith.get_message().getUint64() << std::endl;

    auto t2 = std::chrono::high_resolution_clock::now();
    int bytes_end = io->get_total_bytes_sent();
    double comm_kb = double(bytes_end - bytes_start) / 1024.0;
    double time_ms = std::chrono::duration<double, std::milli>(t2 - t1).count();
    std::cout << std::fixed << std::setprecision(3)
              << "Communication: " << comm_kb << " KB, "
              << "Time: " << time_ms << " ms" << std::endl;

    int bytes_start1 = io->get_total_bytes_sent();
    auto t3 = std::chrono::high_resolution_clock::now();

    // 3. 算术MPC本地加法 x + r
    Plaintext u; vector<Ciphertext> u_cips(num_party);
    u = (x_arith + r_arith) % fd;
    u_cips[party - 1] = elgl->kp.get_pk().encrypt(u);
    elgl->serialize_sendall(u);
    elgl->serialize_sendall(u_cips[party - 1]);
    for (int i = 0; i < num_party; ++i) {
        Plaintext tmp;
        if (i != party - 1) {
            elgl->deserialize_recv(tmp, i + 1);
            u = (u + tmp) % fd;
            elgl->deserialize_recv(u_cips[i], i + 1);   
        }
    }
    // cout << "u = " << u.get_message().getUint64() << std::endl;

    // 5. P1计算u的l比特分解
    vector<uint8_t> u_bits(l, 0);
    if (party == 1){
        uint64_t tmp = u.get_message().getUint64();
        for (int i = l-1; i >= 0; --i) {
            u_bits[i] = tmp & 1; 
            tmp >>= 1;
        }
    } else{
        for (int i = 0; i < l; ++i) {
            u_bits[i] = 0;
        }
    }
    // for (int i = 0; i < l; ++i) {
    //     cout << "u_bits[" << i << "] = " << int(u_bits[i]) << std::endl;
    // }

    // 6. 各方分发布尔份额 <u>^b
    vector<TinyMAC<MultiIOBase>::LabeledShare> u_bool(l);
    for (int i = 0; i < l; ++i) u_bool[i] = tiny.distributed_share(u_bits[i]);
    // 7. 输出 x_bool = u_bool ⊕ r_bits
    for (int i = 0; i < l; ++i) x_bool[i] = tiny.add(u_bool[i], r_bits[i]);

    // for (int i = 0; i < l; ++i) {
    //     cout << "u_bool[" << i << "] = " << int(u_bool[i].value) << std::endl;
    // }
    // for (int i = 0; i < l; ++i) {
    //     cout << "x_bool[" << i << "] = " << int(x_bool[i].value) << std::endl;
    // }
    
    uint64_t sum = 0;
    for (int i = 0; i < l; ++i) {
        uint8_t open = tiny.reconstruct(u_bool[i]);
        sum = (sum << 1) | open;
    }
    for (int i = 0; i < l; ++i) {
        
        if (u.get_message().getUint64() != sum) {
            std::cerr << "Party " << party << " error: u_open[" << i << "] = " << u.get_message().getUint64() << ", expected " << sum << std::endl;
            throw std::runtime_error("B2L output mismatch");
        }
    }


    auto t4 = std::chrono::high_resolution_clock::now();
    int bytes_end1 = io->get_total_bytes_sent();
    double comm_kb1 = double(bytes_end1 - bytes_start1) / 1024.0;
    double time_ms1 = std::chrono::duration<double, std::milli>(t4 - t3).count();
    std::cout << std::fixed << std::setprecision(3)
              << "Communication: " << comm_kb1 << " KB, "
              << "Time: " << time_ms1 << " ms" << std::endl;

    return x_bool;
}
} // namespace A2B_spdz2k 