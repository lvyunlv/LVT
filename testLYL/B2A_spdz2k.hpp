#pragma once
#include "emp-aby/io/multi-io.hpp"
#include "emp-aby/io/mp_io_channel.h"
#include "emp-aby/lvt.h"
#include "emp-aby/elgl_interface.hpp"
#include "emp-aby/tiny.hpp"
#include "emp-aby/spdz2k.hpp"
#include "L2A_spdz2k.hpp"
#include <vector>
#include <mcl/vint.hpp>
#include <random>
#include <map>
#include <stdexcept>
#include <chrono>

namespace B2A_spdz2k {
using namespace emp;
using std::vector;

inline SPDZ2k<MultiIOBase>::LabeledShare B2A(
    ELGL<MultiIOBase>* elgl,
    LVT<MultiIOBase>* lvt,
    TinyMAC<MultiIOBase>& tiny,
    SPDZ2k<MultiIOBase>& spdz2k,
    int party,
    int num_party,
    MultiIO* io,
    ThreadPool* pool,
    const uint64_t& FIELD_SIZE,
    const vector<TinyMAC<MultiIOBase>::LabeledShare>& x_bits,
    double& online_time,
    double& online_comm
) {
    int l = x_bits.size();
    vector<SPDZ2k<MultiIOBase>::LabeledShare> shared_x(l); 
    
    // 1. 随机r_bits
    vector<TinyMAC<MultiIOBase>::LabeledShare> r_bits(l), u_bits(l);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> bit_dis(0, 1);
    for (int i = 0; i < l; ++i) r_bits[i] = tiny.distributed_share(bit_dis(gen));

    // 2. B2L查表
    vector<SPDZ2k<MultiIOBase>::LabeledShare> shared_r(l);
    shared_x.resize(l);

    vector<Ciphertext> x_cipher(l), r_cipher(l), x_lut_ciphers(num_party), r_lut_ciphers(num_party);
    vector<Plaintext> x_plain(l), r_plain(l);
    
    for (int i = 0; i < l; ++i) {
        Plaintext plain_i;
        plain_i.assign(std::to_string(r_bits[i].value));
        r_cipher[i] = lvt->global_pk.encrypt(plain_i);
        lvt->lookup_online(r_plain[i], plain_i, r_cipher[i], r_lut_ciphers);
        shared_r[i] = L2A_spdz2k::L2A_for_B2A(elgl, lvt, spdz2k, party, num_party, io, pool, r_plain[i], r_lut_ciphers, FIELD_SIZE);
        if (shared_r[i].value == 0) shared_r[i].value = 0;
    }

    int bytes_start = io->get_total_bytes_sent();
    auto t1 = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < l; ++i) {
        Plaintext plain_i;
        plain_i.assign(std::to_string(x_bits[i].value));
        x_cipher[i] = lvt->global_pk.encrypt(plain_i);
        lvt->lookup_online(x_plain[i], plain_i, x_cipher[i], x_lut_ciphers);
    }

    int skip_bytes_start = io->get_total_bytes_sent();
    auto skip_t1 = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < l; ++i) {
        shared_x[i] = L2A_spdz2k::L2A_for_B2A(elgl, lvt, spdz2k, party, num_party, io, pool, x_plain[i], x_lut_ciphers, FIELD_SIZE);
        if (shared_x[i].value == 0) shared_x[i].value = 0;
    }
    int skip_bytes_end = io->get_total_bytes_sent();
    auto skip_t2 = std::chrono::high_resolution_clock::now();
    double skip_comm_kb = double(skip_bytes_end - skip_bytes_start) / 1024.0;
    double skip_time_ms = std::chrono::duration<double, std::milli>(skip_t2 - skip_t1).count();

    for (int i = 0; i < l; ++i) u_bits[i] = tiny.add(x_bits[i], r_bits[i]);

    // 4. 校验一致性（可选，出错抛异常）
    for (int i = 0; i < l; ++i) {
        auto spdz2k_u = spdz2k.add(shared_x[i], shared_r[i]);
        auto m = spdz2k.multiply(shared_x[i], shared_r[i]);
        auto spdz2k_open = spdz2k.reconstruct(m);
        spdz2k_open = (spdz2k_open % FIELD_SIZE + FIELD_SIZE) % FIELD_SIZE;

        m = m * 2;
        m.value = (FIELD_SIZE - m.value) % FIELD_SIZE;
        if (m.value < 0) m.value += FIELD_SIZE;
        m.mac = (FIELD_SIZE - m.mac) % FIELD_SIZE;
        if (m.mac < 0) m.mac += FIELD_SIZE;

        spdz2k_u = spdz2k.add(spdz2k_u, m);
        spdz2k_open = spdz2k.reconstruct(spdz2k_u);
        spdz2k_open = (spdz2k_open % FIELD_SIZE + FIELD_SIZE) % FIELD_SIZE;

        uint8_t tiny_u = tiny.reconstruct(tiny.add(x_bits[i], r_bits[i]));
        if (2 + tiny_u % 2 != 2 + spdz2k_open % 2) {
            cout << "tiny_u: " << to_string(tiny_u) << " spdz2k_open: " << spdz2k_open << endl;
            throw std::runtime_error("B2A check failed: decrypted value != share sum");
        }
    }

    // 计算l比特share_x形成的十进制share_x_decimal
    SPDZ2k<MultiIOBase>::LabeledShare share_x_decimal;
    share_x_decimal.value = 0;
    share_x_decimal.mac = 0;
    share_x_decimal.owner = party;
    share_x_decimal.field_size_ptr = &FIELD_SIZE;
    for (int i = 0; i < l; ++i) {
        share_x_decimal = share_x_decimal * 2 + shared_x[i];
    }

    int bytes_end = io->get_total_bytes_sent();
    auto t2 = std::chrono::high_resolution_clock::now();
    double comm_kb = double(bytes_end - bytes_start) / 1024.0 - skip_comm_kb;
    double time_ms = std::chrono::duration<double, std::milli>(t2 - t1).count() - skip_time_ms;
    std::cout << std::fixed << std::setprecision(3)
              << "Communication: " << comm_kb << " KB, "
              << "Time: " << time_ms << " ms" << std::endl;

    online_time = time_ms;
    online_comm = comm_kb;

    return share_x_decimal; 
}

inline SPDZ2k<MultiIOBase>::LabeledShare B2A_for_A2B(
    ELGL<MultiIOBase>* elgl,
    LVT<MultiIOBase>* lvt,
    TinyMAC<MultiIOBase>& tiny,
    SPDZ2k<MultiIOBase>& spdz2k,
    int party,
    int num_party,
    MultiIO* io,
    ThreadPool* pool,
    const uint64_t& FIELD_SIZE,
    const vector<TinyMAC<MultiIOBase>::LabeledShare>& x_bits
) {
    int l = x_bits.size();
    vector<SPDZ2k<MultiIOBase>::LabeledShare> shared_x(l); 

    // int bytes_start = io->get_total_bytes_sent();
    // auto t1 = std::chrono::high_resolution_clock::now();
    
    // 1. 随机r_bits
    vector<TinyMAC<MultiIOBase>::LabeledShare> r_bits(l), u_bits(l);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> bit_dis(0, 1);
    for (int i = 0; i < l; ++i) r_bits[i] = tiny.distributed_share(bit_dis(gen));
    for (int i = 0; i < l; ++i) u_bits[i] = tiny.add(x_bits[i], r_bits[i]);

    // 2. B2L查表
    vector<SPDZ2k<MultiIOBase>::LabeledShare> shared_r(l);
    shared_x.resize(l);

    vector<Ciphertext> x_cipher(l), r_cipher(l), x_lut_ciphers(num_party), r_lut_ciphers(num_party);
    vector<Plaintext> x_plain(l), r_plain(l);
    
    for (int i = 0; i < l; ++i) {
        Plaintext plain_i;
        // cout << "number i: " << i << endl;
        // cout << "x_plain: " << to_string(x_bits[i].value) << endl;   
        // cout << "r_plain: " << to_string(r_bits[i].value) << endl;

        plain_i.assign(std::to_string(x_bits[i].value));
        x_cipher[i] = lvt->global_pk.encrypt(plain_i);
        lvt->lookup_online(x_plain[i], plain_i, x_cipher[i], x_lut_ciphers);
        shared_x[i] = L2A_spdz2k::L2A_for_B2A(elgl, lvt, spdz2k, party, num_party, io, pool, x_plain[i], x_lut_ciphers, FIELD_SIZE);
        if (shared_x[i].value == 0) shared_x[i].value = 0;

        plain_i.assign(std::to_string(r_bits[i].value));
        r_cipher[i] = lvt->global_pk.encrypt(plain_i);
        lvt->lookup_online(r_plain[i], plain_i, r_cipher[i], r_lut_ciphers);
        shared_r[i] = L2A_spdz2k::L2A_for_B2A(elgl, lvt, spdz2k, party, num_party, io, pool, r_plain[i], r_lut_ciphers, FIELD_SIZE);
        if (shared_r[i].value == 0) shared_r[i].value = 0;
    }

    // 4. 校验一致性（可选，出错抛异常）
    for (int i = 0; i < l; ++i) {
        auto spdz2k_u = spdz2k.add(shared_x[i], shared_r[i]);
        auto m = spdz2k.multiply(shared_x[i], shared_r[i]);
        auto spdz2k_open = spdz2k.reconstruct(m);
        spdz2k_open = (spdz2k_open % FIELD_SIZE + FIELD_SIZE) % FIELD_SIZE;

        m = m * 2;
        m.value = (FIELD_SIZE - m.value) % FIELD_SIZE;
        if (m.value < 0) m.value += FIELD_SIZE;
        m.mac = (FIELD_SIZE - m.mac) % FIELD_SIZE;
        if (m.mac < 0) m.mac += FIELD_SIZE;

        spdz2k_u = spdz2k.add(spdz2k_u, m);
        spdz2k_open = spdz2k.reconstruct(spdz2k_u);
        spdz2k_open = (spdz2k_open % FIELD_SIZE + FIELD_SIZE) % FIELD_SIZE;

        uint8_t tiny_u = tiny.reconstruct(tiny.add(x_bits[i], r_bits[i]));
        if ((2 + tiny_u % 2) != (2 + spdz2k_open % 2)) {
            cout << "tiny_u: " << tiny_u << " spdz2k_open: " << spdz2k_open << endl;
            throw std::runtime_error("B2A check failed: decrypted value != share sum");
        }
    }

    // 计算l比特share_x形成的十进制share_x_decimal
    SPDZ2k<MultiIOBase>::LabeledShare share_x_decimal;
    share_x_decimal.value = 0;
    share_x_decimal.mac = 0;
    share_x_decimal.owner = party;
    share_x_decimal.field_size_ptr = &FIELD_SIZE;
    for (int i = 0; i < l; ++i) {
        share_x_decimal = share_x_decimal * 2 + shared_x[i];
    }

    // auto t2 = std::chrono::high_resolution_clock::now();
    // int bytes_end = io->get_total_bytes_sent();
    // double comm_kb = double(bytes_end - bytes_start) / 1024.0;
    // double time_ms = std::chrono::duration<double, std::milli>(t2 - t1).count();
    // std::cout << std::fixed << std::setprecision(3)
    //           << "Communication: " << comm_kb << " KB, "
    //           << "Time: " << time_ms << " ms" << std::endl;
              
    return share_x_decimal; 
}
} // namespace B2A_spdz2k