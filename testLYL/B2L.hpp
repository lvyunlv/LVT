#pragma once
#include "emp-aby/io/multi-io.hpp"
#include "emp-aby/io/mp_io_channel.h"
#include "emp-aby/lvt.h"
#include "emp-aby/elgl_interface.hpp"
#include "emp-aby/tiny.hpp"
#include "L2A_spdz2k.hpp"
#include <vector>
#include <mcl/vint.hpp>
#include <random>
#include <map>
#include <stdexcept>
#include <chrono>
#include <tuple>

namespace B2L {
using namespace emp;
using std::vector;

inline tuple<Plaintext, vector<Ciphertext>> B2L(ELGL<MultiIOBase>* elgl, LVT<MultiIOBase>* lvt, TinyMAC<MultiIOBase>& tiny, int party, int num_party, MultiIO* io, ThreadPool* pool, const vector<TinyMAC<MultiIOBase>::LabeledShare>& x_bits, const uint64_t& modulus) {
    int bytes_start = io->get_total_bytes_sent();
    auto t1 = std::chrono::high_resolution_clock::now();

    int l = x_bits.size();
    vector<Plaintext> shared_x(l); 
    Plaintext fd(modulus);
    
    vector<TinyMAC<MultiIOBase>::LabeledShare> r_bits(l);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> bit_dis(0, 1);
    for (int i = 0; i < l; ++i) {
        r_bits[i] = tiny.distributed_share(bit_dis(gen));
    }

    vector<Ciphertext> x_cipher(l), r_cipher(l), x_lut_ciphers(num_party), r_lut_ciphers(num_party);
    vector<Plaintext> x_plain(l), r_plain(l);
    
    for (int i = 0; i < l; ++i) {
        Plaintext plain_i;
        plain_i.assign(std::to_string(r_bits[i].value));
        r_cipher[i] = lvt->global_pk.encrypt(plain_i);
        auto [out1, out2] = lvt->lookup_online(plain_i, r_cipher[i], r_lut_ciphers);
        r_plain[i] = out1;
    }

    int bytes_end = io->get_total_bytes_sent();
    auto t2 = std::chrono::high_resolution_clock::now();
    double comm_kb = double(bytes_end - bytes_start) / 1024.0;
    double time_ms = std::chrono::duration<double, std::milli>(t2 - t1).count();
    cout << "Offline time: " << time_ms << " ms, comm: " << comm_kb << " KB" << std::endl;

    int bytes_start1 = io->get_total_bytes_sent();
    auto t3 = std::chrono::high_resolution_clock::now();

    vector<Plaintext> out(l);
    for (int i = 0; i < l; ++i) {
        Plaintext plain_i;
        plain_i.assign(std::to_string(x_bits[i].value));
        x_cipher[i] = lvt->global_pk.encrypt(plain_i);
        auto [out1, out2] = lvt->lookup_online(plain_i, x_cipher[i], x_lut_ciphers);
        x_plain[i] = out1;
    }
    
    Plaintext x; x.assign("0");
    for (int i = 0; i < l; ++i) {
        out[i] = x_plain[i]^r_plain[i];
        x = (x + x + x_plain[i]) % fd;
        elgl->serialize_sendall(out[i]);
        for (int j = 0; j < num_party; ++j) {
            if (j != party - 1) {
                Plaintext plain_i;
                elgl->deserialize_recv(plain_i, j + 1);
                out[i] ^= plain_i;
            }
        }
    }

    for (int i = 0; i < l; ++i) {
        uint8_t out_ = tiny.reconstruct(tiny.add(x_bits[i],r_bits[i]));
        if (out_ != out[i].get_message().getMpz().getLow32bit()) {
            std::cerr << "Error: B2L output does not match expected value." << std::endl;
            cout << i << " Expected: " << int(out_) << ", Got: " << int(out[i].get_message().getMpz().getLow32bit()) << std::endl;
            throw std::runtime_error("B2L output mismatch");
        }
    }

    vector<Ciphertext> x_cip(num_party);
    x_cip[party - 1] = lvt->global_pk.encrypt(x);
    elgl->serialize_sendall(x_cip[party - 1]);

    for (int i = 1; i <= num_party; ++i) {
        if (i != party) {
            elgl->deserialize_recv(x_cip[i - 1], i);
        }
    }

    int bytes_end1 = io->get_total_bytes_sent();
    auto t4 = std::chrono::high_resolution_clock::now();
    double comm_kb1 = double(bytes_end1 - bytes_start1) / 1024.0;
    double time_ms1 = std::chrono::duration<double, std::milli>(t4 - t3).count();
    cout << "Online time: " << time_ms1 << " ms, comm: " << comm_kb1 << " KB" << std::endl;

    return std::make_tuple(x, x_cip);
}


inline tuple<Plaintext, vector<Ciphertext>> B2L_for_L2B(
    ELGL<MultiIOBase>* elgl,
    LVT<MultiIOBase>* lvt,
    TinyMAC<MultiIOBase>& tiny,
    int party,
    int num_party,
    MultiIO* io,
    ThreadPool* pool,
    const vector<TinyMAC<MultiIOBase>::LabeledShare>& x_bits,
    const uint64_t& modulus
) {
    int l = x_bits.size();
    vector<Plaintext> shared_x(l); 
    Plaintext fd(modulus);
    
    vector<TinyMAC<MultiIOBase>::LabeledShare> r_bits(l);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> bit_dis(0, 1);
    for (int i = 0; i < l; ++i) {
        r_bits[i] = tiny.distributed_share(bit_dis(gen));
    }

    vector<Ciphertext> x_cipher(l), r_cipher(l), x_lut_ciphers(num_party), r_lut_ciphers(num_party);
    vector<Plaintext> x_plain(l), r_plain(l);
    
    for (int i = 0; i < l; ++i) {
        Plaintext plain_i;
        plain_i.assign(std::to_string(r_bits[i].value));
        r_cipher[i] = lvt->global_pk.encrypt(plain_i);
        auto [out1, out2] = lvt->lookup_online(plain_i, r_cipher[i], r_lut_ciphers);
        r_plain[i] = out1;
    }

    vector<Plaintext> out(l);
    for (int i = 0; i < l; ++i) {
        Plaintext plain_i;
        plain_i.assign(std::to_string(x_bits[i].value));
        x_cipher[i] = lvt->global_pk.encrypt(plain_i);
        auto [out1, out2] = lvt->lookup_online(plain_i, x_cipher[i], x_lut_ciphers);
        x_plain[i] = out1;
    }
    
    Plaintext x; x.assign("0");
    for (int i = 0; i < l; ++i) {
        out[i] = x_plain[i]^r_plain[i];
        x = (x + x + x_plain[i]) % fd;
        elgl->serialize_sendall(out[i]);
        for (int j = 0; j < num_party; ++j) {
            if (j != party - 1) {
                Plaintext plain_i;
                elgl->deserialize_recv(plain_i, j + 1);
                out[i] ^= plain_i;
            }
        }
    }

    for (int i = 0; i < l; ++i) {
        uint8_t out_ = tiny.reconstruct(tiny.add(x_bits[i],r_bits[i]));
        if (out_ != out[i].get_message().getMpz().getLow32bit()) {
            std::cerr << "Error: B2L output does not match expected value." << std::endl;
            cout << i << " Expected: " << int(out_) << ", Got: " << int(out[i].get_message().getMpz().getLow32bit()) << std::endl;
            throw std::runtime_error("B2L output mismatch in B2L_for_L2B");
        }
    }

    vector<Ciphertext> x_cip(num_party);
    x_cip[party - 1] = lvt->global_pk.encrypt(x);
    elgl->serialize_sendall(x_cip[party - 1]);

    for (int i = 1; i <= num_party; ++i) {
        if (i != party) {
            elgl->deserialize_recv(x_cip[i - 1], i);
        }
    }

    return std::make_tuple(x, x_cip);
}

}

inline std::vector<uint8_t> get_first_12_bits(const std::vector<uint8_t>& input) {
    if (input.size() != 24) {
        throw std::invalid_argument("Input vector must have exactly 24 bits.");
    }
    return std::vector<uint8_t>(input.begin(), input.begin() + 12);
}

inline std::vector<uint8_t> get_last_12_bits(const std::vector<uint8_t>& input) {
    if (input.size() != 24) {
        throw std::invalid_argument("Input vector must have exactly 24 bits.");
    }
    return std::vector<uint8_t>(input.begin() + 12, input.end());
}