#pragma once
#include "emp-aby/io/multi-io.hpp"
#include "emp-aby/io/mp_io_channel.h"
#include "emp-aby/lvt.h"
#include "emp-aby/elgl_interface.hpp"
#include "emp-aby/spdz2k.hpp"
#include <vector>
#include <tuple>
#include <mcl/vint.hpp>
#include <map>
#include <iostream>
#include <iomanip>
#include <chrono>

namespace L2A_spdz2k {
using namespace emp;
using std::vector;
using std::tuple;
using std::map;

inline SPDZ2k<MultiIOBase>::LabeledShare L2A(
    ELGL<MultiIOBase>* elgl,
    LVT<MultiIOBase>* lvt,
    SPDZ2k<MultiIOBase>& spdz2k,
    int party,
    int num_party,
    MultiIO* io,
    ThreadPool* pool,
    const Plaintext& x_plain,
    const vector<Ciphertext>& vec_cx,
    const uint64_t& fd,
    map<std::string, Fr>& P_to_m
) {
    SPDZ2k<MultiIOBase>::LabeledShare shared_x;
    int bytes_start = io->get_total_bytes_sent();
    auto t1 = std::chrono::high_resolution_clock::now();

    uint64_t r_spdz2k = spdz2k.rng() % fd;
    SPDZ2k<MultiIOBase>::LabeledShare shared_r;
    shared_r = spdz2k.distributed_share(r_spdz2k);
    shared_x = spdz2k.distributed_share(x_plain.get_message().getUint64());

    Plaintext r;
    r.assign(to_string(r_spdz2k));

    Ciphertext cr, count;

    cr = lvt->global_pk.encrypt(r);
    count = vec_cx[party - 1] + cr;

    elgl->serialize_sendall(cr);

    for(int i = 1; i <= num_party; i++) {
        if(i != party) {
            Ciphertext cr_i;
            elgl->deserialize_recv(cr_i, i);
            count += vec_cx[i - 1] + cr_i;
        }
    }

    Fr u;
    u = threshold_decrypt_easy<MultiIOBase>(count, elgl, lvt->global_pk, lvt->user_pk, io, pool, party, num_party, P_to_m);
    // std::cout << "u: " << u.getStr() << std::endl;
    uint64_t uu; uu = u.getUint64();
    uu = uu % fd;
    // std::cout << "uu: " << to_string(uu) << std::endl;

    uint64_t u_int;
    SPDZ2k<MultiIOBase>::LabeledShare shared_u;
    shared_u = spdz2k.add(shared_x, shared_r);
    u_int = spdz2k.reconstruct(shared_u);
    // std::cout << "u_int: " << to_string(u_int) << std::endl;

    if (uu != u_int) {
        cout << "uu: " << to_string(uu) << endl;
        cout << "u_int: " << to_string(u_int) << endl;
        throw std::runtime_error("L2A_mascot check failed: decrypted value != share sum");
    }

    auto t2 = std::chrono::high_resolution_clock::now();
    int bytes_end = io->get_total_bytes_sent();
    double comm_kb = double(bytes_end - bytes_start) / 1024.0;
    double time_ms = std::chrono::duration<double, std::milli>(t2 - t1).count();
    std::cout << std::fixed << std::setprecision(3)
              << "Communication: " << comm_kb << " KB, "
              << "Time: " << time_ms << " ms" << std::endl;

    return shared_x;
}


inline SPDZ2k<MultiIOBase>::LabeledShare L2A_for_B2A(
    ELGL<MultiIOBase>* elgl,
    LVT<MultiIOBase>* lvt,
    SPDZ2k<MultiIOBase>& spdz2k,
    int party,
    int num_party,
    MultiIO* io,
    ThreadPool* pool,
    const Plaintext& x_plain,
    const vector<Ciphertext>& vec_cx,
    const uint64_t& fd,
    map<std::string, Fr>& P_to_m
) {
    SPDZ2k<MultiIOBase>::LabeledShare shared_x;
    // int bytes_start = io->get_total_bytes_sent();
    // auto t1 = std::chrono::high_resolution_clock::now();

    uint64_t r_spdz2k = spdz2k.rng() % fd;
    SPDZ2k<MultiIOBase>::LabeledShare shared_r;
    shared_r = spdz2k.distributed_share(r_spdz2k);
    shared_x = spdz2k.distributed_share(x_plain.get_message().getUint64());

    Plaintext r;
    r.assign(to_string(r_spdz2k));

    Ciphertext cr, count;

    cr = lvt->global_pk.encrypt(r);
    count = vec_cx[party - 1] + cr;

    elgl->serialize_sendall(cr);

    for(int i = 1; i <= num_party; i++) {
        if(i != party) {
            Ciphertext cr_i;
            elgl->deserialize_recv(cr_i, i);
            count += vec_cx[i - 1] + cr_i;
        }
    }

    Fr u;
    u = threshold_decrypt_easy<MultiIOBase>(count, elgl, lvt->global_pk, lvt->user_pk, io, pool, party, num_party, P_to_m);
    // std::cout << "u: " << u.getStr() << std::endl;
    uint64_t uu; uu = u.getUint64();
    uu = uu % 2;
    // std::cout << "uu: " << to_string(uu) << std::endl;

    uint64_t u_int;
    SPDZ2k<MultiIOBase>::LabeledShare shared_u;
    shared_u = spdz2k.add(shared_x, shared_r);
    u_int = spdz2k.reconstruct(shared_u);
    u_int = u_int % 2;
    // std::cout << "u_int: " << to_string(u_int) << std::endl;

    if (uu != u_int) {
        cout << "uu: " << to_string(uu) << endl;
        cout << "u_int: " << to_string(u_int) << endl;
        throw std::runtime_error("L2A_mascot check failed: decrypted value != share sum");
    }

    // auto t2 = std::chrono::high_resolution_clock::now();
    // int bytes_end = io->get_total_bytes_sent();
    // double comm_kb = double(bytes_end - bytes_start) / 1024.0;
    // double time_ms = std::chrono::duration<double, std::milli>(t2 - t1).count();
    // std::cout << std::fixed << std::setprecision(3)
    //           << "Communication: " << comm_kb << " KB, "
    //           << "Time: " << time_ms << " ms" << std::endl;

    return shared_x;
}

} 