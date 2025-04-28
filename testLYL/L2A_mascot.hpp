#pragma once
#include "emp-aby/io/multi-io.hpp"
#include "emp-aby/io/mp_io_channel.h"
#include "emp-aby/lvt.h"
#include "emp-aby/elgl_interface.hpp"
#include "emp-aby/mascot.hpp"
#include <vector>
#include <tuple>
#include <mcl/vint.hpp>
#include <map>
#include <iostream>
#include <iomanip>
#include <chrono>

namespace L2A_mascot {
using namespace emp;
using std::vector;
using std::tuple;
using std::map;

inline MASCOT<MultiIOBase>::LabeledShare L2A(
    ELGL<MultiIOBase>* elgl,
    LVT<MultiIOBase>* lvt,
    MASCOT<MultiIOBase>& mascot,
    int party,
    int num_party,
    MultiIO* io,
    ThreadPool* pool,
    const Plaintext& x_plain,
    const vector<Ciphertext>& vec_cx,
    const mcl::Vint& fd
) {
    MASCOT<MultiIOBase>::LabeledShare shared_x;

    // int bytes_start = io->get_total_bytes_sent();
    // auto t1 = std::chrono::high_resolution_clock::now();

    mcl::Vint r_mascot; 
    r_mascot.setRand(fd);
    r_mascot %= fd; if (r_mascot < 0) r_mascot += fd;
    MASCOT<MultiIOBase>::LabeledShare shared_r;
    shared_r = mascot.distributed_share(r_mascot);
    mcl::Vint x_mascot;
    Fr s = x_plain.get_message();
    x_mascot.setStr(s.getStr());
    x_mascot %= fd; if (x_mascot < 0) x_mascot += fd;
    shared_x = mascot.distributed_share(x_mascot);

    Plaintext r;
    r.assign(r_mascot.getStr());

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

    Fr u = threshold_decrypt_easy<MultiIOBase>(count, elgl, lvt->global_pk, lvt->user_pk, io, pool, party, num_party, lvt->P_to_m, lvt);
    mcl::Vint uu(u.getStr());
    uu %= fd; if (uu < 0) uu += fd;
    // std::cout << "uu: " << to_string(uu) << std::endl;

    mcl::Vint u_int;
    MASCOT<MultiIOBase>::LabeledShare shared_u;
    shared_u = mascot.add(shared_x, shared_r);
    u_int = mascot.reconstruct(shared_u);
    u_int %= fd; if (u_int < 0) u_int += fd;

    if (uu != u_int) {
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


inline MASCOT<MultiIOBase>::LabeledShare L2A_for_B2A(
    ELGL<MultiIOBase>* elgl,
    LVT<MultiIOBase>* lvt,
    MASCOT<MultiIOBase>& mascot,
    int party,
    int num_party,
    MultiIO* io,
    ThreadPool* pool,
    const Plaintext& x_plain,
    const vector<Ciphertext>& vec_cx,
    const mcl::Vint& fd
) {
    MASCOT<MultiIOBase>::LabeledShare shared_x;

    // int bytes_start = io->get_total_bytes_sent();
    // auto t1 = std::chrono::high_resolution_clock::now();

    mcl::Vint r_mascot; 
    r_mascot.setRand(fd);
    r_mascot %= fd; if (r_mascot < 0) r_mascot += fd;
    MASCOT<MultiIOBase>::LabeledShare shared_r;
    shared_r = mascot.distributed_share(r_mascot);
    mcl::Vint x_mascot;
    Fr s = x_plain.get_message();
    x_mascot.setStr(s.getStr());
    x_mascot %= fd; if (x_mascot < 0) x_mascot += fd;
    shared_x = mascot.distributed_share(x_mascot);

    Plaintext r;
    r.assign(r_mascot.getStr());

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

    Fr u = threshold_decrypt_easy<MultiIOBase>(count, elgl, lvt->global_pk, lvt->user_pk, io, pool, party, num_party, lvt->P_to_m, lvt);
    mcl::Vint uu(u.getStr());
    uu %= fd; if (uu < 0) uu += fd;
    // std::cout << "uu: " << to_string(uu) << std::endl;

    mcl::Vint u_int;
    MASCOT<MultiIOBase>::LabeledShare shared_u;
    shared_u = mascot.add(shared_x, shared_r);
    u_int = mascot.reconstruct(shared_u);
    u_int %= fd; if (u_int < 0) u_int += fd;

    if ((uu % 2) != (u_int % 2)) {
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

} // namespace L2A_mascot