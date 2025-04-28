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

namespace A2L_mascot {
using namespace emp;
using std::vector;
using std::tuple;
using std::map;

inline tuple<Plaintext, vector<Ciphertext>> A2L(
    ELGL<MultiIOBase>* elgl,
    LVT<MultiIOBase>* lvt,
    MASCOT<MultiIOBase>& mascot,
    int party,
    int num_party,
    MultiIO* io,
    ThreadPool* pool,
    const MASCOT<MultiIOBase>::LabeledShare& shared_x,
    const mcl::Vint& fd
) {
    Plaintext x;
    vector<Ciphertext> vec_cx(num_party);

    // int bytes_start = io->get_total_bytes_sent();
    // auto t1 = std::chrono::high_resolution_clock::now();

    mcl::Vint r_mascot; r_mascot.setRand(fd);
    MASCOT<MultiIOBase>::LabeledShare shared_r = mascot.distributed_share(r_mascot);

    mcl::Vint xval = shared_x.value; xval %= fd; if (xval < 0) xval += fd;
    // cout << "xval: " << xval << endl;
    mcl::Vint rval = shared_r.value; rval %= fd; if (rval < 0) rval += fd;
    // cout << "rval: " << rval << endl;
    Plaintext r;
    // cout << xval.getStr() << endl;
    x.assign(xval.getStr());
    r.assign(rval.getStr());
    // cout << "x: " << x.get_message().getStr() << endl;

    Ciphertext cx, cr, count;
    cx = lvt->global_pk.encrypt(x);
    cr = lvt->global_pk.encrypt(r);
    count = cx + cr;
    vec_cx[party - 1] = cx;

    elgl->serialize_sendall(cx);
    elgl->serialize_sendall(cr);

    for(int i = 1; i <= num_party; i++) {
        if(i != party) {
            Ciphertext cx_i, cr_i;
            elgl->deserialize_recv(cx_i, i);
            elgl->deserialize_recv(cr_i, i);
            count += cx_i + cr_i;
            vec_cx[i - 1] = cx_i;
        }
    }

    Fr u = threshold_decrypt_easy<MultiIOBase>(count, elgl, lvt->global_pk, lvt->user_pk, io, pool, party, num_party, lvt->P_to_m, lvt);
    mcl::Vint uu(u.getStr());
    uu %= fd; if (uu < 0) uu += fd;

    MASCOT<MultiIOBase>::LabeledShare shared_u = mascot.add(shared_x, shared_r);
    mcl::Vint u_int = mascot.reconstruct(shared_u);
    u_int %= fd; if (u_int < 0) u_int += fd;

    // if (uu != u_int) {
    //     cout << "解密uu: " << uu << endl;
    //     cout << "MASCOT 重构 u_int: " << u_int << endl;
    //     cout << "shared_x: " << xval << endl;
    //     cout << "x: " << x.get_message() << endl;
    // }

    if (uu != u_int) {
        throw std::runtime_error("A2L_spdz2k check failed: decrypted value != share sum");
    }

    // std::cout << "u: " << u.getStr() << std::endl;
    // std::cout << "uu: " << uu.getStr() << std::endl;
    // std::cout << "u_int: " << u_int.getStr() << std::endl;

    // auto t2 = std::chrono::high_resolution_clock::now();
    // int bytes_end = io->get_total_bytes_sent();
    // double comm_kb = double(bytes_end - bytes_start) / 1024.0;
    // double time_ms = std::chrono::duration<double, std::milli>(t2 - t1).count();
    // std::cout << std::fixed << std::setprecision(3)
    //           << "Communication: " << comm_kb << " KB, "
    //           << "Time: " << time_ms << " ms" << std::endl;

    return std::make_tuple(x, vec_cx);
}

} // namespace A2L_mascot