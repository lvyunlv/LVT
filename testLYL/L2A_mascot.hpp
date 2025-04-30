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
    const mcl::Vint& fd,
    double& online_time,
    double& online_comm
) {
    MASCOT<MultiIOBase>::LabeledShare shared_x;
    Fr fd_fr; 
    fd_fr.setStr(fd.getStr());
    BLS12381Element G_fd(fd_fr);

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
    elgl->serialize_sendall(cr);

    vector<Ciphertext> vec_cr(num_party);
    vec_cr[party - 1] = cr;
    for(int i = 1; i <= num_party; i++) {
        if(i != party) {
            Ciphertext cr_i;
            elgl->deserialize_recv(cr_i, i);
            vec_cr[i - 1] = cr_i;
        }
    }

    count = cr;
    for(int i = 1; i <= num_party; i++) {
        if(i != party) {
            count += vec_cr[i - 1];
        }
    }

    int bytes_start = io->get_total_bytes_sent();
    auto t1 = std::chrono::high_resolution_clock::now();

    count += vec_cx[party - 1];
    for(int i = 1; i <= num_party; i++) {
        if(i != party) {
            count += vec_cx[i - 1];
        }
    }

    BLS12381Element u = threshold_decrypt_easy<MultiIOBase>(count, elgl, lvt->global_pk, lvt->user_pk, io, pool, party, num_party, lvt->P_to_m, lvt);
    mcl::Vint u_int;
    MASCOT<MultiIOBase>::LabeledShare shared_u;
    shared_u = mascot.add(shared_x, shared_r);
    u_int = mascot.reconstruct(shared_u);
    u_int %= fd; if (u_int < 0) u_int += fd;

    Fr u_int_fr; 
    u_int_fr.setStr(u_int.getStr());
    BLS12381Element uu(u_int_fr);
    
    auto t2 = std::chrono::high_resolution_clock::now();
    int bytes_end = io->get_total_bytes_sent();
    double comm_kb = double(bytes_end - bytes_start) / 1024.0;
    double time_ms = std::chrono::duration<double, std::milli>(t2 - t1).count();
    std::cout << std::fixed << std::setprecision(3)
              << "Communication: " << comm_kb << " KB, "
              << "Time: " << time_ms << " ms" << std::endl;

    online_time = time_ms;
    online_comm = comm_kb;

    BLS12381Element tmp = G_fd;
    for (int i = 0; i <= num_party * 2; i++) {
        if (uu != tmp) {
            return shared_x;
        }
        tmp += G_fd;
    }
    throw std::runtime_error("A2L_spdz2k check failed: decrypted value != share sum");

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
    Fr fd_fr; 
    fd_fr.setStr(fd.getStr());
    BLS12381Element G_fd(fd_fr);

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
    elgl->serialize_sendall(cr);

    vector<Ciphertext> vec_cr(num_party);
    vec_cr[party - 1] = cr;
    for(int i = 1; i <= num_party; i++) {
        if(i != party) {
            Ciphertext cr_i;
            elgl->deserialize_recv(cr_i, i);
            vec_cr[i - 1] = cr_i;
        }
    }
    count = cr;
    for(int i = 1; i <= num_party; i++) {
        if(i != party) {
            count += vec_cr[i - 1];
        }
    }

    count += vec_cx[party - 1];
    for(int i = 1; i <= num_party; i++) {
        if(i != party) {
            count += vec_cx[i - 1];
        }
    }
    
    BLS12381Element u = threshold_decrypt_easy<MultiIOBase>(count, elgl, lvt->global_pk, lvt->user_pk, io, pool, party, num_party, lvt->P_to_m, lvt);
    mcl::Vint u_int;
    MASCOT<MultiIOBase>::LabeledShare shared_u;
    shared_u = mascot.add(shared_x, shared_r);
    u_int = mascot.reconstruct(shared_u);
    u_int %= fd; if (u_int < 0) u_int += fd;

    Fr u_int_fr; 
    u_int_fr.setStr(u_int.getStr());
    BLS12381Element uu(u_int_fr);

    BLS12381Element tmp = G_fd;
    BLS12381Element uu1 = uu - BLS12381Element(2);
    BLS12381Element uu2 = uu + BLS12381Element(2);
    for (int i = 0; i <= num_party * 2; i++) {
        if (uu != tmp && uu1 != tmp && uu2 != tmp) {
            return shared_x;
        }
        tmp += G_fd;
        uu1 += G_fd;
        uu2 += G_fd;
    }
    throw std::runtime_error("A2L_spdz2k check failed: decrypted value != share sum");
}

} // namespace L2A_mascot