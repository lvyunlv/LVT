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

namespace A2L_spdz2k {
using namespace emp;
using std::vector;
using std::tuple;
using std::map;

inline tuple<Plaintext, vector<Ciphertext>> A2L(
    ELGL<MultiIOBase>* elgl,
    LVT<MultiIOBase>* lvt,
    SPDZ2k<MultiIOBase>& spdz2k,
    int party,
    int num_party,
    MultiIO* io,
    ThreadPool* pool,
    const SPDZ2k<MultiIOBase>::LabeledShare& shared_x,
    uint64_t fd
) {
    // output 声明
    Plaintext x;
    vector<Ciphertext> vec_cx(num_party);

    // int bytes_start = io->get_total_bytes_sent();
    // auto t1 = std::chrono::high_resolution_clock::now();

    uint64_t r_spdz2k = spdz2k.rng() % fd; if (r_spdz2k < 0) r_spdz2k += fd;
    SPDZ2k<MultiIOBase>::LabeledShare shared_r;
    shared_r = spdz2k.distributed_share(r_spdz2k);
    // cout << "shared_x: " << shared_x.value << endl;
    // cout << "shared_r: " << shared_r.value << endl;

    uint64_t xval = shared_x.value % fd; if (xval < 0) xval += fd;
    uint64_t rval = shared_r.value % fd; if (rval < 0) rval += fd;
    Plaintext r;
    x.assign(std::to_string(xval));
    r.assign(std::to_string(rval));

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
    uint64_t uu = u.getUint64();
    uu %= fd;

    SPDZ2k<MultiIOBase>::LabeledShare shared_u;
    shared_u = spdz2k.add(shared_x, shared_r);
    uint64_t u_int = spdz2k.reconstruct(shared_u);
    u_int %= fd;

    // if (uu != u_int) {
    //     cout << "解密uu: " << uu << endl;
    //     cout << "MASCOT 重构 u_int: " << u_int << endl;
    //     cout << "shared_x: " << xval << endl;
    //     cout << "x: " << x.get_message() << endl;
    // }
    if (uu != u_int) {
        throw std::runtime_error("A2L_spdz2k check failed: decrypted value != share sum");
    }
    
    // 统计结束通信字节和时间
    // auto t2 = std::chrono::high_resolution_clock::now();
    // int bytes_end = io->get_total_bytes_sent();
    // double comm_kb = double(bytes_end - bytes_start) / 1024.0;
    // double time_ms = std::chrono::duration<double, std::milli>(t2 - t1).count();
    // std::cout << std::fixed << std::setprecision(3)
    //           << "Communication: " << comm_kb << " KB, "
    //           << "Time: " << time_ms << " ms" << std::endl;

    return std::make_tuple(x, vec_cx);
}

} // namespace A2L_spdz2k