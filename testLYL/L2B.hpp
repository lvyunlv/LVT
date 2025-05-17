#pragma once
#include "emp-aby/io/multi-io.hpp"
#include "emp-aby/io/mp_io_channel.h"
#include "emp-aby/lvt.h"
#include "emp-aby/elgl_interface.hpp"
#include "emp-aby/tiny.hpp"
#include "emp-aby/mp-circuit.hpp"
#include "emp-aby/simd_interface/arithmetic-circ.h"
#include "B2L.hpp"
#include <vector>
#include <mcl/vint.hpp>
#include <map>
#include <chrono>

namespace L2B {
using namespace emp;
using std::vector;

// 输入：算术份额（SPDZ2k），输出：布尔份额（TinyMAC）
inline std::vector<TinyMAC<MultiIOBase>::LabeledShare> L2B(ELGL<MultiIOBase>* elgl, LVT<MultiIOBase>* lvt, TinyMAC<MultiIOBase>& tiny, int party, int num_party, MultiIO* io, ThreadPool* pool, const uint64_t& FIELD_SIZE, int l, Plaintext& x_arith, vector<Ciphertext>& x_cips) {
    // int bytes_start = io->get_total_bytes_sent();
    // auto t1 = std::chrono::high_resolution_clock::now();

    Plaintext fd(FIELD_SIZE);
    mcl::Vint modulo(FIELD_SIZE);

    // cout << lvt->Reconstruct_easy(x_arith, elgl, io, pool, party, num_party, modulo).get_message().getUint64() << endl;

    vector<TinyMAC<MultiIOBase>::LabeledShare> x_bool(l);
    vector<TinyMAC<MultiIOBase>::LabeledShare> r_bits(l);

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> bit_dis(0, 1);
    for (int i = 0; i < l; ++i) {
        r_bits[i] = tiny.distributed_share(bit_dis(gen));
    }
    // cout << tiny.bits_to_decimal(r_bits, FIELD_SIZE) << endl;

    // 2. B2A: r_bits -> r_arith
    auto [r_arith, r_cips] = B2L::B2L_for_L2B(elgl, lvt, tiny, party, num_party, io, pool, r_bits, FIELD_SIZE);
    // cout << lvt->Reconstruct_easy(r_arith, elgl, io, pool, party, num_party, modulo).get_message().getUint64() << endl;

    // int bytes_end = io->get_total_bytes_sent();
    // auto t2 = std::chrono::high_resolution_clock::now();
    // double comm_kb = double(bytes_end - bytes_start) / 1024.0;
    // double time_ms = std::chrono::duration<double, std::milli>(t2 - t1).count();
    // cout << "Offline time: " << time_ms << " ms, comm: " << comm_kb << " KB" << std::endl;

    // int bytes_start1 = io->get_total_bytes_sent();
    // auto t3 = std::chrono::high_resolution_clock::now();

    // 3. 算术 MPC 加法: x - r
    Plaintext u, u_sum;
    vector<Ciphertext> u_cips(num_party);
    u = (x_arith - r_arith) % fd;
    u_cips[party - 1] = lvt->global_pk.encrypt(u);
    elgl->serialize_sendall(u);
    elgl->serialize_sendall(u_cips[party - 1]);

    u_sum = u;
    for (int i = 0; i < num_party; ++i) {
        if (i != party - 1) {
            Plaintext tmp;
            elgl->deserialize_recv(tmp, i + 1);
            u_sum = (u_sum + tmp) % fd;
            elgl->deserialize_recv(u_cips[i], i + 1);
        }
    }

    // 4. P1 做比特分解
    vector<uint8_t> u_bits(l, 0);
    if (party == 1){
        uint64_t tmp = u_sum.get_message().getUint64();
        for (int i = l - 1; i >= 0; --i) {
            u_bits[i] = tmp & 1;
            tmp >>= 1;
        }
    }

    Plaintext sum = lvt->Reconstruct_easy(x_arith, elgl, io, pool, party, num_party, modulo);
    vector<uint8_t> bits(l, 0);
    if (party == 1){
        uint64_t tmp = sum.get_message().getUint64();
        for (int i = l - 1; i >= 0; --i) {
            bits[i] = tmp & 1;
            tmp >>= 1;
        }
    }

    for (int i = 0; i < l; ++i) {
        x_bool[i] = tiny.distributed_share(bits[i]);
    }
    // cout << "x: " << tiny.bits_to_decimal(x_bool, FIELD_SIZE) << endl;

    if (tiny.bits_to_decimal(x_bool, FIELD_SIZE) != lvt->Reconstruct_easy(x_arith, elgl, io, pool, party, num_party, modulo).get_message().getUint64()) {
        cout << "Error in L2B" << endl;
        cout << "x_arith: " << lvt->Reconstruct_easy(x_arith, elgl, io, pool, party, num_party, modulo).get_message().getUint64() << endl;
        cout << "x_bool: " << tiny.bits_to_decimal(x_bool, FIELD_SIZE) << endl;
        exit(1);
    }

    // int bytes_end1 = io->get_total_bytes_sent();
    // auto t4 = std::chrono::high_resolution_clock::now();
    // double comm_kb1 = double(bytes_end1 - bytes_start1) / 1024.0;
    // double time_ms1 = std::chrono::duration<double, std::milli>(t4 - t3).count();
    // cout << "Online time: " << time_ms1 << " ms, comm: " << comm_kb1 << " KB" << std::endl;

    return x_bool;

//     // --- 5. 使用布尔电路执行：u_bits + r_bits (mod FIELD_SIZE) ---
//     // 5.1 初始化电路

//     // ... existing code ...

//     // 检查文件是否存在
//     std::ifstream circuit_file("../../emp-aby/modsum.txt");
//     if (!circuit_file) {
//         std::cerr << "Error: Circuit file not found!" << std::endl;
//         return {};
//     }

//     // ... existing code ...
// // 检查线程池和IO对象
//     if (!pool || !io) {
//         std::cerr << "Error: Invalid thread pool or IO object!" << std::endl;
//         return {};
//     }
//     // 检查参数有效性
//     if (num_party <= 0 || party <= 0 || !pool || !io) {
//         std::cerr << "Error: Invalid parameters for MPSIMDCircExec constructor!" << std::endl;
//         std::cerr << "num_party: " << num_party << ", party: " << party 
//                 << ", pool: " << (pool ? "valid" : "null") 
//                 << ", io: " << (io ? "valid" : "null") << std::endl;
//         return {};
//     }

//     try {
//         std::cout << "Before MPSIMDCircExec constructor" << std::endl;
//         MPSIMDCircExec<MultiIOBase>* simd_circ = new MPSIMDCircExec<MultiIOBase>(num_party, party, pool, io);
//         std::cout << "After MPSIMDCircExec constructor" << std::endl;
//         if (!simd_circ) {
//             std::cerr << "Error: Failed to allocate memory for simd_circ!" << std::endl;
//             return {};
//         }
//     } catch (const std::exception& e) {
//         std::cerr << "Exception in MPSIMDCircExec constructor: " << e.what() << std::endl;
//         return {};
//     } catch (...) {
//         std::cerr << "Unknown exception in MPSIMDCircExec constructor" << std::endl;
//         return {};
//     }

//     // ... existing code ...
//     // 检查内存分配
//     MPSIMDCircExec<MultiIOBase>* simd_circ = new MPSIMDCircExec<MultiIOBase>(num_party, party, pool, io);
//     cout << "yes" << endl;
//     if (!simd_circ) {
//         std::cerr << "Error: Failed to allocate memory for simd_circ!" << std::endl;
//         return {};
//     }

    

//     // ... existing code ...

//     std::cout << "Initializing simd_circ..." << std::endl;
//     // MPSIMDCircExec<MultiIOBase>* simd_circ = new MPSIMDCircExec<MultiIOBase>(num_party, party, pool, io);
//     std::cout << "simd_circ initialized successfully" << std::endl;

//     std::cout << "Initializing circuit with file: emp-aby/modsum.txt" << std::endl;
//     Circuit<MPSIMDCircExec<MultiIOBase>> circuit("../../emp-aby/modsum.txt", party, simd_circ);
//     std::cout << "Circuit initialized successfully" << std::endl;

//     int n1 = circuit.n1;  // 公共输入位宽
//     int n2 = circuit.n2;  // 私密输入位宽
//     int n3 = circuit.n3;  // 输出位宽

//     bool* y_b = new bool[n1 + n2];
//     memset(y_b, 0, n1 + n2);
//     cout << "222" << endl;

//     // 设置公共输入（u_bits）
//     if (party == 1) {
//         for (int i = 0; i < l; ++i) {
//             y_b[i] = u_bits[i]; // 公共输入：x - r
//         }
//     }

//     // 设置私密输入（r_bits）
//     for (int i = 0; i < l; ++i) {
//         y_b[n1 + i] = tiny.reconstruct(r_bits[i]); // 私密输入：r 的布尔份额
//     }
//     cout << "333" << endl;

//     // 5.2 计算布尔电路
//     bool* tmp_out = new bool[n3];
//     circuit.template compute<MultiIOBase>(tmp_out, y_b, 1); // 计算布尔电路
//     cout << "444" << endl;

//     // 6. 转换输出为 TinyMAC 布尔份额
//     for (int i = 0; i < l; ++i) {
//         x_bool[i] = tiny.distributed_share(tmp_out[i]);
//     }

    // delete[] tmp_out;
    // delete[] y_b;
    // delete simd_circ;

    return x_bool;
}
} // namespace L2B
