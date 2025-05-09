#pragma once
#include "emp-aby/io/mp_io_channel.h"
#include "emp-aby/spdz2k.hpp"
#include "emp-aby/elgl_interface.hpp"
#include "emp-aby/lvt.h"
#include "emp-aby/io/multi-io.hpp"
#include "testLYL/A2L_spdz2k.hpp"
#include "testLYL/L2A_spdz2k.hpp"
#include "FixedPointConverter.h"

#include <vector>
#include <cassert>
#include <initializer_list>
#include <iostream>
#include <thread>
#include <mcl/vint.hpp>
#include <random>
#include <sstream>

const int f = 16;
const int FixedPoint_bits = 24;
const int FixedPoint_SIZE = 1ULL << 24;
namespace emp {

enum class ShareType {
    SPDZ2k,
    LUT
};

// 声明全局 LVT 实例
namespace LVTInstances {
    static LVT<MultiIOBase>* lvt_relu = nullptr;
    static LVT<MultiIOBase>* lvt_gelu = nullptr;
    static LVT<MultiIOBase>* lvt_softmax = nullptr;
    static LVT<MultiIOBase>* lvt_div = nullptr;
    static LVT<MultiIOBase>* lvt_sqrt = nullptr;

    // 初始化所有 LVT 实例
    static void initialize(int num_party, int party, MPIOChannel<MultiIOBase>* io, ThreadPool* pool, ELGL<MultiIOBase>* elgl, 
                         Fr& alpha_fr, int num) {
        if (lvt_relu == nullptr) {
            lvt_relu = new LVT<MultiIOBase>(num_party, party, io, pool, elgl, 
                                          "../../build/bin/table_relu.txt", alpha_fr, num, FixedPoint_bits);
            lvt_relu->generate_shares_fake(lvt_relu->lut_share, lvt_relu->rotation, lvt_relu->table);
        }
        
        if (lvt_gelu == nullptr) {
            lvt_gelu = new LVT<MultiIOBase>(num_party, party, io, pool, elgl, 
                                          "../../build/bin/table_gelu.txt", alpha_fr, num, FixedPoint_bits);
            lvt_gelu->generate_shares_fake(lvt_gelu->lut_share, lvt_gelu->rotation, lvt_gelu->table);
        }
        
        if (lvt_softmax == nullptr) {
            lvt_softmax = new LVT<MultiIOBase>(num_party, party, io, pool, elgl, 
                                             "../../build/bin/table_softmax.txt", alpha_fr, num, FixedPoint_bits);
            lvt_softmax->generate_shares_fake(lvt_softmax->lut_share, lvt_softmax->rotation, lvt_softmax->table);
        }
        
        if (lvt_div == nullptr) {
            lvt_div = new LVT<MultiIOBase>(num_party, party, io, pool, elgl, 
                                         "../../build/bin/table_div.txt", alpha_fr, num, FixedPoint_bits);
            lvt_div->generate_shares_fake(lvt_div->lut_share, lvt_div->rotation, lvt_div->table);
        }
        
        if (lvt_sqrt == nullptr) {
            lvt_sqrt = new LVT<MultiIOBase>(num_party, party, io, pool, elgl, 
                                          "../../build/bin/table_sqrt.txt", alpha_fr, num, FixedPoint_bits);
            lvt_sqrt->generate_shares_fake(lvt_sqrt->lut_share, lvt_sqrt->rotation, lvt_sqrt->table);
        }
    }

    // 清理所有 LVT 实例
    static void cleanup() {
        delete lvt_relu;
        delete lvt_gelu;
        delete lvt_softmax;
        delete lvt_div;
        delete lvt_sqrt;
        
        lvt_relu = nullptr;
        lvt_gelu = nullptr;
        lvt_softmax = nullptr;
        lvt_div = nullptr;
        lvt_sqrt = nullptr;
    }
}

template<typename IO = MultiIOBase>
class SecretTensor {
public:
    using Share = typename SPDZ2k<IO>::LabeledShare;

    // 构造函数
    SecretTensor(const std::vector<size_t>& shape, SPDZ2k<MultiIOBase>& spdz2k, ELGL<MultiIOBase>* elgl, LVT<MultiIOBase>* lvt, MPIOChannel<MultiIOBase>* io, ThreadPool* pool, int party, int num_party, const uint64_t& fd, ShareType type = ShareType::SPDZ2k) : shape(shape), spdz2k(spdz2k), elgl(elgl), lvt(lvt), io(io), pool(pool), party(party), num_party(num_party), fd(fd), type(type) {
        total_size = 1;
        for (auto dim : shape) total_size *= dim;

        if (type == ShareType::SPDZ2k) {
            data_spdz2k.resize(total_size);
        } else {
            data_lut_plain.resize(total_size);
            data_lut_cipher.resize(total_size);
        }
    }

    // 从明文初始化
    static SecretTensor from_plaintext(const std::vector<size_t>& shape, const std::vector<uint64_t>& values, SPDZ2k<MultiIOBase>& spdz2k, ELGL<MultiIOBase>* elgl, LVT<MultiIOBase>* lvt, MPIOChannel<MultiIOBase>* io, ThreadPool* pool, int party, int num_party, const uint64_t& fd, ShareType type = ShareType::SPDZ2k)
    {
        assert(values.size() == product(shape));

        SecretTensor tensor(shape, spdz2k, elgl, lvt, io, pool, party, num_party, fd, type);

        if (type == ShareType::SPDZ2k) {
            for (size_t i = 0; i < values.size(); ++i) {
                tensor.data_spdz2k[i] = spdz2k.distributed_share(values[i]);
            }
        } else {
            for (size_t i = 0; i < values.size(); ++i) {
                auto [plain, cipher] = A2L_spdz2k::A2L(elgl, lvt, spdz2k, party, num_party, static_cast<MultiIO*>(io), pool,
                                                       spdz2k.distributed_share(values[i]), fd,
                                                       tensor.time_dummy, tensor.comm_dummy);
                tensor.data_lut_plain[i] = plain;
                tensor.data_lut_cipher[i] = cipher;
            }
        }

        return tensor;
    }

    // 向量加法 - 使用安全的MPC加法
    SecretTensor add(const SecretTensor& other) const {
        assert(type == ShareType::SPDZ2k && other.type == ShareType::SPDZ2k);
        assert(shape == other.shape);

        SecretTensor result(shape, spdz2k, elgl, lvt, io, pool, party, num_party, fd);
        
        // 直接进行加法，不使用线程池
        for (size_t i = 0; i < total_size; ++i) {
            result.data_spdz2k[i] = spdz2k.add(data_spdz2k[i], other.data_spdz2k[i]);
        }

        return result;
    }

    // 矩阵乘法 - 使用安全的MPC乘法和截断
    SecretTensor matmul(const SecretTensor& other) const {
        assert(type == ShareType::SPDZ2k && other.type == ShareType::SPDZ2k);
        assert(shape.size() == 2 && other.shape.size() == 2);
        assert(shape[1] == other.shape[0]);

        size_t m = shape[0], k = shape[1], n = other.shape[1];
        std::vector<size_t> result_shape = {m, n};
        SecretTensor result(result_shape, spdz2k, elgl, lvt, io, pool, party, num_party, fd);

        // 对每个结果元素进行多方乘法
        // TODO: 多线程
        for (size_t i = 0; i < m; ++i) {
            for (size_t j = 0; j < n; ++j) {
                Share acc = spdz2k.get_zero_share();
                for (size_t p = 0; p < k; ++p) {
                    size_t a_idx = i * k + p;
                    size_t b_idx = p * n + j;
                    Share prod = spdz2k.multiply_with_trunc(data_spdz2k[a_idx], other.data_spdz2k[b_idx], f);
                    acc = spdz2k.add(acc, prod);
                }
                result.data_spdz2k[i * n + j] = acc;
            }
        }

        return result;
    }

    // 转换 SPDZ2k → LUT
    void to_lut() {
        assert(type == ShareType::SPDZ2k);
        data_lut_plain.resize(total_size);
        data_lut_cipher.resize(total_size);

        for (size_t i = 0; i < total_size; ++i) {
            auto [plain, cipher] = A2L_spdz2k::A2L(elgl, lvt, spdz2k, party, num_party, static_cast<MultiIO*>(io), pool, data_spdz2k[i], fd, time_dummy, comm_dummy);
            data_lut_plain[i] = plain;
            data_lut_cipher[i] = cipher;
        }

        data_spdz2k.clear();
        type = ShareType::LUT;
    }

    // 转换 LUT → SPDZ2k
    void to_spdz2k() {
        assert(type == ShareType::LUT);
        data_spdz2k.resize(total_size);

        for (size_t i = 0; i < total_size; ++i) {
            data_spdz2k[i] = L2A_spdz2k::L2A(elgl, lvt, spdz2k, party, num_party, static_cast<MultiIO*>(io), pool, data_lut_plain[i], data_lut_cipher[i], fd, time_dummy, comm_dummy);
        }

        data_lut_plain.clear();
        data_lut_cipher.clear();
        type = ShareType::SPDZ2k;
    }

    // 获取总尺寸
    size_t size() const { return total_size; }

    // 非线性函数计算
    void lookup_online(Plaintext& out, Plaintext& x_share, const Ciphertext& x_cipher, 
                      const std::vector<Ciphertext>& x_ciphers, LVT<MultiIOBase>* lvt_instance) const {
        lvt_instance->lookup_online(out, x_share, const_cast<Ciphertext&>(x_cipher), 
                                  const_cast<std::vector<Ciphertext>&>(x_ciphers));
    }

    // ReLU激活函数
    SecretTensor relu() const {
        assert(type == ShareType::SPDZ2k);
        
        // 1. 转换为LUT share
        SecretTensor lut_tensor = *this;
        lut_tensor.to_lut();
        
        // 2. 使用LVT计算ReLU
        for (size_t i = 0; i < total_size; ++i) {
            Plaintext out, x_share;
            lookup_online(out, x_share, lut_tensor.data_lut_cipher[i][0], 
                         lut_tensor.data_lut_cipher[i], LVTInstances::lvt_relu);
            lut_tensor.data_lut_plain[i] = out;
        }
        
        return lut_tensor;
    }

    // GELU激活函数
    SecretTensor gelu() const {
        assert(type == ShareType::SPDZ2k);
        
        // 1. 转换为LUT share
        SecretTensor lut_tensor = *this;
        lut_tensor.to_lut();
        
        // 2. 使用LVT计算GELU
        for (size_t i = 0; i < total_size; ++i) {
            Plaintext out, x_share;
            lookup_online(out, x_share, lut_tensor.data_lut_cipher[i][0], 
                         lut_tensor.data_lut_cipher[i], LVTInstances::lvt_gelu);
            lut_tensor.data_lut_plain[i] = out;
        }
        
        return lut_tensor;
    }

    // Softmax函数
    SecretTensor softmax() const {
        assert(type == ShareType::SPDZ2k);
        
        // 1. 转换为LUT share
        SecretTensor lut_tensor = *this;
        lut_tensor.to_lut();
        
        // 2. 使用LVT计算softmax
        for (size_t i = 0; i < total_size; ++i) {
            Plaintext out, x_share;
            lookup_online(out, x_share, lut_tensor.data_lut_cipher[i][0], 
                         lut_tensor.data_lut_cipher[i], LVTInstances::lvt_softmax);
            lut_tensor.data_lut_plain[i] = out;
        }
        
        return lut_tensor;
    }

    // 除法
    SecretTensor div(const SecretTensor& other) const {
        assert(type == ShareType::SPDZ2k && other.type == ShareType::SPDZ2k);
        assert(shape == other.shape);
        
        // 1. 转换为LUT share
        SecretTensor lut_tensor = *this;
        SecretTensor other_lut = other;
        lut_tensor.to_lut();
        other_lut.to_lut();
        
        // 2. 使用LVT计算除法
        for (size_t i = 0; i < total_size; ++i) {
            Plaintext out, x_share;
            lookup_online(out, x_share, lut_tensor.data_lut_cipher[i][0], 
                         lut_tensor.data_lut_cipher[i], LVTInstances::lvt_div);
            lut_tensor.data_lut_plain[i] = out;
        }
        
        return lut_tensor;
    }

    // 平方根
    SecretTensor sqrt() const {
        assert(type == ShareType::SPDZ2k);
        
        // 1. 转换为LUT share
        SecretTensor lut_tensor = *this;
        lut_tensor.to_lut();
        
        // 2. 使用LVT计算平方根
        for (size_t i = 0; i < total_size; ++i) {
            Plaintext out, x_share;
            lookup_online(out, x_share, lut_tensor.data_lut_cipher[i][0], 
                         lut_tensor.data_lut_cipher[i], LVTInstances::lvt_sqrt);
            lut_tensor.data_lut_plain[i] = out;
        }
        
        return lut_tensor;
    }

private:
    static size_t product(const std::vector<size_t>& shape) {
        size_t p = 1;
        for (auto s : shape) p *= s;
        return p;
    }

public:
    std::vector<size_t> shape;
    ShareType type;

    // spdz2k share
    std::vector<Share> data_spdz2k;

    // LUT share
    std::vector<Plaintext> data_lut_plain;
    std::vector<std::vector<Ciphertext>> data_lut_cipher;

    // MPC 环境依赖
    SPDZ2k<IO>& spdz2k;
    ELGL<IO>* elgl;
    LVT<IO>* lvt;
    MPIOChannel<IO>* io;
    ThreadPool* pool;
    int party;
    int num_party;
    uint64_t fd;

    // Dummy 测试数据
    double time_dummy = 0.0;
    double comm_dummy = 0.0;

private:
    size_t total_size;
};

} // namespace emp