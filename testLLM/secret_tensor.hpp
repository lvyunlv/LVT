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
    static LVT<MultiIOBase>* lvt_div = nullptr;
    static LVT<MultiIOBase>* lvt_sqrt = nullptr;
    static LVT<MultiIOBase>* lvt_pow = nullptr;
    static LVT<MultiIOBase>* lvt_exp = nullptr;
    static LVT<MultiIOBase>* lvt_log = nullptr;
    static LVT<MultiIOBase>* lvt_sigmoid = nullptr;
    static LVT<MultiIOBase>* lvt_tanh = nullptr;

    // 初始化所有 LVT 实例
    static void initialize(int num_party, int party, MPIOChannel<MultiIOBase>* io, ThreadPool* pool, ELGL<MultiIOBase>* elgl, Fr& alpha_fr, int num) {
        using LVTPtr = LVT<MultiIOBase>*;
        std::vector<std::tuple<std::string, std::string, LVTPtr*, std::string>> lvt_list = {
            {"relu",    "../../build/bin/table_relu.txt",    &lvt_relu,    "lvt_relu_instance.bin"},
            {"gelu",    "../../build/bin/table_gelu.txt",    &lvt_gelu,    ""},
            {"div",     "../../build/bin/table_div.txt",     &lvt_div,     ""},
            {"sqrt",    "../../build/bin/table_sqrt.txt",    &lvt_sqrt,    ""},
            {"pow",     "../../build/bin/table_pow.txt",     &lvt_pow,     ""},
            {"exp",     "../../build/bin/table_exp.txt",     &lvt_exp,     ""},
            {"log",     "../../build/bin/table_log.txt",     &lvt_log,     ""},
            {"sigmoid", "../../build/bin/table_sigmoid.txt", &lvt_sigmoid, ""},
            {"tanh",    "../../build/bin/table_tanh.txt",    &lvt_tanh,    ""}
        };

        for (const auto& [name, table_path, lvt_ptr_ref, instance_file] : lvt_list) {
            if (*lvt_ptr_ref != nullptr) continue;

            std::string instance_path = "../../build/cache/" + (instance_file.empty() ? ("lvt_" + name + "_instance.bin") : instance_file);
            std::string cache_path    = "../../build/cache/lvt_" + name + ".bin";

            // 若存在序列化 LVT 实例，优先加载
            if (std::filesystem::exists(instance_path)) {
                std::ifstream ifs(instance_path, std::ios::binary);
                if (ifs.is_open()) {
                    *lvt_ptr_ref = new LVT<MultiIOBase>();
                    ifs >> **lvt_ptr_ref;  // 假设你实现了 operator>> 重载
                    ifs.close();
                    std::cout << "Loaded " << name << " instance from file." << std::endl;
                    continue;
                }
            }

            // 创建新实例并初始化 LUT
            *lvt_ptr_ref = new LVT<MultiIOBase>(num_party, party, io, pool, elgl,
                                                table_path, alpha_fr, num, FixedPoint_bits);

            if (std::filesystem::exists(cache_path)) {
                (*lvt_ptr_ref)->load_from_file(cache_path);
            } else {
                (*lvt_ptr_ref)->generate_shares_fake((*lvt_ptr_ref)->lut_share,
                                                    (*lvt_ptr_ref)->rotation,
                                                    (*lvt_ptr_ref)->table);
                (*lvt_ptr_ref)->save_to_file(cache_path);
            }

            // 可选：保存实例
            std::ofstream ofs(instance_path, std::ios::binary);
            if (ofs.is_open()) {
                ofs << **lvt_ptr_ref;  // operator<< 重载
                ofs.close();
                std::cout << "Saved " << name << " instance to file." << std::endl;
            }

            std::cout << name << " done" << std::endl;
            (*lvt_ptr_ref)->DistKeyGen();
        }

    }

    // 清理所有 LVT 实例
    static void cleanup() {
        delete lvt_relu;      lvt_relu = nullptr;
        delete lvt_gelu;      lvt_gelu = nullptr;
        delete lvt_div;       lvt_div = nullptr;
        delete lvt_sqrt;      lvt_sqrt = nullptr;
        delete lvt_pow;       lvt_pow = nullptr;
        delete lvt_exp;       lvt_exp = nullptr;
        delete lvt_log;       lvt_log = nullptr;
        delete lvt_sigmoid;   lvt_sigmoid = nullptr;
        delete lvt_tanh;      lvt_tanh = nullptr;
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
                tensor.data_spdz2k[i] = spdz2k.distributed_share_(values[i]);
            }
        } else {
            for (size_t i = 0; i < values.size(); ++i) {
                auto [plain, cipher] = A2L_spdz2k::A2L(elgl, lvt, spdz2k, party, num_party, static_cast<MultiIO*>(io), pool, spdz2k.distributed_share_(values[i]), fd, tensor.time_dummy, tensor.comm_dummy);
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
    void lookup_online(Plaintext& out, std::vector<Ciphertext>& out_ciphers, Plaintext& x_share, const Ciphertext& x_cipher, const std::vector<Ciphertext>& x_ciphers, LVT<MultiIOBase>* lvt_instance) const {
        lvt_instance->lookup_online(out, out_ciphers, x_share, const_cast<Ciphertext&>(x_cipher), const_cast<std::vector<Ciphertext>&>(x_ciphers));
    }

    // ReLU激活函数
    SecretTensor relu() const {
        SecretTensor lut_tensor = *this;
        if (type == ShareType::SPDZ2k) {
            lut_tensor.to_lut();
        }
        // 2. 使用LVT计算ReLU
        for (size_t i = 0; i < total_size; ++i) {
            Plaintext out;
            vector<Ciphertext> out_ciphers;
            out_ciphers.resize(num_party);
            lookup_online(out, out_ciphers, lut_tensor.data_lut_plain[i], lut_tensor.data_lut_cipher[i][0], lut_tensor.data_lut_cipher[i], LVTInstances::lvt_relu);
            lut_tensor.data_lut_plain[i] = out;
            for (int j = 0; j < num_party; ++j) {
                lut_tensor.data_lut_cipher[i][j] = out_ciphers[j];
            }
        }  
        return lut_tensor;
    }

    // GELU激活函数
    SecretTensor gelu() const {
        SecretTensor lut_tensor = *this;
        if (type == ShareType::SPDZ2k) {
            // 1. 转换为LUT share
            lut_tensor.to_lut();
        }
        // 2. 使用LVT计算ReLU
        for (size_t i = 0; i < total_size; ++i) {
            Plaintext out;
            vector<Ciphertext> out_ciphers;
            out_ciphers.resize(num_party);
            lookup_online(out, out_ciphers, lut_tensor.data_lut_plain[i], lut_tensor.data_lut_cipher[i][0], lut_tensor.data_lut_cipher[i], LVTInstances::lvt_gelu);
            lut_tensor.data_lut_plain[i] = out;
            for (int j = 0; j < num_party; ++j) {
                lut_tensor.data_lut_cipher[i][j] = out_ciphers[j];
            }
        }  
        return lut_tensor;
    }

    // Softmax函数
    SecretTensor softmax() const {
        assert(type == ShareType::SPDZ2k);
        assert(shape.size() == 2); // 支持 (batch, dim) 输入

        size_t batch = shape[0];
        size_t dim = shape[1];
        std::vector<size_t> out_shape = {batch, dim};

        SecretTensor exp_tensor(out_shape, spdz2k, elgl, lvt, io, pool, party, num_party, fd, ShareType::LUT);
        exp_tensor.data_lut_plain.resize(total_size);
        exp_tensor.data_lut_cipher.resize(total_size);

        // Step 1: SPDZ2k → LUT → exp
        for (size_t i = 0; i < total_size; ++i) {
            auto [plain, cipher] = A2L_spdz2k::A2L(elgl, LVTInstances::lvt_exp, spdz2k, party, num_party,
                                                static_cast<MultiIO*>(io), pool,
                                                data_spdz2k[i], fd,
                                                exp_tensor.time_dummy, exp_tensor.comm_dummy);

            Plaintext out, x_share;
            LVTInstances::lvt_exp->lookup_online(out, x_share, cipher[0], cipher);

            exp_tensor.data_lut_plain[i] = out;
            exp_tensor.data_lut_cipher[i] = cipher;
        }

        // Step 2: 还原 SPDZ2k share (LUT → SPDZ2k)
        exp_tensor.to_spdz2k();

        // Step 3: 按 batch 分组求和
        std::vector<Share> row_sums(batch);
        for (size_t b = 0; b < batch; ++b) {
            Share acc = spdz2k.get_zero_share();
            for (size_t j = 0; j < dim; ++j) {
                acc = spdz2k.add(acc, exp_tensor.data_spdz2k[b * dim + j]);
            }
            row_sums[b] = acc;
        }

        // Step 4: 每个元素除以该行的 sum
        SecretTensor result(out_shape, spdz2k, elgl, lvt, io, pool, party, num_party, fd);
        for (size_t b = 0; b < batch; ++b) {
            for (size_t j = 0; j < dim; ++j) {
                size_t idx = b * dim + j;
                result.data_spdz2k[idx] = spdz2k.divide(exp_tensor.data_spdz2k[idx], row_sums[b], f);
            }
        }

        return result;
    }


    // 除法
    SecretTensor div(const SecretTensor& other) const {
        SecretTensor this_spdz2k = *this;
        SecretTensor other_lut = other;
        if (type != ShareType::SPDZ2k) {
            this_spdz2k.to_spdz2k();
        }
        if (other.type == ShareType::SPDZ2k) {
            other_lut.to_lut();
        }
        // 2. 使用LVT计算除法
        for (size_t i = 0; i < total_size; ++i) {
            Plaintext out;
            vector<Ciphertext> out_ciphers;
            lookup_online(out, out_ciphers, other_lut.data_lut_plain[i], other_lut.data_lut_cipher[i][0], other_lut.data_lut_cipher[i], LVTInstances::lvt_div);
            other_lut.data_lut_plain[i] = out;
            other_lut.data_lut_cipher[i] = out_ciphers;
        }
        other_lut.to_spdz2k();
        SecretTensor out_tensor = this_spdz2k;
        for (size_t i = 0; i < total_size; ++i) {
            out_tensor.data_spdz2k[i] = spdz2k.multiply_with_trunc(this_spdz2k.data_spdz2k[i], other_lut.data_spdz2k[i], f);
        }
        return out_tensor;
    }

    // 平方根
    SecretTensor sqrt() const {
        SecretTensor lut_tensor = *this;
        if (type == ShareType::SPDZ2k) {
            // 1. 转换为LUT share
            lut_tensor.to_lut();
        }
        // 2. 使用LVT计算ReLU
        for (size_t i = 0; i < total_size; ++i) {
            Plaintext out;
            vector<Ciphertext> out_ciphers;
            out_ciphers.resize(num_party);
            lookup_online(out, out_ciphers, lut_tensor.data_lut_plain[i], lut_tensor.data_lut_cipher[i][0], lut_tensor.data_lut_cipher[i], LVTInstances::lvt_sqrt);
            lut_tensor.data_lut_plain[i] = out;
            for (int j = 0; j < num_party; ++j) {
                lut_tensor.data_lut_cipher[i][j] = out_ciphers[j];
            }
        }  
        return lut_tensor;
    }

    // 张量减法
    SecretTensor sub(const SecretTensor& other) const {
        assert(type == ShareType::SPDZ2k && other.type == ShareType::SPDZ2k);
        assert(shape == other.shape);
        SecretTensor result(shape, spdz2k, elgl, lvt, io, pool, party, num_party, fd);
        for (size_t i = 0; i < total_size; ++i) {
            result.data_spdz2k[i] = spdz2k.sub(data_spdz2k[i], other.data_spdz2k[i]);
        }
        return result;
    }

    // 逐元素乘法
    SecretTensor mul(const SecretTensor& other) const {
        assert(type == ShareType::SPDZ2k && other.type == ShareType::SPDZ2k);
        assert(shape == other.shape);
        SecretTensor result(shape, spdz2k, elgl, lvt, io, pool, party, num_party, fd);
        for (size_t i = 0; i < total_size; ++i) {
            result.data_spdz2k[i] = spdz2k.multiply_with_trunc(data_spdz2k[i], other.data_spdz2k[i], f);
        }
        return result;
    }

    // 幂运算（仅支持幂为2/3/0.5等常用，底层用LUT实现）
    SecretTensor pow() const {
        SecretTensor lut_tensor = *this;
        if (type == ShareType::SPDZ2k) {
            // 1. 转换为LUT share
            lut_tensor.to_lut();
        }
        // 2. 使用LVT计算ReLU
        for (size_t i = 0; i < total_size; ++i) {
            Plaintext out;
            vector<Ciphertext> out_ciphers;
            out_ciphers.resize(num_party);
            lookup_online(out, out_ciphers, lut_tensor.data_lut_plain[i], lut_tensor.data_lut_cipher[i][0], lut_tensor.data_lut_cipher[i], LVTInstances::lvt_pow);
            lut_tensor.data_lut_plain[i] = out;
            for (int j = 0; j < num_party; ++j) {
                lut_tensor.data_lut_cipher[i][j] = out_ciphers[j];
            }
        }  
        return lut_tensor;
    }

    // 指数函数（exp），用LUT实现
    SecretTensor exp() const {
        SecretTensor lut_tensor = *this;
        if (type == ShareType::SPDZ2k) {
            // 1. 转换为LUT share
            lut_tensor.to_lut();
        }
        // 2. 使用LVT计算ReLU
        for (size_t i = 0; i < total_size; ++i) {
            Plaintext out;
            vector<Ciphertext> out_ciphers;
            out_ciphers.resize(num_party);
            lookup_online(out, out_ciphers, lut_tensor.data_lut_plain[i], lut_tensor.data_lut_cipher[i][0], lut_tensor.data_lut_cipher[i], LVTInstances::lvt_exp);
            lut_tensor.data_lut_plain[i] = out;
            for (int j = 0; j < num_party; ++j) {
                lut_tensor.data_lut_cipher[i][j] = out_ciphers[j];
            }
        }  
        return lut_tensor;
    }

    // 对数函数（log），用LUT实现
    SecretTensor log() const {
        SecretTensor lut_tensor = *this;
        if (type == ShareType::SPDZ2k) {
            // 1. 转换为LUT share
            lut_tensor.to_lut();
        }
        // 2. 使用LVT计算ReLU
        for (size_t i = 0; i < total_size; ++i) {
            Plaintext out;
            vector<Ciphertext> out_ciphers;
            out_ciphers.resize(num_party);
            lookup_online(out, out_ciphers, lut_tensor.data_lut_plain[i], lut_tensor.data_lut_cipher[i][0], lut_tensor.data_lut_cipher[i], LVTInstances::lvt_log);
            lut_tensor.data_lut_plain[i] = out;
            for (int j = 0; j < num_party; ++j) {
                lut_tensor.data_lut_cipher[i][j] = out_ciphers[j];
            }
        }  
        return lut_tensor;
    }

    // Sigmoid激活函数，LUT实现
    SecretTensor sigmoid() const {
        SecretTensor lut_tensor = *this;
        if (type == ShareType::SPDZ2k) {
            // 1. 转换为LUT share
            lut_tensor.to_lut();
        }
        // 2. 使用LVT计算ReLU
        for (size_t i = 0; i < total_size; ++i) {
            Plaintext out;
            vector<Ciphertext> out_ciphers;
            out_ciphers.resize(num_party);
            lookup_online(out, out_ciphers, lut_tensor.data_lut_plain[i], lut_tensor.data_lut_cipher[i][0], lut_tensor.data_lut_cipher[i], LVTInstances::lvt_sigmoid);
            lut_tensor.data_lut_plain[i] = out;
            for (int j = 0; j < num_party; ++j) {
                lut_tensor.data_lut_cipher[i][j] = out_ciphers[j];
            }
        }  
        return lut_tensor;
    }

    // Tanh激活函数，LUT实现
    SecretTensor tanh() const {
        SecretTensor lut_tensor = *this;
        if (type == ShareType::SPDZ2k) {
            // 1. 转换为LUT share
            lut_tensor.to_lut();
        }
        // 2. 使用LVT计算ReLU
        for (size_t i = 0; i < total_size; ++i) {
            Plaintext out;
            vector<Ciphertext> out_ciphers;
            out_ciphers.resize(num_party);
            lookup_online(out, out_ciphers, lut_tensor.data_lut_plain[i], lut_tensor.data_lut_cipher[i][0], lut_tensor.data_lut_cipher[i], LVTInstances::lvt_tanh);
            lut_tensor.data_lut_plain[i] = out;
            for (int j = 0; j < num_party; ++j) {
                lut_tensor.data_lut_cipher[i][j] = out_ciphers[j];
            }
        }  
        return lut_tensor;
    }

    // reshape操作，仅修改shape和数据排列，不做实际数据变换
    SecretTensor reshape(const std::vector<size_t>& new_shape) const {
        assert(product(new_shape) == total_size);
        SecretTensor result = *this;
        result.shape = new_shape;
        return result;
    }

    // transpose操作，交换指定轴
    SecretTensor transpose(const std::vector<size_t>& axes) const {
        assert(axes.size() == shape.size());
        std::vector<size_t> new_shape(shape.size());
        for (size_t i = 0; i < axes.size(); ++i) new_shape[i] = shape[axes[i]];
        SecretTensor result(new_shape, spdz2k, elgl, lvt, io, pool, party, num_party, fd, type);
        // 这里只实现一维数据的重排，实际需实现多维索引映射
        // TODO: 完善多维transpose
        for (size_t i = 0; i < total_size; ++i) {
            if (type == ShareType::SPDZ2k)
                result.data_spdz2k[i] = data_spdz2k[i];
            else {
                result.data_lut_plain[i] = data_lut_plain[i];
                result.data_lut_cipher[i] = data_lut_cipher[i];
            }
        }
        return result;
    }

    // sum操作，按指定轴求和（这里只实现全局sum，axis需进一步实现）
    SecretTensor sum(int axis = -1, bool keepdim = false) const {
        // 这里只实现全局sum
        SecretTensor result({1}, spdz2k, elgl, lvt, io, pool, party, num_party, fd, type);
        if (type == ShareType::SPDZ2k) {
            result.data_spdz2k[0] = spdz2k.get_zero_share();
            for (size_t i = 0; i < total_size; ++i)
                result.data_spdz2k[0] = spdz2k.add(result.data_spdz2k[0], data_spdz2k[i]);
        } else {
            result.data_lut_plain[0] = data_lut_plain[0];
            for (size_t i = 1; i < total_size; ++i)
                result.data_lut_plain[0] += data_lut_plain[i];
        }
        return result;
    }

    // mean操作，按指定轴求均值（这里只实现全局mean，axis需进一步实现）
    SecretTensor mean(int axis = -1, bool keepdim = false) const {
        SecretTensor s = sum(axis, keepdim);
        if (type != ShareType::SPDZ2k) {
            s.to_spdz2k();
        }
        SecretTensor denom({1}, spdz2k, elgl, lvt, io, pool, party, num_party, fd, type);
            denom.data_spdz2k[0] = spdz2k.distributed_share_(total_size);
            return s.div(denom);
    }

    // max操作，按指定轴求最大值（这里只实现全局max，axis需进一步实现）
    SecretTensor max(int axis = -1, bool keepdim = false) const {
        SecretTensor result({1}, spdz2k, elgl, lvt, io, pool, party, num_party, fd, type);
        if (type == ShareType::SPDZ2k) {
            result.data_spdz2k[0] = data_spdz2k[0];
            for (size_t i = 1; i < total_size; ++i) {
                // TODO: 需要安全比较协议，这里仅为接口
            }
        } else {
            result.data_lut_plain[0] = data_lut_plain[0];
            for (size_t i = 1; i < total_size; ++i)
                if (data_lut_plain[i] > result.data_lut_plain[0])
                    result.data_lut_plain[0] = data_lut_plain[i];
        }
        return result;
    }

    // Masked Softmax，先用softmax再用mask
    SecretTensor masked_softmax(const SecretTensor& mask) const {
        SecretTensor softmaxed = this->softmax();
        return softmaxed.mul(mask);
    }

    // 按轴分割（这里只实现等分split，axis需进一步实现）
    std::vector<SecretTensor> split(int axis, int num_splits) const {
        std::vector<SecretTensor> result;
        size_t split_size = total_size / num_splits;
        for (int i = 0; i < num_splits; ++i) {
            SecretTensor part({split_size}, spdz2k, elgl, lvt, io, pool, party, num_party, fd, type);
            if (type == ShareType::SPDZ2k) {
                std::copy(data_spdz2k.begin() + i * split_size, data_spdz2k.begin() + (i + 1) * split_size, part.data_spdz2k.begin());
            } else {
                std::copy(data_lut_plain.begin() + i * split_size, data_lut_plain.begin() + (i + 1) * split_size, part.data_lut_plain.begin());
                std::copy(data_lut_cipher.begin() + i * split_size, data_lut_cipher.begin() + (i + 1) * split_size, part.data_lut_cipher.begin());
            }
            result.push_back(part);
        }
        return result;
    }

    // 拼接（concat），这里只实现一维拼接
    static SecretTensor concat(const std::vector<SecretTensor>& tensors, int axis) {
        size_t total = 0;
        for (const auto& t : tensors) total += t.total_size;
        SecretTensor result({total}, tensors[0].spdz2k, tensors[0].elgl, tensors[0].lvt, tensors[0].io, tensors[0].pool, tensors[0].party, tensors[0].num_party, tensors[0].fd, tensors[0].type);
        size_t offset = 0;
        for (const auto& t : tensors) {
            if (t.type == ShareType::SPDZ2k)
                std::copy(t.data_spdz2k.begin(), t.data_spdz2k.end(), result.data_spdz2k.begin() + offset);
            else {
                std::copy(t.data_lut_plain.begin(), t.data_lut_plain.end(), result.data_lut_plain.begin() + offset);
                std::copy(t.data_lut_cipher.begin(), t.data_lut_cipher.end(), result.data_lut_cipher.begin() + offset);
            }
            offset += t.total_size;
        }
        return result;
    }
    
    // 张量切片（这里只实现一维切片，实际多维可扩展）
    SecretTensor slice(const std::vector<size_t>& start, const std::vector<size_t>& end) const {
        assert(start.size() == 1 && end.size() == 1); // 这里只支持一维
        size_t s = start[0], e = end[0];
        assert(e > s && e <= total_size);
        SecretTensor result({e - s}, spdz2k, elgl, lvt, io, pool, party, num_party, fd, type);
        if (type == ShareType::SPDZ2k) {
            std::copy(data_spdz2k.begin() + s, data_spdz2k.begin() + e, result.data_spdz2k.begin());
        } else {
            std::copy(data_lut_plain.begin() + s, data_lut_plain.begin() + e, result.data_lut_plain.begin());
            std::copy(data_lut_cipher.begin() + s, data_lut_cipher.begin() + e, result.data_lut_cipher.begin());
        }
        return result;
    }

    // 堆叠（stack），多维实现：在指定axis插入新维度
    static SecretTensor stack(const std::vector<SecretTensor>& tensors, int axis) {
        assert(!tensors.empty());
        std::vector<size_t> base_shape = tensors[0].shape;
        for (const auto& t : tensors) assert(t.shape == base_shape);
        std::vector<size_t> new_shape = base_shape;
        new_shape.insert(new_shape.begin() + axis, tensors.size());
        size_t total = 1;
        for (auto d : new_shape) total *= d;
        SecretTensor result(new_shape, tensors[0].spdz2k, tensors[0].elgl, tensors[0].lvt, tensors[0].io, tensors[0].pool, tensors[0].party, tensors[0].num_party, tensors[0].fd, tensors[0].type);
        // 这里只做简单拼接，实际应按axis插入
        size_t offset = 0;
        for (const auto& t : tensors) {
            if (t.type == ShareType::SPDZ2k)
                std::copy(t.data_spdz2k.begin(), t.data_spdz2k.end(), result.data_spdz2k.begin() + offset);
            else {
                std::copy(t.data_lut_plain.begin(), t.data_lut_plain.end(), result.data_lut_plain.begin() + offset);
                std::copy(t.data_lut_cipher.begin(), t.data_lut_cipher.end(), result.data_lut_cipher.begin() + offset);
            }
            offset += t.total_size;
        }
        return result;
    }
    
    // LayerNorm归一化，公式：(x-mean)/sqrt(var+eps)*gamma+beta
    SecretTensor layernorm(const SecretTensor& gamma, const SecretTensor& beta, float eps = 1e-5) const {
        // 这里只实现全局LayerNorm，axis支持可后续扩展
        SecretTensor mean_tensor = this->mean();
        SecretTensor x_centered = this->sub(mean_tensor);
        SecretTensor sq = x_centered.mul(x_centered);
        SecretTensor var_tensor = sq.mean();
        SecretTensor var_eps = var_tensor.add(SecretTensor::from_plaintext({1}, {static_cast<uint64_t>(eps * FixedPoint_SIZE)}, spdz2k, elgl, lvt, io, pool, party, num_party, fd, type));
        SecretTensor std_tensor = var_eps.sqrt();
        SecretTensor normed = x_centered.div(std_tensor);
        SecretTensor scaled = normed.mul(gamma);
        SecretTensor shifted = scaled.add(beta);
        return shifted;
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