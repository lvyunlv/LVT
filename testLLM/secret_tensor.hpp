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
const int FixedPoint_SIZE = 1ULL << 24;
namespace emp {

enum class ShareType {
    SPDZ2k,
    LUT
};

template<typename IO = MultiIOBase>
class SecretTensor {
public:
    using Share = typename SPDZ2k<IO>::LabeledShare;

    // 构造函数
    SecretTensor(const std::vector<size_t>& shape, SPDZ2k<MultiIOBase>& spdz2k, ELGL<MultiIOBase>* elgl, LVT<MultiIOBase>* lvt, MultiIO* io, ThreadPool* pool, int party, int num_party, const uint64_t& fd, ShareType type = ShareType::SPDZ2k) : shape(shape), spdz2k(spdz2k), elgl(elgl), lvt(lvt), io(io), pool(pool), party(party), num_party(num_party), fd(fd), type(type) {
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
    static SecretTensor from_plaintext(const std::vector<size_t>& shape, const std::vector<uint64_t>& values, SPDZ2k<MultiIOBase>& spdz2k, ELGL<MultiIOBase>* elgl, LVT<MultiIOBase>* lvt, MultiIO* io, ThreadPool* pool, int party, int num_party, const uint64_t& fd, ShareType type = ShareType::SPDZ2k)
    {
        assert(values.size() == product(shape));

        SecretTensor tensor(shape, spdz2k, elgl, lvt, io, pool, party, num_party, fd, type);

        if (type == ShareType::SPDZ2k) {
            for (size_t i = 0; i < values.size(); ++i) {
                tensor.data_spdz2k[i] = spdz2k.distributed_share(values[i]);
            }
        } else {
            for (size_t i = 0; i < values.size(); ++i) {
                auto [plain, cipher] = A2L_spdz2k::A2L(elgl, lvt, spdz2k, party, num_party, io, pool,
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
            auto [plain, cipher] = A2L_spdz2k::A2L(elgl, lvt, spdz2k, party, num_party, io, pool, data_spdz2k[i], fd, time_dummy, comm_dummy);
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
            data_spdz2k[i] = L2A_spdz2k::L2A(elgl, lvt, spdz2k, party, num_party, io, pool, data_lut_plain[i], data_lut_cipher[i], fd, time_dummy, comm_dummy);
        }

        data_lut_plain.clear();
        data_lut_cipher.clear();
        type = ShareType::SPDZ2k;
    }

    // 获取总尺寸
    size_t size() const { return total_size; }

    // // 非线性函数计算
    // SecretTensor relu() const {
    //     assert(type == ShareType::SPDZ2k);
        
    //     // 1. 转换为LUT share
    //     SecretTensor lut_tensor = *this;
    //     lut_tensor.to_lut();
        
    //     // 2. 使用LVT计算ReLU
    //     for (size_t i = 0; i < total_size; ++i) {
    //         lvt->lookup_online(lut_tensor.data_lut_plain[i], 
    //                          lut_tensor.data_lut_plain[i],
    //                          lut_tensor.data_lut_cipher[i],
    //                          lut_tensor.data_lut_cipher);
    //     }
        
    //     return lut_tensor;
    // }

    // // GELU激活函数
    // SecretTensor gelu() const {
    //     assert(type == ShareType::SPDZ2k);
        
    //     // 1. 转换为LUT share
    //     SecretTensor lut_tensor = *this;
    //     lut_tensor.to_lut();
        
    //     // 2. 使用LVT计算GELU
    //     for (size_t i = 0; i < total_size; ++i) {
    //         lvt->lookup_online(lut_tensor.data_lut_plain[i],
    //                          lut_tensor.data_lut_plain[i],
    //                          lut_tensor.data_lut_cipher[i],
    //                          lut_tensor.data_lut_cipher);
    //     }
        
    //     return lut_tensor;
    // }

    // // Layer Normalization
    // SecretTensor layer_norm(const std::vector<size_t>& norm_shape) const {
    //     assert(type == ShareType::SPDZ2k);
        
    //     // 1. 计算均值
    //     SecretTensor mean = this->mean(norm_shape);
        
    //     // 2. 计算方差
    //     SecretTensor var = this->var(norm_shape, mean);
        
    //     // 3. 标准化
    //     SecretTensor normalized = this->sub(mean).div(var.sqrt());
        
    //     return normalized;
    // }

    // // 计算均值
    // SecretTensor mean(const std::vector<size_t>& axis) const {
    //     assert(type == ShareType::SPDZ2k);
        
    //     // 实现均值计算
    //     // TODO: 实现具体的均值计算逻辑
    //     return *this;
    // }

    // // 计算方差
    // SecretTensor var(const std::vector<size_t>& axis, const SecretTensor& mean) const {
    //     assert(type == ShareType::SPDZ2k);
        
    //     // 实现方差计算
    //     // TODO: 实现具体的方差计算逻辑
    //     return *this;
    // }

    // // 平方根
    // SecretTensor sqrt() const {
    //     assert(type == ShareType::SPDZ2k);
        
    //     // 1. 转换为LUT share
    //     SecretTensor lut_tensor = *this;
    //     lut_tensor.to_lut();
        
    //     // 2. 使用LVT计算平方根
    //     for (size_t i = 0; i < total_size; ++i) {
    //         lvt->lookup_online(lut_tensor.data_lut_plain[i],
    //                          lut_tensor.data_lut_plain[i],
    //                          lut_tensor.data_lut_cipher[i],
    //                          lut_tensor.data_lut_cipher);
    //     }
        
    //     return lut_tensor;
    // }

    // // 减法
    // SecretTensor sub(const SecretTensor& other) const {
    //     assert(type == ShareType::SPDZ2k && other.type == ShareType::SPDZ2k);
    //     assert(shape == other.shape);
        
    //     SecretTensor result(shape, spdz2k, elgl, lvt, io, pool, party, num_party, fd);
        
    //     for (size_t i = 0; i < total_size; ++i) {
    //         result.data_spdz2k[i] = spdz2k.sub(data_spdz2k[i], other.data_spdz2k[i]);
    //     }
        
    //     return result;
    // }

    // // 除法
    // SecretTensor div(const SecretTensor& other) const {
    //     assert(type == ShareType::SPDZ2k && other.type == ShareType::SPDZ2k);
    //     assert(shape == other.shape);
        
    //     // 1. 转换为LUT share
    //     SecretTensor lut_tensor = *this;
    //     lut_tensor.to_lut();
        
    //     // 2. 使用LVT计算除法
    //     for (size_t i = 0; i < total_size; ++i) {
    //         lvt->lookup_online(lut_tensor.data_lut_plain[i],
    //                          lut_tensor.data_lut_plain[i],
    //                          lut_tensor.data_lut_cipher[i],
    //                          lut_tensor.data_lut_cipher);
    //     }
        
    //     return lut_tensor;
    // }

    // // 注意力机制
    // SecretTensor attention(const SecretTensor& key, const SecretTensor& value, 
    //                       const SecretTensor& query, double scale = 1.0) const {
    //     assert(type == ShareType::SPDZ2k && 
    //            key.type == ShareType::SPDZ2k && 
    //            value.type == ShareType::SPDZ2k && 
    //            query.type == ShareType::SPDZ2k);
        
    //     // 1. 计算注意力分数
    //     SecretTensor scores = query.matmul(key.transpose());
        
    //     // 2. 缩放
    //     if (scale != 1.0) {
    //         scores = scores.mul_const(scale);
    //     }
        
    //     // 3. Softmax
    //     SecretTensor attention_weights = scores.softmax();
        
    //     // 4. 计算输出
    //     return attention_weights.matmul(value);
    // }

    // // Softmax
    // SecretTensor softmax() const {
    //     assert(type == ShareType::SPDZ2k);
        
    //     // 1. 转换为LUT share
    //     SecretTensor lut_tensor = *this;
    //     lut_tensor.to_lut();
        
    //     // 2. 使用LVT计算softmax
    //     for (size_t i = 0; i < total_size; ++i) {
    //         lvt->lookup_online(lut_tensor.data_lut_plain[i],
    //                          lut_tensor.data_lut_plain[i],
    //                          lut_tensor.data_lut_cipher[i],
    //                          lut_tensor.data_lut_cipher);
    //     }
        
    //     return lut_tensor;
    // }

    // // 转置操作
    // SecretTensor transpose() const {
    //     assert(type == ShareType::SPDZ2k);
    //     assert(shape.size() == 2);  // 只支持2D张量
        
    //     std::vector<size_t> new_shape = {shape[1], shape[0]};
    //     SecretTensor result(new_shape, spdz2k, elgl, lvt, io, pool, party, num_party, fd);
        
    //     for (size_t i = 0; i < shape[0]; ++i) {
    //         for (size_t j = 0; j < shape[1]; ++j) {
    //             result.data_spdz2k[j * shape[0] + i] = data_spdz2k[i * shape[1] + j];
    //         }
    //     }
        
    //     return result;
    // }

    // // 常量乘法
    // SecretTensor mul_const(double constant) const {
    //     assert(type == ShareType::SPDZ2k);
        
    //     SecretTensor result(shape, spdz2k, elgl, lvt, io, pool, party, num_party, fd);
        
    //     for (size_t i = 0; i < total_size; ++i) {
    //         result.data_spdz2k[i] = spdz2k.mul_const(data_spdz2k[i], constant);
    //     }
        
    //     return result;
    // }

    // // 多头注意力机制
    // SecretTensor multi_head_attention(const SecretTensor& key, const SecretTensor& value,
    //                                 const SecretTensor& query, int num_heads) const {
    //     assert(type == ShareType::SPDZ2k && 
    //            key.type == ShareType::SPDZ2k && 
    //            value.type == ShareType::SPDZ2k && 
    //            query.type == ShareType::SPDZ2k);
        
    //     // 1. 分割头
    //     std::vector<SecretTensor> query_heads = query.split_heads(num_heads);
    //     std::vector<SecretTensor> key_heads = key.split_heads(num_heads);
    //     std::vector<SecretTensor> value_heads = value.split_heads(num_heads);
        
    //     // 2. 计算每个头的注意力
    //     std::vector<SecretTensor> attention_outputs;
    //     for (int i = 0; i < num_heads; ++i) {
    //         attention_outputs.push_back(
    //             attention(key_heads[i], value_heads[i], query_heads[i])
    //         );
    //     }
        
    //     // 3. 合并头
    //     return combine_heads(attention_outputs);
    // }

    // // 分割多头
    // std::vector<SecretTensor> split_heads(int num_heads) const {
    //     assert(type == ShareType::SPDZ2k);
    //     assert(shape.size() == 2);
    //     assert(shape[1] % num_heads == 0);
        
    //     std::vector<SecretTensor> heads;
    //     size_t head_dim = shape[1] / num_heads;
        
    //     for (int i = 0; i < num_heads; ++i) {
    //         std::vector<size_t> head_shape = {shape[0], head_dim};
    //         SecretTensor head(head_shape, spdz2k, elgl, lvt, io, pool, party, num_party, fd);
            
    //         for (size_t j = 0; j < shape[0]; ++j) {
    //             for (size_t k = 0; k < head_dim; ++k) {
    //                 head.data_spdz2k[j * head_dim + k] = 
    //                     data_spdz2k[j * shape[1] + i * head_dim + k];
    //             }
    //         }
            
    //         heads.push_back(head);
    //     }
        
    //     return heads;
    // }

    // // 合并多头
    // static SecretTensor combine_heads(const std::vector<SecretTensor>& heads) {
    //     assert(!heads.empty());
    //     assert(heads[0].type == ShareType::SPDZ2k);
        
    //     size_t num_heads = heads.size();
    //     size_t head_dim = heads[0].shape[1];
    //     size_t batch_size = heads[0].shape[0];
        
    //     std::vector<size_t> result_shape = {batch_size, num_heads * head_dim};
    //     SecretTensor result(result_shape, heads[0].spdz2k, heads[0].elgl, heads[0].lvt,
    //                        heads[0].io, heads[0].pool, heads[0].party, heads[0].num_party,
    //                        heads[0].fd);
        
    //     for (size_t i = 0; i < num_heads; ++i) {
    //         for (size_t j = 0; j < batch_size; ++j) {
    //             for (size_t k = 0; k < head_dim; ++k) {
    //                 result.data_spdz2k[j * (num_heads * head_dim) + i * head_dim + k] =
    //                     heads[i].data_spdz2k[j * head_dim + k];
    //             }
    //         }
    //     }
        
    //     return result;
    // }

    // // BERT Transformer层
    // SecretTensor transformer_layer(const SecretTensor& input,
    //                              const SecretTensor& self_attention_weights,
    //                              const SecretTensor& self_attention_bias,
    //                              const SecretTensor& intermediate_weights,
    //                              const SecretTensor& intermediate_bias,
    //                              const SecretTensor& output_weights,
    //                              const SecretTensor& output_bias,
    //                              int num_heads) const {
    //     assert(type == ShareType::SPDZ2k);
        
    //     // 1. 自注意力层
    //     SecretTensor attention_output = multi_head_attention(
    //         input, input, input, num_heads
    //     );
        
    //     // 2. 添加偏置
    //     attention_output = attention_output.add(self_attention_bias);
        
    //     // 3. Layer Normalization
    //     SecretTensor normalized = attention_output.layer_norm({1});
        
    //     // 4. 前馈网络
    //     SecretTensor intermediate = normalized.matmul(intermediate_weights)
    //                                   .add(intermediate_bias)
    //                                   .gelu();
        
    //     // 5. 输出层
    //     SecretTensor output = intermediate.matmul(output_weights)
    //                                     .add(output_bias);
        
    //     // 6. 残差连接和Layer Normalization
    //     return output.add(normalized).layer_norm({1});
    // }

    // // BERT位置编码
    // SecretTensor add_positional_encoding() const {
    //     assert(type == ShareType::SPDZ2k);
    //     assert(shape.size() == 2);
        
    //     SecretTensor result = *this;
    //     size_t seq_len = shape[0];
    //     size_t hidden_dim = shape[1];
        
    //     // 生成位置编码
    //     for (size_t pos = 0; pos < seq_len; ++pos) {
    //         for (size_t i = 0; i < hidden_dim; ++i) {
    //             double angle = pos / std::pow(10000, 2.0 * i / hidden_dim);
    //             double pe = (i % 2 == 0) ? std::sin(angle) : std::cos(angle);
                
    //             // 将位置编码添加到输入
    //             size_t idx = pos * hidden_dim + i;
    //             result.data_spdz2k[idx] = spdz2k.add(
    //                 result.data_spdz2k[idx],
    //                 spdz2k.encode(pe)
    //             );
    //         }
    //     }
        
    //     return result;
    // }

    // // BERT词嵌入
    // SecretTensor word_embedding(const SecretTensor& embedding_weights,
    //                           const SecretTensor& position_weights,
    //                           const SecretTensor& token_type_weights) const {
    //     assert(type == ShareType::SPDZ2k);
        
    //     // 1. 词嵌入
    //     SecretTensor word_embeddings = matmul(embedding_weights);
        
    //     // 2. 位置编码
    //     SecretTensor position_embeddings = matmul(position_weights);
        
    //     // 3. 类型编码
    //     SecretTensor token_type_embeddings = matmul(token_type_weights);
        
    //     // 4. 合并所有嵌入
    //     return word_embeddings.add(position_embeddings)
    //                          .add(token_type_embeddings)
    //                          .layer_norm({1});
    // }

    // // BERT池化层
    // SecretTensor pooler() const {
    //     assert(type == ShareType::SPDZ2k);
    //     assert(shape.size() == 2);
        
    //     // 取第一个token的表示
    //     std::vector<size_t> new_shape = {1, shape[1]};
    //     SecretTensor result(new_shape, spdz2k, elgl, lvt, io, pool, party, num_party, fd);
        
    //     for (size_t i = 0; i < shape[1]; ++i) {
    //         result.data_spdz2k[i] = data_spdz2k[i];
    //     }
        
    //     return result;
    // }

    // // BERT分类头
    // SecretTensor classification_head(const SecretTensor& weights,
    //                               const SecretTensor& bias) const {
    //     assert(type == ShareType::SPDZ2k);
        
    //     // 1. 池化
    //     SecretTensor pooled = pooler();
        
    //     // 2. 线性层
    //     return pooled.matmul(weights).add(bias);
    // }

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
    MultiIO* io;
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
