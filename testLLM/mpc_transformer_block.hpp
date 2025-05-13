#pragma once
#include "secret_tensor.hpp"

class MPCTransformerBlock {
public:
    SecretTensor W_q, W_k, W_v, W_o;  // 注意力权重
    SecretTensor W1, W2;              // FFN 权重
    LVT<MultiIOBase>* lvt;

    MPCTransformerBlock(const SecretTensor& Wq, const SecretTensor& Wk,
                        const SecretTensor& Wv, const SecretTensor& Wo,
                        const SecretTensor& FFN1, const SecretTensor& FFN2,
                        LVT<MultiIOBase>* lvt_ptr)
        : W_q(Wq), W_k(Wk), W_v(Wv), W_o(Wo), W1(FFN1), W2(FFN2), lvt(lvt_ptr) {}

    SecretTensor forward(const SecretTensor& x) {
        // Attention: Q = xWq, K = xWk, V = xWv
        auto Q = x.matmul(W_q);
        auto K = x.matmul(W_k);
        auto V = x.matmul(W_v);

        // Attention Score: softmax(QK^T / sqrt(dk))
        auto scores = Q.matmul(K.transpose()).scale(1.0 / sqrt(Q.shape[1]));
        auto attention = lvt_softmax->apply(scores);  // 假设你提前初始化了 lvt_softmax

        // Attention Output: A = attention × V
        auto A = attention.matmul(V);
        auto context = A.matmul(W_o);

        // FeedForward: FFN(x) = W2(ReLU(W1(x)))
        auto ff1 = x.matmul(W1);
        auto activated = lvt_gelu->apply(ff1);  // or lvt_relu
        auto ff2 = activated.matmul(W2);

        // Add & Norm 可以简化省略（或写成 x + context + ff2）
        return context.add(ff2);  // 残差连接
    }
};
