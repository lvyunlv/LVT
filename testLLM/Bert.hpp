#include "secret_tensor.hpp"
#include "FixedPointConverter.h"
#include "emp-aby/emp-aby.h"
#include <iostream>

// 创建BERT模型
class BertModel {
private:
    SecretTensor<IO> word_embeddings;
    SecretTensor<IO> position_embeddings;
    SecretTensor<IO> token_type_embeddings;
    std::vector<TransformerLayer> layers;
    SecretTensor<IO> pooler_weights;
    SecretTensor<IO> pooler_bias;
    SecretTensor<IO> classifier_weights;
    SecretTensor<IO> classifier_bias;

public:
    SecretTensor<IO> forward(const SecretTensor<IO>& input_ids,
                           const SecretTensor<IO>& token_type_ids) {
        // 1. 词嵌入
        SecretTensor<IO> embeddings = input_ids.word_embedding(
            word_embeddings,
            position_embeddings,
            token_type_embeddings
        );

        // 2. 添加位置编码
        embeddings = embeddings.add_positional_encoding();

        // 3. Transformer层
        SecretTensor<IO> hidden_states = embeddings;
        for (const auto& layer : layers) {
            hidden_states = layer.forward(hidden_states);
        }

        // 4. 池化
        SecretTensor<IO> pooled = hidden_states.pooler()
            .matmul(pooler_weights)
            .add(pooler_bias)
            .tanh();

        // 5. 分类头
        return pooled.matmul(classifier_weights)
                    .add(classifier_bias);
    }
};