#include "Bert.hpp"
#include "secret_tensor.hpp"
#include "emp-aby/spdz2k.hpp"
#include "emp-aby/elgl_interface.hpp"
#include "emp-aby/lvt.h"
#include "emp-aby/io/multi-io.hpp"
#include <iostream>
#include <vector>
#include <random>

using namespace emp;

// 测试配置
const int BATCH_SIZE = 1;
const int SEQ_LENGTH = 128;
const int HIDDEN_SIZE = 768;
const int NUM_HEADS = 12;
const int NUM_LAYERS = 12;
const int VOCAB_SIZE = 30522;

int party, port;
const static int threads = 8;
int num_party;
// const uint64_t FIELD_SIZE("340282366920938463463374607431768211297");
const uint64_t FIELD_SIZE = (1ULL << 63) - 1;
int m_bits = 32; // bits of message

template<typename IO>
SecretTensor<IO> create_random_tensor(const std::vector<size_t>& shape, 
                                    SPDZ2k<IO>& spdz2k,
                                    ELGL<IO>* elgl,
                                    LVT<IO>* lvt,
                                    MultiIO* io,
                                    ThreadPool* pool,
                                    int party,
                                    int num_party,
                                    const uint64_t& fd) {
    std::vector<uint64_t> values;
    size_t total_size = 1;
    for (auto dim : shape) total_size *= dim;
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(-1.0, 1.0);
    
    for (size_t i = 0; i < total_size; ++i) {
        double val = dis(gen);
        values.push_back(FixedPointConverter::double_to_fixed(val));
    }
    
    return SecretTensor<IO>::from_plaintext(shape, values, spdz2k, elgl, lvt, io, pool, party, num_party, fd);
}

template<typename IO>
class BertTest {
private:
    SPDZ2k<IO>& spdz2k;
    ELGL<IO>* elgl;
    LVT<IO>* lvt;
    MultiIO* io;
    ThreadPool* pool;
    int party;
    int num_party;
    const uint64_t& fd;

public:
    BertTest(SPDZ2k<IO>& spdz2k,
             ELGL<IO>* elgl,
             LVT<IO>* lvt,
             MultiIO* io,
             ThreadPool* pool,
             int party,
             int num_party,
             const uint64_t& fd)
        : spdz2k(spdz2k), elgl(elgl), lvt(lvt), io(io), 
          pool(pool), party(party), num_party(num_party), fd(fd) {}

    void test_word_embedding() {
        if (party == 1) std::cout << "测试词嵌入..." << std::endl;
        
        // 创建输入
        std::vector<size_t> input_shape = {BATCH_SIZE, SEQ_LENGTH};
        SecretTensor<IO> input_ids = create_random_tensor<IO>(input_shape, spdz2k, elgl, lvt, io, pool, party, num_party, fd);
        
        // 创建嵌入矩阵
        std::vector<size_t> embedding_shape = {VOCAB_SIZE, HIDDEN_SIZE};
        SecretTensor<IO> word_embeddings = create_random_tensor<IO>(embedding_shape, spdz2k, elgl, lvt, io, pool, party, num_party, fd);
        SecretTensor<IO> position_embeddings = create_random_tensor<IO>(embedding_shape, spdz2k, elgl, lvt, io, pool, party, num_party, fd);
        SecretTensor<IO> token_type_embeddings = create_random_tensor<IO>(embedding_shape, spdz2k, elgl, lvt, io, pool, party, num_party, fd);
        
        // 执行词嵌入
        SecretTensor<IO> embedded = input_ids.word_embedding(
            word_embeddings, position_embeddings, token_type_embeddings);
        
        if (party == 1) {
            std::cout << "词嵌入输出形状: [";
            for (size_t i = 0; i < embedded.shape.size(); ++i) {
                std::cout << embedded.shape[i];
                if (i < embedded.shape.size() - 1) std::cout << ", ";
            }
            std::cout << "]" << std::endl;
        }
    }

    void test_transformer_layer() {
        if (party == 1) std::cout << "测试Transformer层..." << std::endl;
        
        // 创建输入和权重
        std::vector<size_t> input_shape = {BATCH_SIZE, SEQ_LENGTH, HIDDEN_SIZE};
        SecretTensor<IO> input = create_random_tensor<IO>(input_shape, spdz2k, elgl, lvt, io, pool, party, num_party, fd);
        
        std::vector<size_t> weight_shape = {HIDDEN_SIZE, HIDDEN_SIZE};
        SecretTensor<IO> self_attention_weights = create_random_tensor<IO>(weight_shape, spdz2k, elgl, lvt, io, pool, party, num_party, fd);
        SecretTensor<IO> self_attention_bias = create_random_tensor<IO>(input_shape, spdz2k, elgl, lvt, io, pool, party, num_party, fd);
        SecretTensor<IO> intermediate_weights = create_random_tensor<IO>(weight_shape, spdz2k, elgl, lvt, io, pool, party, num_party, fd);
        SecretTensor<IO> intermediate_bias = create_random_tensor<IO>(input_shape, spdz2k, elgl, lvt, io, pool, party, num_party, fd);
        SecretTensor<IO> output_weights = create_random_tensor<IO>(weight_shape, spdz2k, elgl, lvt, io, pool, party, num_party, fd);
        SecretTensor<IO> output_bias = create_random_tensor<IO>(input_shape, spdz2k, elgl, lvt, io, pool, party, num_party, fd);
        
        // 创建Transformer层
        TransformerLayer<IO> layer(
            self_attention_weights,
            self_attention_bias,
            intermediate_weights,
            intermediate_bias,
            output_weights,
            output_bias,
            NUM_HEADS
        );
        
        // 执行Transformer层计算
        SecretTensor<IO> output = layer.forward(input);
        
        if (party == 1) {
            std::cout << "Transformer层输出形状: [";
            for (size_t i = 0; i < output.shape.size(); ++i) {
                std::cout << output.shape[i];
                if (i < output.shape.size() - 1) std::cout << ", ";
            }
            std::cout << "]" << std::endl;
        }
    }

    void test_full_bert() {
        if (party == 1) std::cout << "测试完整BERT模型..." << std::endl;
        
        // 创建输入
        std::vector<size_t> input_shape = {BATCH_SIZE, SEQ_LENGTH};
        SecretTensor<IO> input_ids = create_random_tensor<IO>(input_shape, spdz2k, elgl, lvt, io, pool, party, num_party, fd);
        SecretTensor<IO> token_type_ids = create_random_tensor<IO>(input_shape, spdz2k, elgl, lvt, io, pool, party, num_party, fd);
        
        // 创建嵌入矩阵
        std::vector<size_t> embedding_shape = {VOCAB_SIZE, HIDDEN_SIZE};
        SecretTensor<IO> word_embeddings = create_random_tensor<IO>(embedding_shape, spdz2k, elgl, lvt, io, pool, party, num_party, fd);
        SecretTensor<IO> position_embeddings = create_random_tensor<IO>(embedding_shape, spdz2k, elgl, lvt, io, pool, party, num_party, fd);
        SecretTensor<IO> token_type_embeddings = create_random_tensor<IO>(embedding_shape, spdz2k, elgl, lvt, io, pool, party, num_party, fd);
        
        // 创建Transformer层
        std::vector<TransformerLayer<IO>> layers;
        for (int i = 0; i < NUM_LAYERS; ++i) {
            if (party == 1) std::cout << "创建第 " << (i + 1) << " 层Transformer..." << std::endl;
            
            std::vector<size_t> weight_shape = {HIDDEN_SIZE, HIDDEN_SIZE};
            SecretTensor<IO> self_attention_weights = create_random_tensor<IO>(weight_shape, spdz2k, elgl, lvt, io, pool, party, num_party, fd);
            SecretTensor<IO> self_attention_bias = create_random_tensor<IO>(input_shape, spdz2k, elgl, lvt, io, pool, party, num_party, fd);
            SecretTensor<IO> intermediate_weights = create_random_tensor<IO>(weight_shape, spdz2k, elgl, lvt, io, pool, party, num_party, fd);
            SecretTensor<IO> intermediate_bias = create_random_tensor<IO>(input_shape, spdz2k, elgl, lvt, io, pool, party, num_party, fd);
            SecretTensor<IO> output_weights = create_random_tensor<IO>(weight_shape, spdz2k, elgl, lvt, io, pool, party, num_party, fd);
            SecretTensor<IO> output_bias = create_random_tensor<IO>(input_shape, spdz2k, elgl, lvt, io, pool, party, num_party, fd);
            
            layers.emplace_back(
                self_attention_weights,
                self_attention_bias,
                intermediate_weights,
                intermediate_bias,
                output_weights,
                output_bias,
                NUM_HEADS
            );
        }
        
        // 创建池化和分类器权重
        std::vector<size_t> pooler_shape = {HIDDEN_SIZE, HIDDEN_SIZE};
        SecretTensor<IO> pooler_weights = create_random_tensor<IO>(pooler_shape, spdz2k, elgl, lvt, io, pool, party, num_party, fd);
        SecretTensor<IO> pooler_bias = create_random_tensor<IO>({HIDDEN_SIZE}, spdz2k, elgl, lvt, io, pool, party, num_party, fd);
        
        std::vector<size_t> classifier_shape = {HIDDEN_SIZE, 2}; // 二分类
        SecretTensor<IO> classifier_weights = create_random_tensor<IO>(classifier_shape, spdz2k, elgl, lvt, io, pool, party, num_party, fd);
        SecretTensor<IO> classifier_bias = create_random_tensor<IO>({2}, spdz2k, elgl, lvt, io, pool, party, num_party, fd);
        
        // 创建BERT模型
        BertModel<IO> bert(
            word_embeddings,
            position_embeddings,
            token_type_embeddings,
            layers,
            pooler_weights,
            pooler_bias,
            classifier_weights,
            classifier_bias
        );
        
        // 执行前向传播
        SecretTensor<IO> output = bert.forward(input_ids, token_type_ids);
        
        if (party == 1) {
            std::cout << "BERT输出形状: [";
            for (size_t i = 0; i < output.shape.size(); ++i) {
                std::cout << output.shape[i];
                if (i < output.shape.size() - 1) std::cout << ", ";
            }
            std::cout << "]" << std::endl;
        }
    }

    void run_all_tests() {
        test_word_embedding();
        test_transformer_layer();
        test_full_bert();
    }
};

Fr alpha_init(int num) {
    Plaintext alpha;
    const mcl::Vint p("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
    const mcl::Vint g("5"); 
    mcl::Vint n = uint64_t(1) << num;
    mcl::Vint alpha_vint;
    mcl::gmp::powMod(alpha_vint, g, (p - 1) / n, p);
    alpha.assign(alpha_vint.getStr());
    Fr alpha_fr = alpha.get_message();
    vector<int64_t> lut_table = {0, 1};
    serializeTable(lut_table, "table.txt", lut_table.size());
    return alpha_fr;
}

int main(int argc, char** argv) {
    BLS12381Element::init();
    if (argc < 4) {
        std::cout << "Usage: <party> <port> <num_party>" << std::endl;
        return 0;
    }
    
    parse_party_and_port(argv, &party, &port);
    num_party = std::stoi(argv[3]);
    
    std::vector<std::pair<std::string, unsigned short>> net_config;
    for (int i = 1; i <= num_party; ++i) {
        net_config.emplace_back("127.0.0.1", static_cast<unsigned short>(port + i - 1));
    }

    ThreadPool pool(threads);
    MultiIO* io = new MultiIO(party, num_party, net_config);
    ELGL<MultiIOBase>* elgl = new ELGL<MultiIOBase>(num_party, io, &pool, party);

    int num = 1;
    Fr alpha_fr = alpha_init(num);
    LVT<MultiIOBase>* lvt = new LVT<MultiIOBase>(num_party, party, io, &pool, elgl, "../../build/bin/table.txt", alpha_fr, num, m_bits);
    
    SPDZ2k<MultiIOBase> spdz2k(elgl);
    
    // 创建测试实例并运行测试
    BertTest<MultiIOBase> bert_test(spdz2k, elgl, lvt, io, &pool, party, num_party, FIELD_SIZE);
    bert_test.run_all_tests();
    
    delete io;
    delete elgl;
    delete lvt;
    
    return 0;
}