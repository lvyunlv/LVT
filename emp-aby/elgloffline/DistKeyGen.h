// 椭圆曲线群上的ElGamal分布式密钥生成
#ifndef ELGLOFFLINE_DISTKEYGEN_H_
#define ELGLOFFLINE_DISTKEYGEN_H_

#include "ELGL/ELGL_Key.h"
#include "elgl/BLS12381Element.h"

// 分布式密钥生成协议
void Run_Gen_Protocol(ELGL_PK& pk, ELGL_SK& sk, std::vector<ELGL_PK>& pks, const int n_player, const int my_num);

class DistKeyGen {
public:
    Plaintext secret; // 私钥部分
    BLS12381Element a; // 椭圆曲线群上的中间值
    ELGL_PK gpk; // 公钥
    std::vector<ELGL_PK>& pki; // 所有参与方的公钥

    // 构造函数
    DistKeyGen(std::vector<ELGL_PK>& pki);

    // 生成随机私钥
    void Gen_Random_Data();

    // 计算中间值 a
    void compute_a();

    // 累加其他参与方的中间值
    void sum_a(const std::vector<BLS12381Element>& as);

    // 完成密钥生成
    void finalize(ELGL_PK& pk, ELGL_SK& sk, std::vector<ELGL_PK>& b);

    // 重载 += 操作符，用于累加密钥生成的中间值
    DistKeyGen& operator+=(const DistKeyGen& other);
};

#endif