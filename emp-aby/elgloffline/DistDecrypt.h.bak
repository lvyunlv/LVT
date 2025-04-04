#ifndef _DistDecrypt
#define _DistDecrypt

#include "ELGL/Ciphertext.h"
#include "elgloffline/Exp_proof.h"
#include "elgloffline/Exp_prover.h"
#include "elgloffline/Exp_verifier.h"
#include "elgl/BLS12381Element.h"

class DistDecrypt {
protected:
    const int n_players;
                    // 当前参与方
    const ELGL_SK& share;                 // 当前参与方的私钥
    const ELGL_PK& pk;                    // 公钥
    const std::vector<ELGL_PK>& pks;      // 所有参与方的公钥

public:
    Plaintext plain;                      // 解密后的明文

    // 构造函数
    DistDecrypt(const int n_player, const ELGL_SK& share, const ELGL_PK& pk, const std::vector<ELGL_PK>& pks, Plaintext fd);

    // 运行分布式解密协议
    Plaintext& run(const Ciphertext& ctx);
};

#endif