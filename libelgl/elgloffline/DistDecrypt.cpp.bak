// 增加DFT
#include "elgloffline/DistDecrypt.h"
#include "ELGLOffline/Exp_proof.h"

// 构造函数
DistDecrypt::DistDecrypt(const int n_players, const ELGL_SK& share, const ELGL_PK& pk, const std::vector<ELGL_PK>& pks, Plaintext fd)
    : n_players(n_players), share(share), pk(pk), pks(pks), plain(fd) {}

// 运行分布式解密协议
Plaintext& DistDecrypt::run(const Ciphertext& ctx) {
    // 计算 a^sk
    BLS12381Element c0 = ctx.get_c0() * share.get_sk();

    // 生成Exp_proof
    // PRNG G;
    // G.ReSeed();
    size_t n_tilde = 65536;
    ExpProof proof(pk, n_tilde);

    ExpProver prover(proof);
    vector<std::stringstream> ciphertexts(n_players);
    vector<std::stringstream> cleartexts(n_players);

    // n_proof = 1
    std::vector<BLS12381Element> g1 = {ctx.get_c0()}; // a
    std::vector<BLS12381Element> y1 = {BLS12381Element(share.get_sk())}; // pki
    std::vector<BLS12381Element> y2 = {c0}; // a^ski
    std::vector<Plaintext> x = {share.get_sk()};
    
    prover.NIZKPoK(proof, ciphertexts[n_players], cleartexts[n_players], g1, y1, y2, x);
    std::cout << "finish this party's prove and send to others" << std::endl;

    std::vector<BLS12381Element> g1_tmp; // a
    std::vector<BLS12381Element> y1_tmp; // pki
    std::vector<BLS12381Element> y2_tmp; // a^ski
    std::vector<BLS12381Element> c0s; // 每个参与方的a^ski
    c0s[n_players] = c0; // 当前参与方的a^ski
    for(int i = 0; i < n_players; i++) {
        if (i != n_players){
            ExpVerifier verifier(proof);
            verifier.NIZKPoK(g1_tmp, y1_tmp, y2_tmp, ciphertexts[i], cleartexts[i]);
            c0s[i] = y2_tmp[0]; 
            std::cout << "finish party " << i << "'s verify" << std::endl;
        }
    }

    // 计算最终解密值m = log_g (b/a^sk)
    BLS12381Element M = ctx.get_c1();
    for (size_t i = 1; i < pks.size(); i++) {
        M = M - c0s[i];
    }

    std::map<Fp, Fr> P_to_m;
    plain.set_message(P_to_m.at(M.getPoint().x));
    return plain;
}