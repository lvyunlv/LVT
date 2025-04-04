// 椭圆曲线群上的ElGamal分布式密钥生成

#include "elgloffline/DistKeyGen.h"
#include <vector>

// 构造函数
DistKeyGen::DistKeyGen(std::vector<ELGL_PK>& pki) : secret(), a(), gpk(), pki(pki) {}

// 生成随机私钥
void DistKeyGen::Gen_Random_Data() {
    secret.set_random();
}

// 计算中间值 a = g^secret
void DistKeyGen::compute_a() {
    a = BLS12381Element(secret.get_message());
}

// 累加其他参与方的中间值
void DistKeyGen::sum_a(const std::vector<BLS12381Element>& as) {
    BLS12381Element a_tmp;
    a_tmp = BLS12381Element(0);
    for (const auto& ai : as) {
        a_tmp += ai;
    }
    a = a_tmp;
}

// 完成密钥生成
void DistKeyGen::finalize(ELGL_PK& pk, ELGL_SK& sk, std::vector<ELGL_PK>& b) {
    pk.assign_pk(a); // 公钥为 a
    sk.assign_sk(secret.get_message()); // 私钥为 secret
    b = pki; // 所有参与方的公钥
}

// 重载 += 操作符
DistKeyGen& DistKeyGen::operator+=(const DistKeyGen& other) {
    secret += other.secret;
    a += other.a;
    return *this;
}

// 分布式密钥生成协议
void Run_Gen_Protocol(ELGL_PK& gpk, ELGL_SK& sk, std::vector<ELGL_PK>& pks, const int n_players, const int my_num) {
    int num_players = n_players;
    std::vector<BLS12381Element> as(num_players);
    std::vector<std::stringstream> Comm_e(num_players), Open_e(num_players);

    // 初始化
    DistKeyGen key(pks);
    key.Gen_Random_Data();
    key.compute_a();
    as[my_num] = key.a;

    // 执行承诺和广播
    std::stringstream ee;
    key.a.pack(ee);
    Commit(Comm_e[my_num], Open_e[my_num], ee, my_num);
    P.Broadcast_Receive(Comm_e);
    P.Broadcast_Receive(Open_e);

    // 验证承诺并解包
    for (int i = 0; i < num_players; i++) {
        if (i != P.my_num()) {
            if (!Open(ee, Comm_e[i], Open_e[i], i)) {
                throw invalid_commitment();
            }
            as[i].unpack(ee);
        }
    }

    // 累加所有参与方的中间值
    key.sum_a(as);

    // 分配公钥给所有参与方
    for (int i = 0; i < num_players; i++) {
        key.pki[i].assign_pk(as[i]);
    }

    // 完成密钥生成
    key.finalize(gpk, sk, pks);
}