#pragma once

#include "lvt.h"
#include "emp-tool/emp-tool.h"
#include <vector>
#include <map>
#include <string>
#include <sstream>
#include <future>
#include <thread>
#include <random>
#include <fstream>
#include <filesystem>
#include <cstdlib>

namespace emp {

// 定义分享结构
struct LVTShare {
    Fr plain_share;  // 明文分享
    Ciphertext cipher_share;  // 密文分享
};

template <typename IO>
class LVTShareProtocol {
private:
    ThreadPool* pool;
    MPIOChannel<IO>* io;
    ELGL<IO>* elgl;
    int party;
    int num_party;
    ELGL_PK global_pk;
    std::vector<ELGL_PK> user_pk;
    std::map<std::string, Fr> P_to_m;

public:
    LVTShareProtocol(int num_party, int party, MPIOChannel<IO>* io, ThreadPool* pool, ELGL<IO>* elgl) {
        this->io = io;
        this->party = party;
        this->num_party = num_party;
        this->pool = pool;
        this->elgl = elgl;
        this->user_pk.resize(num_party);
        this->user_pk[party-1] = elgl->kp.get_pk();
        BLS12381Element::init();
    }

    // 生成LVT分享
    std::vector<LVTShare> generate_share(const Fr& secret) {
        std::vector<LVTShare> shares(num_party);
        
        // 生成加性分享
        std::vector<Fr> plain_shares(num_party);
        Fr sum = Fr(0);
        for (int i = 0; i < num_party - 1; ++i) {
            plain_shares[i].setRand();
            sum += plain_shares[i];
        }
        plain_shares[num_party - 1] = secret - sum;
        
        // 为每个分享生成密文
        for (int i = 0; i < num_party; ++i) {
            shares[i].plain_share = plain_shares[i];
            shares[i].cipher_share = elgl->encrypt(plain_shares[i]);
        }
        
        return shares;
    }

    // 分享的加法操作
    LVTShare add_shares(const LVTShare& a, const LVTShare& b) {
        LVTShare result;
        result.plain_share = a.plain_share + b.plain_share;
        result.cipher_share = a.cipher_share + b.cipher_share;
        return result;
    }

    // 分享的标量乘法
    LVTShare scalar_mul_share(const LVTShare& share, const Fr& scalar) {
        LVTShare result;
        result.plain_share = share.plain_share * scalar;
        BLS12381Element tmp1, tmp2;
        tmp1 = share.cipher_share.get_c0() * scalar;
        tmp2 = share.cipher_share.get_c1() * scalar;
        result.cipher_share = Ciphertext(tmp1, tmp2);
        return result;
    }

    // 打开分享（所有参与方需要交换他们的分享）
    Fr open_share(const std::vector<LVTShare>& shares) {
        return threshold_decrypt_lvt(shares[0].cipher_share, elgl, global_pk, user_pk, io, pool, party, num_party, P_to_m);
    }

    // 保存分享到文件
    void save_shares_to_file(const std::vector<LVTShare>& shares, const std::string& folder) {
        std::filesystem::create_directory(folder);
        
        for (size_t i = 0; i < shares.size(); ++i) {
            std::ofstream file(folder + "/share_P" + std::to_string(i) + ".dat");
            file << shares[i].plain_share.getStr() << "\n";
            BLS12381Element c0 = shares[i].cipher_share.get_c0();
            BLS12381Element c1 = shares[i].cipher_share.get_c1();
            file << c0.getPoint().getStr() << "\n";
            file << c1.getPoint().getStr() << "\n";
        }
    }

    // 从文件加载分享
    std::vector<LVTShare> load_shares_from_file(const std::string& folder) {
        std::vector<LVTShare> shares(num_party);
        
        for (int i = 0; i < num_party; ++i) {
            std::ifstream file(folder + "/share_P" + std::to_string(i) + ".dat");
            std::string plain_str, c0_str, c1_str;
            file >> plain_str >> c0_str >> c1_str;
            
            shares[i].plain_share.setStr(plain_str);
            
            Fr c0_fr, c1_fr;
            c0_fr.setStr(c0_str);
            c1_fr.setStr(c1_str);
            BLS12381Element c0(c0_fr);
            BLS12381Element c1(c1_fr);
            shares[i].cipher_share = Ciphertext(c0, c1);
        }
        
        return shares;
    }

    // 初始化P_to_m表
    void init_P_to_m(size_t tb_size) {
        build_safe_P_to_m(P_to_m, num_party, tb_size);
    }
};

} // namespace emp 