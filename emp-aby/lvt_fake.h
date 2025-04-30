#pragma once
#include "libelgl/elgl/BLS12381Element.h"
#include "emp-aby/utils.h"
#include "emp-aby/elgl_interface.hpp"
// #include "libelgl/elgl/FFT.h"
#include "libelgl/elgl/Ciphertext.h"
#include "libelgl/elgloffline/RotationProof.h"
#include "libelgl/elgloffline/RotationProver.h"
#include "libelgl/elgloffline/RotationVerifier.h"
#include "libelgl/elgloffline/Exp_proof.h"
#include "libelgl/elgloffline/Exp_prover.h"
#include "libelgl/elgloffline/Exp_verifier.h"

#include "libelgl/elgloffline/Range_Proof.h"
#include "libelgl/elgloffline/Range_Prover.h"
#include "libelgl/elgloffline/Range_Verifier.h"
#include "libelgl/elgl/FFT_Para_Optimized.hpp"
#include "emp-aby/BSGS.hpp"
#include "emp-aby/P2M.hpp"
// #include "libelgl/elgl/FFT_Para_AccelerateCompatible.hpp"

const int thread_num = 8;
// #include "cmath"
// #include <poll.h>

namespace emp{

void deserializeTable(vector<int64_t>& table, const char* filename, size_t table_size = 1<<16) {
    ifstream inFile(filename, ios::binary);
    if (!inFile) {
        cerr << "Error: Unable to open file for reading.\n";
        return;
    }

    table.resize(table_size);  // 预分配空间
    inFile.read(reinterpret_cast<char*>(table.data()), table_size * sizeof(int64_t));

    // 计算实际读取的元素个数
    size_t elementsRead = inFile.gcount() / sizeof(int64_t);
    table.resize(elementsRead);  // 调整大小以匹配实际读取的内容

    inFile.close();
}

template <typename IO>
class LVT{
    public:
    int num_used = 0;
    ThreadPool* pool;

    ELGL<IO>* elgl;
    MPIOChannel<IO>* io;
    std::vector<Ciphertext> cr_i;
    Fr alpha;
    size_t tb_size;
    // void shuffle(Ciphertext& c, bool* rotation, size_t batch_size, size_t i);

    ELGL_PK global_pk;
    Plaintext rotation;
    std::vector<ELGL_PK> user_pk;
    vector<Plaintext> lut_share;
    vector<vector<BLS12381Element>> cip_lut;
    emp::BSGSPrecomputation bsgs;
    std::map<std::string, Fr> P_to_m;
    BLS12381Element g;
    
    int num_party;
    int party;
    vector<int64_t> table;
    LVT(int num_party, int party, MPIOChannel<IO>* io, ThreadPool* pool, ELGL<IO>* elgl, Fr& alpha, int table_size);
    LVT(int num_party, int party, MPIOChannel<IO>* io, ThreadPool* pool, ELGL<IO>* elgl, std::string tableFile, Fr& alpha, int table_size);
    void DistKeyGen();
    ~LVT();
    void generate_shares(vector<Plaintext>& lut_share, Plaintext& rotation, vector<int64_t> table);
    void lookup_online(Plaintext& out, Plaintext& x_share, Ciphertext& x_cipher, vector<Ciphertext>& x_ciphers);
    void lookup_online_easy(Plaintext& out, Plaintext& x_share, Ciphertext& x_cipher, vector<Ciphertext>& x_ciphers);
};

template <typename IO>
LVT<IO>::LVT(int num_party, int party, MPIOChannel<IO>* io, ThreadPool* pool, ELGL<IO>* elgl, Fr& alpha, int table_size){
    this->io = io;
    this->party = party;
    this->num_party = num_party;
    this->alpha = alpha;
    this->pool = pool;
    this->elgl = elgl;
    this->user_pk.resize(num_party);
    this->user_pk[party-1] = elgl->kp.get_pk();
    this->tb_size = 1 << table_size;
    this->cip_lut.resize(num_party);
    this->cr_i.resize(num_party);
    this->lut_share.resize(tb_size);
    BLS12381Element::init();
    BLS12381Element g = BLS12381Element::generator();
    // bsgs.precompute(g, 1ULL << 32);
}

void build_safe_P_to_m(std::map<std::string, Fr>& P_to_m, int num_party, size_t tb_size) {
    size_t max_exponent = 2 * tb_size * num_party;
    
    // // 如果表较小，直接计算
    // if (max_exponent <= 1<<8) {
    //     // 测试时间
    //     // auto start_time = chrono::high_resolution_clock::now();
    //     cout << "开始构建大小为" << max_exponent << "的P_to_m表..." << endl;
    //     for (size_t i = 0; i <= max_exponent; ++i) {
    //         BLS12381Element g_i(i);
    //         P_to_m[g_i.getPoint().getStr()] = Fr(to_string(i));
    //     }
    //     cout << "P_to_m表构建完成" << endl;
    //     // auto end_time = chrono::high_resolution_clock::now();
    //     // auto duration = chrono::duration_cast<chrono::milliseconds>(end_time - start_time);
    //     // cout << "构建表用时: " << duration.count() << " 毫秒" << endl;
    //     return;
    // }
    
    // 如果表较大，尝试读取文件
    // auto start_time = chrono::high_resolution_clock::now();
    cout << "开始读取P_to_m表..." << endl;
    const char* filename = "P_to_m_table.bin";
    deserialize_P_to_m(P_to_m, filename);
    cout << "P_to_m表读取完成" << endl;
    // auto end_time = chrono::high_resolution_clock::now();
    // auto duration = chrono::duration_cast<chrono::milliseconds>(end_time - start_time);
    // cout << "读取表用时: " << duration.count() << " 毫秒" << endl;
    
    // 如果文件不存在或读取失败，则计算并保存
    if (P_to_m.empty()) {
        cout << "P_to_m表为空，开始计算..." << endl;
        for (size_t i = 0; i <= max_exponent; ++i) {
            BLS12381Element g_i(i);
            P_to_m[g_i.getPoint().getStr()] = Fr(i);
        }
        serialize_P_to_m(P_to_m, filename);
        cout << "P_to_m表计算完成" << endl;
    }
}

template <typename IO>
LVT<IO>::LVT(int num_party, int party, MPIOChannel<IO>* io, ThreadPool* pool, ELGL<IO>* elgl, string tableFile, Fr& alpha, int table_size)
    : LVT(num_party, party, io, pool, elgl, alpha, table_size) {
    // load table from file
    deserializeTable(table, tableFile.c_str(), tb_size);
    // cout << "table size: " << tb_size << endl;
    if (tb_size <= 65536) build_safe_P_to_m(P_to_m, num_party, tb_size);

    uint64_t N = 1ULL << 38; // 32-bit空间
    try {
        // auto start_time = chrono::high_resolution_clock::now();
        std::cout << "开始加载bsgs表..." << std::endl;
        bsgs.deserialize("bsgs_table.bin");
        cout << "bsgs表加载完成" << endl;
        
        // auto end_time = chrono::high_resolution_clock::now();
        // auto duration = chrono::duration_cast<chrono::milliseconds>(end_time - start_time);
        // cout << "读取表用时: " << duration.count() << " 毫秒" << endl;
        // std::cout << "成功加载预计算数据" << std::endl;
    } catch (const std::exception& e) {
        std::cout << "bsgs预计算数据不存在或损坏，开始预计算..." << std::endl;
        // auto start_time = chrono::high_resolution_clock::now();
        bsgs.precompute(g, N);
        // auto end_time = chrono::high_resolution_clock::now();
        // auto duration = chrono::duration_cast<chrono::milliseconds>(end_time - start_time);
        // cout << "预计算用时: " << duration.count() << " 毫秒" << endl;
        // std::cout << "预计算完成，保存到文件..." << std::endl;
        bsgs.serialize("bsgs_table.bin");
        cout << "bsgs表保存完成" << endl;
    }
}

template <typename IO>
void LVT<IO>::generate_shares(vector<Plaintext>& lut_share, Plaintext& rotation, vector<int64_t> table) {
    vector<std::future<void>> res;
    mcl::Vint bound;
    bound.setStr(to_string(tb_size));
    lut_share.resize(tb_size);
    cip_lut.resize(num_party);
    for (int i = 0; i < num_party; i++) {
        cip_lut[i].resize(tb_size);
    }
    // 每个party选取rotation
    rotation.set_message(1);
    Ciphertext my_rot_cipher = global_pk.encrypt(rotation);
    elgl->serialize_sendall(my_rot_cipher);
    for (int i = 1; i <= num_party; ++i) {
        res.emplace_back(pool->enqueue([this, &my_rot_cipher, i]() {
            if (i == party){
                this->cr_i[party-1] = my_rot_cipher;
            }else{
                Ciphertext other_rot_cipher;
                elgl->deserialize_recv(other_rot_cipher, i);
                this->cr_i[i-1] = other_rot_cipher;
            }
        }));
    }
    for (auto & f : res) f.get();
    res.clear();

    int64_t t1 = table[0];
    size_t rotate_sum = num_party;
    // cout << "rotate_sum = " << rotate_sum << endl;
    cr_i[party-1] = global_pk.encrypt(rotation);
    elgl->serialize_sendall(cr_i[party-1]);
    for (size_t i = 0; i < num_party; i++){
        if (i != (party-1)){
            Ciphertext other_rot_cipher;
            elgl->deserialize_recv(other_rot_cipher, i+1);
            this->cr_i[i] = other_rot_cipher;
        }
    }

    for (size_t i = 0; i < tb_size; i++){
        lut_share[i].set_message(table[(i - rotate_sum) % tb_size]);
        if (party == 1){
            int64_t tmp = (lut_share[i].get_message().getInt64() - ((num_party - 1) * t1)) % tb_size;
            lut_share[i].set_message(tmp);
            // cout << "lut_share[" << i << "] = " << lut_share[i].get_message().getInt64() << endl;
        }
        else {
            lut_share[i].set_message(t1);
            // cout << "lut_share[" << i << "] = " << lut_share[i].get_message().getInt64() << endl;
        }
        cip_lut[party-1][i] = g * lut_share[i].get_message().getInt64() + global_pk.get_pk() * elgl->kp.get_sk().get_sk();
    }

    std::stringstream cip_lut_;
    for (size_t i = 0; i < tb_size; i++){
        cip_lut[party-1][i].pack(cip_lut_);
    }
    std::stringstream cip;
    std::string cip_raw = cip_lut_.str();
    cip << base64_encode(cip_raw);
    elgl->serialize_sendall_(cip);

    for (size_t i = 1; i <= num_party; i++){
        if (i != party){
            std::stringstream cip_;
            std::string cip_raw_;
            std::stringstream cip_b64;
            elgl->deserialize_recv_(cip_, i);
            cip_raw_ = cip_.str();
            cip_b64 << base64_decode(cip_raw_);
            for (size_t j = 0; j < tb_size; j++){
                cip_lut[i-1][j].unpack(cip_b64);
            }
        }
    }
}

template <typename IO>
void LVT<IO>::DistKeyGen(){
    // first broadcast my own pk
    vector<std::future<void>> tasks;
    global_pk = elgl->kp.get_pk();
    elgl->serialize_sendall(global_pk);
    for (size_t i = 1; i <= num_party; i++){
        if (i != party){
            tasks.push_back(pool->enqueue([this, i](){
                // rcv other's pk
                ELGL_PK pk;
                elgl->deserialize_recv(pk, i);
                this->user_pk[i-1] = pk;
            }));
        }
    }
    for (auto & task : tasks) {
        task.get();
    }
    tasks.clear();
    // cal global pk_
    BLS12381Element global_pk_ = BLS12381Element(0);
    for (auto& pk : user_pk){
        global_pk_ += pk.get_pk();
    }
    global_pk.assign_pk(global_pk_);
}

template <typename IO>
Fr threshold_decrypt(Ciphertext& c, ELGL<IO>* elgl, const ELGL_PK& global_pk, const std::vector<ELGL_PK>& user_pks, MPIOChannel<IO>* io, ThreadPool* pool, int party, int num_party, std::map<std::string, Fr>& P_to_m, LVT<IO>* lvt) {
    // 第一部分保持不变
    Plaintext sk(elgl->kp.get_sk().get_sk());
    BLS12381Element ask = c.get_c0() * sk.get_message();
    std::vector<BLS12381Element> ask_parts(num_party);
    ask_parts[party - 1] = ask;

    ExpProof exp_proof(global_pk);
    ExpProver exp_prover(exp_proof);
    ExpVerifier exp_verifier(exp_proof);

    std::stringstream commit, response;
    BLS12381Element g1 = c.get_c0();
    BLS12381Element y1 = elgl->kp.get_pk().get_pk();
    exp_prover.NIZKPoK(exp_proof, commit, response, g1, y1, ask, sk, party, pool);

    std::stringstream commit_b64, response_b64;
    commit_b64 << base64_encode(commit.str());
    response_b64 << base64_encode(response.str());

    elgl->serialize_sendall_(commit_b64);
    elgl->serialize_sendall_(response_b64);

    // 并行化处理验证过程
    std::vector<std::future<void>> verify_futures;
    for (int i = 1; i <= num_party; ++i) {
        if (i != party) {
            verify_futures.push_back(pool->enqueue([i, &party, global_pk, elgl, &ask_parts, &g1, &user_pks, pool]() {
                ExpProof exp_proof(global_pk);
                std::stringstream local_commit_stream, local_response_stream;

                elgl->deserialize_recv_(local_commit_stream, i);
                elgl->deserialize_recv_(local_response_stream, i);

                std::string comm_raw = local_commit_stream.str();
                std::string resp_raw = local_response_stream.str();

                local_commit_stream.str("");
                local_commit_stream.clear();
                local_commit_stream << base64_decode(comm_raw);
                local_commit_stream.seekg(0);

                local_response_stream.str("");
                local_response_stream.clear();
                local_response_stream << base64_decode(resp_raw);
                local_response_stream.seekg(0);

                BLS12381Element y1_other = user_pks[i - 1].get_pk();
                BLS12381Element ask_i;
                ExpVerifier exp_verifier(exp_proof);
                exp_verifier.NIZKPoK(g1, y1_other, ask_i, local_commit_stream, local_response_stream, pool, i);
                ask_parts[i - 1] = ask_i;
            }));
        }
    }
    for (auto& fut : verify_futures) fut.get();
    verify_futures.clear();


    BLS12381Element pi_ask = c.get_c1();
    for (auto& ask_i : ask_parts) {
        pi_ask -= ask_i;
    }

    std::string key = pi_ask.getPoint().getStr();
    Fr y;
    if(lvt->tb_size <= 131072) {
        auto it = P_to_m.find(key);
        if (it == P_to_m.end()) {
            std::cerr << "[Error] pi_ask not found in P_to_m! pi_ask = " << key << std::endl;
            exit(1);
        }
        return it->second;
    } else {
        y = lvt->bsgs.solve_parallel_with_pool(pi_ask, pool, thread_num);
    }
    return y;
}


template <typename IO>
Fr threshold_decrypt_easy(Ciphertext& c, ELGL<IO>* elgl, const ELGL_PK& global_pk, const std::vector<ELGL_PK>& user_pks, MPIOChannel<IO>* io, ThreadPool* pool, int party, int num_party, std::map<std::string, Fr>& P_to_m, LVT<IO>* lvt) {
    // 第一部分保持不变
    Plaintext sk(elgl->kp.get_sk().get_sk());
    BLS12381Element ask = c.get_c0() * sk.get_message();
    std::vector<BLS12381Element> ask_parts(num_party);
    ask_parts[party - 1] = ask;

    std::stringstream commit;
    BLS12381Element g1 = c.get_c0();
    BLS12381Element y1 = elgl->kp.get_pk().get_pk();
    ask.pack(commit);

    std::stringstream commit_b64;
    commit_b64 << base64_encode(commit.str());
    elgl->serialize_sendall_(commit_b64);

    // 并行化处理验证过程
    std::vector<std::future<void>> verify_futures;
    for (int i = 1; i <= num_party; ++i) {
        if (i != party) {
            verify_futures.push_back(pool->enqueue([i, &party, global_pk, elgl, &ask_parts, &g1, &user_pks, pool]() {
                std::stringstream local_commit_stream;

                elgl->deserialize_recv_(local_commit_stream, i);
                std::string comm_raw = local_commit_stream.str();

                local_commit_stream.str("");
                local_commit_stream.clear();
                local_commit_stream << base64_decode(comm_raw);
                local_commit_stream.seekg(0);

                ask_parts[i - 1].unpack(local_commit_stream);
                BLS12381Element y1_other = user_pks[i - 1].get_pk();
            }));
        }
    }
    for (auto& fut : verify_futures) fut.get();
    verify_futures.clear();

    BLS12381Element pi_ask = c.get_c1();
    for (auto& ask_i : ask_parts) {
        pi_ask -= ask_i;
    }

    std::string key = pi_ask.getPoint().getStr();
    Fr y;
    y = lvt->bsgs.solve_parallel_with_pool(pi_ask, pool, thread_num);
    return y;
}

template <typename IO>
void LVT<IO>::lookup_online(Plaintext& out, Plaintext& x_share, Ciphertext& x_cipher, vector<Ciphertext>& x_ciphers){
    // cout << "party: " << party << " x_share = " << x_share.get_message().getStr() << endl;
    vector<std::future<void>> res;
    vector<Plaintext> u_shares;

    x_ciphers.resize(num_party);
    u_shares.resize(num_party);

    x_ciphers[party-1] = x_cipher;
    u_shares[party-1] = x_share + this->rotation;

    // accept cipher from all party
    for (size_t i = 1; i <= num_party; i++){
        res.push_back(pool->enqueue([this, i, &x_ciphers, &u_shares](){
            if (i != party){
                Ciphertext x_cip;
                elgl->deserialize_recv(x_cip, i);
                Plaintext u_share;
                elgl->deserialize_recv(u_share, i);
                x_ciphers[i-1] = x_cip;
                u_shares[i-1] = u_share;
            }
        }));
    }
    elgl->serialize_sendall(x_cipher, party);
    elgl->serialize_sendall(u_shares[party-1], party);
    for (auto& v : res)
        v.get();
    res.clear();

    Ciphertext c = x_ciphers[0] + cr_i[0];
    Plaintext uu = u_shares[0];
    for (size_t i=1; i<num_party; i++){
        c +=  x_ciphers[i] + cr_i[i];
        uu += u_shares[i];
    }
    // uu mod tb_size
    mcl::Vint h;
    h.setStr(to_string(tb_size));
    mcl::Vint q1 = uu.get_message().getMpz();
    mcl::gmp::mod(q1, q1, h);
    uu.assign(q1.getStr());

    Fr u = threshold_decrypt(c, elgl, global_pk, user_pk, elgl->io, pool, party, num_party, P_to_m, this);
    // u mod tb_size
    mcl::Vint q2 = u.getMpz(); 
    mcl::gmp::mod(q2, q2, h);
    u.setStr(q2.getStr());
    
    if (u != uu.get_message()){
        cout << "u = " << u.getStr() << endl;
        cout << "uu = " << uu.get_message().getStr() << endl;
        cout << "error: in online lookup" << endl;
        exit(1);
    }
    
    // Fr uu_ = uu.get_message();
    // std::cout << "u = " << u.getStr() << std::endl;

    // u mod table size
    mcl::Vint tbs;
    tbs.setStr(to_string(tb_size));
    mcl::Vint u_mpz = u.getMpz(); 
    mcl::gmp::mod(u_mpz, u_mpz, tbs);
    // std::cout << "masked lookup index: " << u_mpz.getStr() << std::endl;

    mcl::Vint index_mpz;
    index_mpz.setStr(u_mpz.getStr());
    size_t index = static_cast<size_t>(index_mpz.getLow32bit());
    out = lut_share[index];

    // cout << endl << "table" << endl;
    // for (size_t i = 0; i < tb_size; i++){
    //     Fr t = lut_share[i].get_message();
    //     cout << "table[" << i << "] = " << t.getStr() << endl;
    // }
    // std::cout << "T[x]_share for party " << party << ": " << out.get_message().getStr() << endl;

    // send done
    
}

template <typename IO>
void LVT<IO>::lookup_online_easy(Plaintext& out, Plaintext& x_share, Ciphertext& x_cipher, vector<Ciphertext>& x_ciphers){
    // cout << "party: " << party << " x_share = " << x_share.get_message().getStr() << endl;
    vector<std::future<void>> res;
    vector<Plaintext> u_shares;

    x_ciphers.resize(num_party);
    u_shares.resize(num_party);

    x_ciphers[party-1] = x_cipher;
    u_shares[party-1] = x_share + this->rotation;

    // accept cipher from all party
    for (size_t i = 1; i <= num_party; i++){
        res.push_back(pool->enqueue([this, i, &x_ciphers, &u_shares](){
            if (i != party){
                Ciphertext x_cip;
                elgl->deserialize_recv(x_cip, i);
                Plaintext u_share;
                elgl->deserialize_recv(u_share, i);
                x_ciphers[i-1] = x_cip;
                u_shares[i-1] = u_share;
            }
        }));
    }
    elgl->serialize_sendall(x_cipher, party);
    elgl->serialize_sendall(u_shares[party-1], party);
    for (auto& v : res)
        v.get();
    res.clear();

    Ciphertext c = x_ciphers[0] + cr_i[0];
    Plaintext uu = u_shares[0];
    for (size_t i=1; i<num_party; i++){
        c +=  x_ciphers[i] + cr_i[i];
        uu += u_shares[i];
    }
    // uu mod tb_size
    mcl::Vint h;
    h.setStr(to_string(tb_size));
    mcl::Vint q1 = uu.get_message().getMpz();
    mcl::gmp::mod(q1, q1, h);
    uu.assign(q1.getStr());

    Fr u = threshold_decrypt_easy(c, elgl, global_pk, user_pk, elgl->io, pool, party, num_party, P_to_m, this);
    // u mod tb_size
    mcl::Vint q2 = u.getMpz(); 
    mcl::gmp::mod(q2, q2, h);
    u.setStr(q2.getStr());
    
    if (u != uu.get_message()){
        cout << "u = " << u.getStr() << endl;
        cout << "uu = " << uu.get_message().getStr() << endl;
        cout << "error: in online lookup" << endl;
        exit(1);
    }
    
    // Fr uu_ = uu.get_message();
    // std::cout << "u = " << u.getStr() << std::endl;

    // u mod table size
    mcl::Vint tbs;
    tbs.setStr(to_string(tb_size));
    mcl::Vint u_mpz = u.getMpz(); 
    mcl::gmp::mod(u_mpz, u_mpz, tbs);
    // std::cout << "masked lookup index: " << u_mpz.getStr() << std::endl;

    mcl::Vint index_mpz;
    index_mpz.setStr(u_mpz.getStr());
    size_t index = static_cast<size_t>(index_mpz.getLow32bit());
    out = lut_share[index];

    // cout << endl << "table" << endl;
    // for (size_t i = 0; i < tb_size; i++){
    //     Fr t = lut_share[i].get_message();
    //     cout << "table[" << i << "] = " << t.getStr() << endl;
    // }
    // std::cout << "T[x]_share for party " << party << ": " << out.get_message().getStr() << endl;

    // send done
    
}


template <typename IO>
LVT<IO>::~LVT(){
}

}

void serializeTable(vector<int64_t>& table, const char* filename, size_t table_size = 1<<16) {
    if (table.size() > table_size) {
        cerr << "Error: Table size exceeds the given limit.\n";
        return;
    }

    ofstream outFile(filename, ios::binary);
    if (!outFile) {
        cerr << "Error: Unable to open file for writing.\n";
        return;
    }

    outFile.write(reinterpret_cast<const char*>(table.data()), table.size() * sizeof(int64_t));
    outFile.close();
}