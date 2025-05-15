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
    BLS12381Element G_tbs;

    ELGL<IO>* elgl;
    MPIOChannel<IO>* io;
    std::vector<Ciphertext> cr_i;
    Fr alpha;
    size_t tb_size;
    size_t m_size;
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
    LVT(int num_party, int party, MPIOChannel<IO>* io, ThreadPool* pool, ELGL<IO>* elgl, Fr& alpha, int table_size, int m_bits);
    LVT(int num_party, int party, MPIOChannel<IO>* io, ThreadPool* pool, ELGL<IO>* elgl, std::string tableFile, Fr& alpha, int table_size, int m_bits);
    static void initialize(std::string name, std::string table_path, LVT<IO>*& lvt_ptr_ref, std::string instance_file, int num_party, int party, MPIOChannel<IO>* io, ThreadPool* pool, ELGL<IO>* elgl, Fr& alpha_fr, int table_size, int m_bits);
    void DistKeyGen();
    ~LVT();
    void generate_shares(vector<Plaintext>& lut_share, Plaintext& rotation, vector<int64_t> table);
    void generate_shares_fake(vector<Plaintext>& lut_share, Plaintext& rotation, vector<int64_t> table);
    tuple<Plaintext, vector<Ciphertext>> lookup_online(Plaintext& x_share, Ciphertext& x_cipher, vector<Ciphertext>& x_ciphers);
    void lookup_online_easy(Plaintext& out, Plaintext& x_share, Ciphertext& x_cipher, vector<Ciphertext>& x_ciphers);
    void save_full_state(const std::string& filename);
    void load_full_state(const std::string& filename);

    LVT(): num_party(0), party(0), io(nullptr), pool(nullptr), elgl(nullptr), alpha(Fr()), tb_size(0), m_size(0) {};
};

template <typename IO>
void LVT<IO>::save_full_state(const std::string& filename) {
    std::ofstream out(filename, std::ios::binary);
    if (!out) throw std::runtime_error("Failed to open file for writing");
    
    // Save basic parameters
    out.write(reinterpret_cast<const char*>(&num_party), sizeof(int));
    out.write(reinterpret_cast<const char*>(&party), sizeof(int));
    out.write(reinterpret_cast<const char*>(&tb_size), sizeof(size_t));
    out.write(reinterpret_cast<const char*>(&m_size), sizeof(size_t));
    
    // Save rotation directly as a binary Fr
    const Fr& rot_fr = rotation.get_message();
    out.write(reinterpret_cast<const char*>(&rot_fr), sizeof(Fr));
    
    // Save lut_share directly - all the Fr values in one batch
    for (size_t i = 0; i < tb_size; i++) {
        const Fr& fr = lut_share[i].get_message();
        out.write(reinterpret_cast<const char*>(&fr), sizeof(Fr));
    }
    
    // Save secret key
    const Fr& sk_fr = elgl->kp.get_sk().get_sk();
    out.write(reinterpret_cast<const char*>(&sk_fr), sizeof(Fr));
    
    // Save table
    size_t table_size = table.size();
    out.write(reinterpret_cast<const char*>(&table_size), sizeof(size_t));
    out.write(reinterpret_cast<const char*>(table.data()), table_size * sizeof(int64_t));
    
    // Save cip_lut efficiently - direct binary format
    for (int i = 0; i < num_party; ++i) {
        for (size_t j = 0; j < tb_size; ++j) {
            // Save each BLS12381Element in binary format
            const G1& point = cip_lut[i][j].getPoint();
            out.write(reinterpret_cast<const char*>(&point), sizeof(G1));
        }
    }
    
    // Save cr_i
    for (int i = 0; i < num_party; ++i) {
        // Save each Ciphertext in binary format
        const G1& c0 = cr_i[i].get_c0().getPoint();
        const G1& c1 = cr_i[i].get_c1().getPoint();
        out.write(reinterpret_cast<const char*>(&c0), sizeof(G1));
        out.write(reinterpret_cast<const char*>(&c1), sizeof(G1));
    }
    
    // Save global_pk
    const G1& global_point = global_pk.get_pk().getPoint();
    out.write(reinterpret_cast<const char*>(&global_point), sizeof(G1));
    
    // Save user_pk
    for (int i = 0; i < num_party; ++i) {
        const G1& user_point = user_pk[i].get_pk().getPoint();
        out.write(reinterpret_cast<const char*>(&user_point), sizeof(G1));
    }
    
    out.close();
}

template <typename IO>
void LVT<IO>::load_full_state(const std::string& filename) {
    std::ifstream in(filename, std::ios::binary);
    if (!in) throw std::runtime_error("Failed to open file for reading");
    
    // Load basic parameters
    in.read(reinterpret_cast<char*>(&num_party), sizeof(int));
    in.read(reinterpret_cast<char*>(&party), sizeof(int));
    in.read(reinterpret_cast<char*>(&tb_size), sizeof(size_t));
    in.read(reinterpret_cast<char*>(&m_size), sizeof(size_t));
    
    // Load rotation directly
    Fr rot_fr;
    in.read(reinterpret_cast<char*>(&rot_fr), sizeof(Fr));
    rotation.set_message(rot_fr);
    
    // Load lut_share directly
    lut_share.resize(tb_size);
    for (size_t i = 0; i < tb_size; i++) {
        Fr fr;
        in.read(reinterpret_cast<char*>(&fr), sizeof(Fr));
        lut_share[i].set_message(fr);
    }
    
    // Load secret key
    Fr sk_fr;
    in.read(reinterpret_cast<char*>(&sk_fr), sizeof(Fr));
    ELGL_SK key;
    key.sk = sk_fr;
    elgl->kp.sk = key;
    
    // Load table
    size_t table_size;
    in.read(reinterpret_cast<char*>(&table_size), sizeof(size_t));
    table.resize(table_size);
    in.read(reinterpret_cast<char*>(table.data()), table_size * sizeof(int64_t));
    
    // Load cip_lut efficiently
    cip_lut.resize(num_party);
    for (int i = 0; i < num_party; ++i) {
        cip_lut[i].resize(tb_size);
        for (size_t j = 0; j < tb_size; ++j) {
            G1 point;
            in.read(reinterpret_cast<char*>(&point), sizeof(G1));
            BLS12381Element elem;
            elem.point = point;
            cip_lut[i][j] = elem;
        }
    }
    
    // Load cr_i
    cr_i.resize(num_party);
    for (int i = 0; i < num_party; ++i) {
        G1 c0, c1;
        in.read(reinterpret_cast<char*>(&c0), sizeof(G1));
        in.read(reinterpret_cast<char*>(&c1), sizeof(G1));
        
        BLS12381Element e0, e1;
        e0.point = c0;
        e1.point = c1;
        cr_i[i] = Ciphertext(e0, e1);
    }
    
    // Load global_pk
    G1 global_point;
    in.read(reinterpret_cast<char*>(&global_point), sizeof(G1));
    BLS12381Element global_elem;
    global_elem.point = global_point;
    global_pk.assign_pk(global_elem);
    
    // Load user_pk
    user_pk.resize(num_party);
    for (int i = 0; i < num_party; ++i) {
        G1 user_point;
        in.read(reinterpret_cast<char*>(&user_point), sizeof(G1));
        BLS12381Element user_elem;
        user_elem.point = user_point;
        user_pk[i].assign_pk(user_elem);
    }
    
    in.close();
}



template <typename IO>
LVT<IO>::LVT(int num_party, int party, MPIOChannel<IO>* io, ThreadPool* pool, ELGL<IO>* elgl, Fr& alpha, int table_size, int m_bits){
    this->io = io;
    this->party = party;
    this->num_party = num_party;
    this->alpha = alpha;
    this->pool = pool;
    this->elgl = elgl;
    this->user_pk.resize(num_party);
    this->user_pk[party-1] = elgl->kp.get_pk();
    this->tb_size = 1ULL << table_size;
    this->m_size = 1ULL << m_bits;
    this->cip_lut.resize(num_party);
    this->cr_i.resize(num_party);
    this->lut_share.resize(tb_size);
    this->G_tbs = BLS12381Element(tb_size);
    BLS12381Element::init();
    BLS12381Element g = BLS12381Element::generator();
}

// 在类外定义initialize函数
template <typename IO>
void LVT<IO>::initialize(std::string name, std::string table_path, LVT<IO>*& lvt_ptr_ref, std::string instance_file, int num_party, int party, MPIOChannel<IO>* io, ThreadPool* pool, ELGL<IO>* elgl, Fr& alpha_fr, int table_size, int m_bits) {

    std::string tablefile = "../../build/bin/table_" + name + ".txt";
    std::string full_state_path = "../../build/cache/lvt_offline_" + std::to_string(table_size) + "-P" + std::to_string(party) + ".bin";
    lvt_ptr_ref = new LVT<IO>(num_party, party, io, pool, elgl, tablefile, alpha_fr, table_size, m_bits);
    cout << "LVT initialized" << endl;

    // 测试时间
    if (std::filesystem::exists(full_state_path)) {
        auto start = clock_start();
        lvt_ptr_ref->load_full_state(full_state_path);
        std::cout << "Loading offline time: " << std::fixed << std::setprecision(6) << time_from(start) / 1e6 << " seconds" << std::endl;
    } else {
        auto start = clock_start();
        lvt_ptr_ref->DistKeyGen();
        cout << "DistKeyGen finished" << endl;
        lvt_ptr_ref->generate_shares(lvt_ptr_ref->lut_share, lvt_ptr_ref->rotation, lvt_ptr_ref->table);
        cout << "Generate shares finished" << endl;
        lvt_ptr_ref->save_full_state(full_state_path);
        std::cout << "Generate offline time: " << std::fixed << std::setprecision(6) << time_from(start) / 1e6 << " seconds" << std::endl;
    }
}


void build_safe_P_to_m(std::map<std::string, Fr>& P_to_m, int num_party, size_t m_size) {
    size_t max_exponent = 2 * m_size * num_party;
    if (max_exponent <= 1<<8) {
        for (size_t i = 0; i <= max_exponent; ++i) {
            BLS12381Element g_i(i);
            P_to_m[g_i.getPoint().getStr()] = Fr(to_string(i));
        }
        return;
    }
    const char* filename = "P_to_m_table.bin";
    for (size_t i = 0; i <= max_exponent; ++i) {
        BLS12381Element g_i(i);
        g_i.getPoint().normalize();
        P_to_m[g_i.getPoint().getStr()] = Fr(i);
    }
    serialize_P_to_m(P_to_m, filename);
}

template <typename IO>
LVT<IO>::LVT(int num_party, int party, MPIOChannel<IO>* io, ThreadPool* pool, ELGL<IO>* elgl, string tableFile, Fr& alpha, int table_size, int m_bits)
    : LVT(num_party, party, io, pool, elgl, alpha, table_size, m_bits) {
    deserializeTable(table, tableFile.c_str(), tb_size);
    if (m_bits <= 16) {
        build_safe_P_to_m(P_to_m, num_party, m_size);
        if (m_bits == 1) return;
    }
    // cout << "m_bits > 16, using BSGS" << endl;
    uint64_t N = 1ULL << 32; // 38-bit空间
    try {
        bsgs.deserialize("bsgs_table.bin");
        cout << "BSGS table loaded successfully." << endl;
    } catch (const std::exception& e) {
        bsgs.precompute(g, N);
        bsgs.serialize("bsgs_table.bin");
    }
}

template <typename IO>
void LVT<IO>::generate_shares(vector<Plaintext>& lut_share, Plaintext& rotation, vector<int64_t> table) {
    // std::cout <<"alpha:" << alpha << std::endl;
    vector<std::future<void>> res;
    vector<BLS12381Element> c0;
    vector<BLS12381Element> c1;
    vector<BLS12381Element> c0_;
    vector<BLS12381Element> c1_;
    
    RotationProof rot_proof(global_pk, global_pk, tb_size);
    RotationVerifier Rot_verifier(rot_proof);
    RotationProver Rot_prover(rot_proof);

    mcl::Vint bound;
    bound.setStr(to_string(tb_size));
    RangeProof Range_proof(global_pk, bound, tb_size);
    RangeVerifier Range_verifier(Range_proof);
    RangeProver Range_prover(Range_proof);

    c0.resize(tb_size);
    c1.resize(tb_size);
    c0_.resize(tb_size);
    c1_.resize(tb_size);
    ELGL_SK sbsk;
    ELGL_SK twosk;

    rotation.set_random(bound);
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
    for (auto & f : res) {
        f.get();
    }
    res.clear();
    
    if (party == ALICE) {
        // encrypt the table
        
        std::stringstream comm, response, encMap;
        //time
        auto start = std::chrono::high_resolution_clock::now();
        elgl->DecProof(global_pk, comm, response, encMap, this->table, tb_size, c0, c1, pool);

        // print comm response encMap

        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> elapsed = end - start;
        // std::cout << "DecProof time: " << elapsed.count() << " seconds" << std::endl;
        // print comm response encMap
        std::stringstream comm_, response_, encMap_;        
        std::string comm_raw = comm.str();
        // time encode and send
        start = std::chrono::high_resolution_clock::now();
        comm_ << base64_encode(comm_raw);
        std::string response_raw = response.str();
        response_ << base64_encode(response_raw);
        std::string encMap_raw = encMap.str();
        encMap_ << base64_encode(encMap_raw);

        elgl->serialize_sendall_(response_);
        elgl->serialize_sendall_(comm_);
        elgl->serialize_sendall_(encMap_);
        // time encode and send
        end = std::chrono::high_resolution_clock::now();
        elapsed = end - start;
        // std::cout << "encode and send time: " << elapsed.count() << " seconds" << std::endl;
    }else{
        std::stringstream comm, response, encMap;
        std::string comm_raw, response_raw, encMap_raw;
        std::stringstream comm_, response_, encMap_;
        // time receive and decode
        auto start = std::chrono::high_resolution_clock::now();
        elgl->deserialize_recv_(response, ALICE);
        elgl->deserialize_recv_(comm, ALICE);
        elgl->deserialize_recv_(encMap, ALICE);
        comm_raw = comm.str();
        comm_ << base64_decode(comm_raw);
        response_raw = response.str();
        response_ << base64_decode(response_raw);
        encMap_raw = encMap.str();
        encMap_ << base64_decode(encMap_raw);
        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> elapsed = end - start;
        // std::cout << "receive and decode time: " << elapsed.count() << " seconds" << std::endl;

        // time verify
        start = std::chrono::high_resolution_clock::now();
        elgl->DecVerify(global_pk, comm_, response_, encMap_, c0, c1, tb_size, pool);
        end = std::chrono::high_resolution_clock::now();
        elapsed = end - start;
        // std::cout << "DecVerify time: " << elapsed.count() << " seconds" << std::endl;
    }

    // // decrypt c0,c1
    // for (size_t i = 0; i < tb_size; i++){
    //     Ciphertext cc(c0[i],c1[i]);
    //     Fr u = threshold_decrypt(cc, elgl, global_pk, user_pk, elgl->io, pool, party, num_party, P_to_m, this);
    //     cout << "u: " << u.getStr() << endl;
    // }

    vector<BLS12381Element> ak;
    vector<BLS12381Element> bk;
    vector<BLS12381Element> dk;
    vector<BLS12381Element> ek;
    ak.resize(tb_size);
    bk.resize(tb_size);
    dk.resize(tb_size);
    ek.resize(tb_size);
    mcl::Unit N(tb_size);
    // time fft
    auto start = std::chrono::high_resolution_clock::now();
    res.push_back(pool->enqueue(
        [this, &c0, &ak, N]()
        {
            FFT_Para(c0, ak, this->alpha, N);     
        }
    ));
    res.push_back(pool->enqueue(
        [this, &c1, &bk, N]()
        {
            FFT_Para(c1, bk, this->alpha, N);
        }
    ));
    for (auto& f : res) {
        f.get();
    }
    res.clear();
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    // std::cout << "FFT time: " << elapsed.count() << " seconds" << std::endl;
    
    if (party == ALICE)
    {
        Plaintext beta;
        vector<Plaintext> betak;
        betak.resize(tb_size);

        Plaintext::pow(beta, alpha, rotation);
        vector<Plaintext> sk;
        sk.resize(tb_size);
        for (size_t i = 0; i < tb_size; i++){
            sk[i].set_random();
        }
        // time this part
        auto start = std::chrono::high_resolution_clock::now();
        // for (size_t i = 0; i < tb_size; i++){
        //     if (i==0) {betak[i].assign(1);}
        //     else {betak[i] = betak[i - 1] * beta;}}

        for (size_t i = 0; i < tb_size; i++){
            res.push_back(pool->enqueue(
                [this, i, &dk, &ek, &sk, &ak, &bk, &beta]()
                {
                    Plaintext betak_;
                    Plaintext i_;
                    i_.assign(to_string(i));
                    Plaintext::pow(betak_, beta, i_);
                    dk[i] = BLS12381Element(1) * sk[i].get_message();
                    dk[i] += ak[i] * betak_.get_message();
                    // e_k = bk ^ betak * h^sk
                    ek[i] = global_pk.get_pk() * sk[i].get_message();
                    ek[i] += bk[i] * betak_.get_message();
                }
            ));
        }
        for (auto& f : res) {
            f.get();
        }
        res.clear();
        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> elapsed = end - start;
        // std::cout << "dk ek time: " << elapsed.count() << " seconds" << std::endl;
        // time prove
        start = std::chrono::high_resolution_clock::now();
        std::stringstream commit_ro, response_ro;
        Rot_prover.NIZKPoK(rot_proof, commit_ro, response_ro, global_pk, global_pk, dk, ek, ak, bk, beta, sk, pool);
        end = std::chrono::high_resolution_clock::now();
        elapsed = end - start;
        // std::cout << "NIZKPoK time: " << elapsed.count() << " seconds" << std::endl;
        // time prove and encode
        start = std::chrono::high_resolution_clock::now();
        std::stringstream comm_ro_, response_ro_;        
        std::string comm_raw = commit_ro.str();
        comm_ro_ << base64_encode(comm_raw);
        std::string response_raw = response_ro.str();
        response_ro_ << base64_encode(response_raw);

        elgl->serialize_sendall_(comm_ro_);
        elgl->serialize_sendall_(response_ro_);
        // time prove and encode
        end = std::chrono::high_resolution_clock::now();
        elapsed = end - start;
        // std::cout << "prove and encode time: " << elapsed.count() << " seconds" << std::endl;
    }
    
    for (size_t i = 1; i <= num_party -1; i++){
        size_t index = i - 1;
        if (i == party) {
            continue;
        }else{
            res.push_back(pool->enqueue([this, i, index, &c0, &c1, &dk, &ek, &Rot_prover,&rot_proof, &Rot_verifier, &rotation]()
            {
                vector<BLS12381Element> ak_thread;
                vector<BLS12381Element> bk_thread;
                vector<BLS12381Element> dk_thread;
                vector<BLS12381Element> ek_thread;
                ak_thread.resize(tb_size);
                bk_thread.resize(tb_size);
                dk_thread.resize(tb_size);
                ek_thread.resize(tb_size);
                // TODO: read ciphertexts and proof
                std::stringstream comm_ro, response_ro;
                std::string comm_raw, response_raw;
                std::stringstream comm_, response_;
// time receive and decode 
                auto start = std::chrono::high_resolution_clock::now();
                elgl->deserialize_recv_(comm_ro, i);
                elgl->deserialize_recv_(response_ro, i);

                comm_raw = comm_ro.str();
                response_raw = response_ro.str();

                comm_ << base64_decode(comm_raw);
                response_ << base64_decode(response_raw);
                auto end = std::chrono::high_resolution_clock::now();
                std::chrono::duration<double> elapsed = end - start;
                // std::cout << "receive and decode time: " << elapsed.count() << " seconds" << std::endl;

                // time verify
                start = std::chrono::high_resolution_clock::now();
                Rot_verifier.NIZKPoK(dk_thread, ek_thread, ak_thread, bk_thread, comm_, response_, this->global_pk, this->global_pk, pool);
                end = std::chrono::high_resolution_clock::now();
                elapsed = end - start;
                // std::cout << "NIZKPoK verify time: " << elapsed.count() << " seconds" << std::endl;

                if (i == this->party - 1)
                {

                    // std::cout << "last party begin prove." << std::endl;
                    vector<BLS12381Element> dk_;
                    vector<BLS12381Element> ek_;
                    dk_.resize(tb_size);
                    ek_.resize(tb_size);
                    Plaintext beta;
                    Plaintext::pow(beta, alpha, rotation);
                    // betak.assign("1");
                    vector<Plaintext> sk;
                    sk.resize(tb_size);
                    // time this part
                    auto start = std::chrono::high_resolution_clock::now();
                    vector<std::future<void>> res_;
                    for (size_t i = 0; i < tb_size; i++){
                        res_.push_back(pool->enqueue(
                            [this, i, &dk_, &ek_, &sk, &ak_thread, &bk_thread, &dk_thread, &ek_thread, &beta]()
                            {
                                Plaintext betak;
                                Plaintext i_;
                                i_.assign(to_string(i));
                                Plaintext::pow(betak, beta, i_);
                                dk_[i] = dk_thread[i] * betak.get_message();
                                ek_[i] = ek_thread[i] * betak.get_message();
                                // betak *= beta;
                                // TODO: here use power function can parallel
                                sk[i].set_random();
                                dk_[i] += BLS12381Element(sk[i].get_message());
                                ek_[i] += global_pk.get_pk() * sk[i].get_message();
                            }
                        ));
                    }
                    for (auto & f : res_) {
                        f.get();
                    }
                    res_.clear();
                    auto end = std::chrono::high_resolution_clock::now();
                    std::chrono::duration<double> elapsed = end - start;
                    // std::cout << "dk ek time: " << elapsed.count() << " seconds" << std::endl;

                    std::stringstream commit_ro, response_ro;
                    // time prove
                    start = std::chrono::high_resolution_clock::now();
                    Rot_prover.NIZKPoK(rot_proof, commit_ro, response_ro, global_pk, global_pk, dk_, ek_, dk_thread, ek_thread, beta, sk, pool);
                    end = std::chrono::high_resolution_clock::now();
                    elapsed = end - start;
                    // std::cout << "NIZKPoK time: " << elapsed.count() << " seconds" << std::endl;
                    // time encode and send
                    start = std::chrono::high_resolution_clock::now();
                    std::stringstream comm_ro_final, response_ro_final; 
                    std::string comm_raw_final, response_raw_final;
                    comm_raw_final = commit_ro.str();
                    response_raw_final = response_ro.str();
                    comm_ro_final << base64_encode(comm_raw_final);
                    response_ro_final << base64_encode(response_raw_final);

                    elgl->serialize_sendall_(comm_ro_final);
                    elgl->serialize_sendall_(response_ro_final);
                    // time encode and send
                    end = std::chrono::high_resolution_clock::now();
                    elapsed = end - start;
                    // std::cout << "prove and encode time: " << elapsed.count() << " seconds" << std::endl;
                    if (this->num_party == this->party){
                        dk = dk_;
                        ek = ek_;
                    }
                }
            }));
        }
    }

    for (auto& v : res)
        v.get();
    res.clear();

    if (party != num_party){
        
        // TODO: read ciphertexts and proof
        std::stringstream comm_ro, response_ro;
        std::string comm_raw, response_raw;
        std::stringstream comm_, response_;
        
        auto start = std::chrono::high_resolution_clock::now();
        elgl->deserialize_recv_(comm_ro, num_party);
        elgl->deserialize_recv_(response_ro, num_party);
        comm_raw = comm_ro.str();
        response_raw = response_ro.str();
        comm_ << base64_decode(comm_raw);
        response_ << base64_decode(response_raw);
        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> elapsed = end - start;
        // std::cout << "receive and decode time: " << elapsed.count() << " seconds" << std::endl;
        // time verify
        start = std::chrono::high_resolution_clock::now();
        Rot_verifier.NIZKPoK(dk, ek, ak, bk, comm_, response_, global_pk, global_pk, pool);
        end = std::chrono::high_resolution_clock::now();
        elapsed = end - start;
        // std::cout << "NIZKPoK verify time: " << elapsed.count() << " seconds" << std::endl;
    }

    Plaintext alpha_inv;
    Fr alpha_inv_;
    Fr::inv(alpha_inv_, alpha);
    alpha_inv.assign(alpha_inv_.getMpz());
    Fr N_inv;
    Fr::inv(N_inv, N);
    start = std::chrono::high_resolution_clock::now();
    res.push_back(pool->enqueue(
        [this, &dk, &c0_, &N, &alpha_inv]()
        {
            FFT_Para(dk, c0_, alpha_inv.get_message(), N);
        }
    ));
    res.push_back(pool->enqueue(
        [this, &ek, &c1_, &N, &alpha_inv]()
        {
            FFT_Para(ek, c1_, alpha_inv.get_message(), N);
        }
    ));
    for (auto& f : res) {
        f.get();
    }
    res.clear();
    // FFT_Para(dk, c0_, alpha_inv.get_message(), N);
    // FFT_Para(ek, c1_, alpha_inv.get_message(), N);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start;
    // std::cout << "IFFT time: " << elapsed.count() << " seconds" << std::endl;

    for (size_t i = 0; i < tb_size; i++) {
        res.push_back(pool->enqueue([&c0_, &c1_, &N_inv, i]() {
            c0_[i] *= N_inv;
            c1_[i] *= N_inv;
        }));
    }
    for (auto& f : res) {
        f.get();
    }
    res.clear();

    // std::cout << "finish IFFT" << std::endl; 
    // cal sk0 + sk1

    if (party == ALICE) {
        vector<Plaintext> y_alice;
        vector<BLS12381Element> L;
        L.resize(tb_size);
        
        auto g = BLS12381Element::generator();
        Fr e = Fr(to_string((num_party - 1) * m_size));
        BLS12381Element base = g * e; 
        vector<BLS12381Element> l_alice(tb_size, base);
        
        vector<BLS12381Element> l_(num_party);

        // for each c_1
        for (size_t i = 2; i <= num_party; i++)
        {
            vector<BLS12381Element> y3;
            vector<BLS12381Element> y2;
            y2.resize(tb_size);
            y3.resize(tb_size);
            std::stringstream commit_ro, response_ro;
            std::string comm_raw, response_raw;
            std::stringstream comm_, response_;
            // time 
            auto start = std::chrono::high_resolution_clock::now();
            elgl->deserialize_recv_(commit_ro, i);
            elgl->deserialize_recv_(response_ro, i);
            comm_raw = commit_ro.str();
            response_raw = response_ro.str();
            comm_ << base64_decode(comm_raw);
            response_ << base64_decode(response_raw);
            auto end = std::chrono::high_resolution_clock::now();
            std::chrono::duration<double> elapsed = end - start;
            // std::cout << "receive and decode time: " << elapsed.count() << " seconds" << std::endl;
            
            BLS12381Element pk__ = user_pk[i-1].get_pk();
            // time 
            start = std::chrono::high_resolution_clock::now();
            Range_verifier.NIZKPoK(pk__, y3, y2, comm_, response_, c0_, global_pk, pool);
            end = std::chrono::high_resolution_clock::now();
            elapsed = end - start;
            // std::cout << "NIZKPoK verify time: " << elapsed.count() << " seconds" << std::endl;
            //time
            start = std::chrono::high_resolution_clock::now();
            for (size_t j = 0; j < tb_size; j++)
            {
                // xiugai
                l_alice[j] -= y2[j];
            }
            end = std::chrono::high_resolution_clock::now();
            elapsed = end - start;
            // std::cout << "l_alice time: " << elapsed.count() << " seconds" << std::endl;
            
            cip_lut[i-1] = y3;
        }
        
        for (size_t i = 0; i < tb_size; i++){
            res.push_back(pool->enqueue([&c1_, &l_alice, i]() {
                l_alice[i] += c1_[i];
            }));
        }
        for (auto& f : res) {
            f.get();
        }
        res.clear();

        cip_lut[0].resize(tb_size);
        // cal c0^-sk * l
        // time
        start = std::chrono::high_resolution_clock::now();
        bool flag = 0; 
        if(m_size <= 131072) flag = 1;
        for (size_t i = 0; i < tb_size; i++){
            // res.push_back(pool->enqueue([this, &l_alice, &c0_, &L, i, &lut_share, flag](){
                BLS12381Element Y = l_alice[i] - c0_[i] * elgl->kp.get_sk().get_sk(); 
                Y.getPoint().normalize();
                Fr y; 
                if(flag) {
                    auto it = this->P_to_m.find(Y.getPoint().getStr());
                    if (it == this->P_to_m.end()) {
                        std::cerr << "[Error] y not found in P_to_m! y = " << Y.getPoint().getStr() << std::endl;
                        exit(1);
                    } else {
                        // std::cout << "查找成功，值 = " << it->second << std::endl;
                        y = it->second;
                    }
                } else 
                {   
                    // cout << "solve_parallel_with_pool: " << i << endl;
                    y = this->bsgs.solve_parallel_with_pool(Y, pool, thread_num);
                }
                mcl::Vint r_;
                mcl::Vint y_;
                y_ = y.getMpz();
                // cout << "y_:" << y_.getStr() << endl;
                mcl::Vint ms;  
                ms.setStr(to_string(this->m_size));
                // cout << "ms" << ms.getStr() << endl;
                mcl::gmp::mod(r_, y_, ms);
                Fr r;
                r.setMpz(r_);
                lut_share[i].set_message(r);
                // cout << "party: " << party << "计算的lut_share[" << i << "] = " << lut_share[i].get_message().getStr() << endl;
                BLS12381Element l(r);
                l += c0_[i] * this->elgl->kp.get_sk().get_sk();
                L[i] = BLS12381Element(l);
                BLS12381Element pk_tmp = this->global_pk.get_pk();
                this->cip_lut[0][i] = BLS12381Element(r) + pk_tmp * this->elgl->kp.get_sk().get_sk();
            // }));
            
        }


        // for (auto & f : res) {
        //     f.get();
        // }
        // res.clear();
        
        // time
        end = std::chrono::high_resolution_clock::now();
        elapsed = end - start;
        // std::cout << "cal l time: " << elapsed.count() << " seconds" << std::endl;

        std::stringstream commit_ss, response_ss;
        std::string commit_raw, response_raw;
        std::stringstream commit_b64_, response_b64_;
        
        // time prove
        start = std::chrono::high_resolution_clock::now();
        Range_prover.NIZKPoK(Range_proof, commit_ss, response_ss, global_pk, c0_, cip_lut[0], L, lut_share, elgl->kp.get_sk().get_sk(), pool);
        end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> elapsed = end - start;

        // convert commit_ss and response_ss to base64
        // time
        start = std::chrono::high_resolution_clock::now();
        commit_raw = commit_ss.str();
        commit_b64_ << base64_encode(commit_raw);
        response_raw = response_ss.str();
        response_b64_ << base64_encode(response_raw);
        elgl->serialize_sendall_(commit_b64_);
        elgl->serialize_sendall_(response_b64_);
        // time
        end = std::chrono::high_resolution_clock::now();
        elapsed = end - start;
        // std::cout << "encode and send time: " << elapsed.count() << " seconds" << std::endl;
        // serialize d
        for (size_t i = 2; i <= num_party; i++)
         {
             res.push_back(pool->enqueue([this, i](){
                 this->elgl->wait_for(i);
             }));
         }
         for (auto& v : res)
             v.get();
         res.clear();

    }else{
        // sample x_i
        mcl::Vint bound(to_string(m_size));
        // std::stringstream l_stream;
        // std::stringstream cip_i_stream;
        std::stringstream commit_ss;
        std::stringstream response_ss;
        vector<BLS12381Element> l_1_v;
        vector<BLS12381Element> cip_v;
        // time
        auto start = std::chrono::high_resolution_clock::now();
        // 预分配向量大小，避免push_back时的重新分配
        l_1_v.resize(tb_size);
        cip_v.resize(tb_size);

        for (size_t i = 0; i < tb_size; i++) {
            // res.push_back(pool->enqueue([this, i, &lut_share, &c0_, &l_1_v, &cip_v, bound]() {
                    lut_share[i].set_random(bound);
                    // cout << "party: " << party << "选取的lut_share[" << i << "] = " << lut_share[i].get_message().getStr() << endl;
                    BLS12381Element l_1, cip_;
                    l_1 = BLS12381Element(lut_share[i].get_message());
                    l_1 += c0_[i] * this->elgl->kp.get_sk().get_sk();
                    l_1_v[i] = l_1;  

                    cip_ = BLS12381Element(lut_share[i].get_message());
                    cip_ += this->global_pk.get_pk() * this->elgl->kp.get_sk().get_sk();
                    cip_v[i] = cip_;  
            // }));
        }
        // for (auto& f : res) {
        //     f.get();
        // }
        // res.clear();
        // time
        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> elapsed = end - start;
        // std::cout << "cal l_1 and cip_i time: " << elapsed.count() << " seconds" << std::endl;
        cip_lut[party-1] = cip_v;

        // time prove
        start = std::chrono::high_resolution_clock::now();
        Range_prover.NIZKPoK(Range_proof, commit_ss, response_ss, global_pk, c0_, cip_v, l_1_v, lut_share, elgl->kp.get_sk().get_sk(), pool);
        end = std::chrono::high_resolution_clock::now();
        elapsed = end - start;
        // std::cout << "NIZKPoK prove time: " << elapsed.count() << " seconds" << std::endl;
        
        // convert comit_ss and response_ss to base64
        // time
        start = std::chrono::high_resolution_clock::now();
        std::stringstream commit_ra_, response_ra_;
        std::string commit_raw = commit_ss.str();
        commit_ra_ << base64_encode(commit_raw);
        std::string response_raw = response_ss.str();
        response_ra_ << base64_encode(response_raw);
        // sendall
        elgl->serialize_sendall_(commit_ra_);
        elgl->serialize_sendall_(response_ra_);
        // time
        end = std::chrono::high_resolution_clock::now();
        elapsed = end - start;
        // std::cout << "encode and send time: " << elapsed.count() << " seconds" << std::endl;

        // receive all others commit and response
        for (size_t i = 2; i <= num_party; i++){
            if (i != party)
            {
                vector<BLS12381Element> y3;
                vector<BLS12381Element> y2;
                y3.resize(tb_size);
                y2.resize(tb_size);
                std::stringstream commit_ro, response_ro;
                std::string comm_raw, response_raw;
                std::stringstream comm_, response_;
                elgl->deserialize_recv_(commit_ro, i);
                elgl->deserialize_recv_(response_ro, i);
                comm_raw = commit_ro.str();
                response_raw = response_ro.str();
                comm_ << base64_decode(comm_raw);
                response_ << base64_decode(response_raw);
                BLS12381Element pk__ = user_pk[i-1].get_pk();
                Range_verifier.NIZKPoK(pk__, y3, y2, comm_, response_, c0_, global_pk, pool);
                cip_lut[i-1] = y3;
            }
        }

        // accept broadcast from alice
        start = std::chrono::high_resolution_clock::now();
        std::stringstream commit_ro, response_ro;
        std::string comm_raw_, response_raw_;
        std::stringstream comm_, response_;
        elgl->deserialize_recv_(commit_ro, ALICE);
        elgl->deserialize_recv_(response_ro, ALICE);
        comm_raw_ = commit_ro.str();
        response_raw_ = response_ro.str();
        comm_ << base64_decode(comm_raw_);
        response_ << base64_decode(response_raw_);
        vector<BLS12381Element> y2;
        vector<BLS12381Element> y3;
        y2.resize(tb_size);
        y3.resize(tb_size);
        BLS12381Element pk__ = user_pk[0].get_pk();
        Range_verifier.NIZKPoK(pk__, y3, y2, comm_, response_, c0_, global_pk, pool);
        cip_lut[0] = y3;
        elgl->send_done(ALICE);
        // time
        end = std::chrono::high_resolution_clock::now();
        elapsed = end - start;
        // std::cout << "receive and decode time: " << elapsed.count() << " seconds" << std::endl;
    }

    // // print rotation and party id
    // std::cout << "party: " << party << ";  rotation: " << rotation.get_message().getStr() << std::endl;
    // // print lut_share
    // for (size_t i = 0; i < tb_size; i++){
    //     std::cout << "table[" << i << "]:" << lut_share[i].get_message().getStr() << " " << std::endl;
    // }
}

template <typename IO>
void LVT<IO>::generate_shares_fake(vector<Plaintext>& lut_share, Plaintext& rotation, vector<int64_t> table) {
    lut_share.resize(tb_size);
    cip_lut.resize(num_party, vector<BLS12381Element>(tb_size));
    for (int i = 0; i < num_party; ++i) {
        cip_lut[i].resize(tb_size);
    }

    // Step 1: rotation 固定为 0
    rotation.set_message(0);

    // Step 2: 计算本地 LUT share 和加密 LUT
    vector<future<void>> res;
    BLS12381Element tmp = global_pk.get_pk() * elgl->kp.get_sk().get_sk();

    size_t block_size = (tb_size + thread_num - 1) / thread_num;
    for (int t = 0; t < thread_num; ++t) {
        size_t start = t * block_size;
        size_t end = std::min(tb_size, start + block_size);
        res.push_back(pool->enqueue([this, &lut_share, &table, tmp, start, end]() {
            for (size_t i = start; i < end; ++i) {
                if (party == 1) {
                    lut_share[i].set_message(table[i]);
                    cip_lut[party - 1][i] = g * lut_share[i].get_message() + tmp;
                } else {
                    lut_share[i].set_message(0);
                    cip_lut[party - 1][i] = tmp;
                }
            }
        }));
    }

    for (auto& f : res) {
        f.get();
    }
    res.clear();

    // 注意：打包发送比单个传输更快
    // Step 3: 广播自己的 cip_lut[party-1]
    std::stringstream cip_lut_stream;
    for (size_t i = 0; i < tb_size; ++i) {
        cip_lut[party - 1][i].pack(cip_lut_stream);
        // elgl->serialize_sendall(cip_lut[party - 1][i]);
    }
    std::string encoded = base64_encode(cip_lut_stream.str());
    std::stringstream encoded_stream;
    encoded_stream << encoded;
    elgl->serialize_sendall_(encoded_stream);

    // Step 4: 接收其他 party 的 cip_lut
    for (int i = 1; i <= num_party; ++i) {
        if (i != party) {
            // 多线程解包 cip_lut[i - 1][*]
            // for (int t = 0; t < thread_num; ++t) {
            //     size_t start = t * block_size;
            //     size_t end = std::min(tb_size, start + block_size);
            //     res.push_back(pool->enqueue([this, i, start, end]() {
            //         for (size_t j = start; j < end; ++j) {
            //             elgl->deserialize_recv(cip_lut[i - 1][j], i);
            //         }
            //     }));
            // }

            res.push_back(pool->enqueue([this, i]() {
                std::stringstream cip_stream;
                elgl->deserialize_recv_(cip_stream, i);

                std::string decoded = base64_decode(cip_stream.str());
                std::stringstream decoded_stream(decoded);

                for (size_t j = 0; j < tb_size; ++j) {
                    cip_lut[i - 1][j].unpack(decoded_stream);
                }
            }));
        }
    }

    for (auto& f : res) {
        f.get();
    }
    res.clear();
    // cout << "party: " << party << "生成LUT share结束" << endl;
    // cout << "rotation: " << rotation.get_message().getStr() << endl;
    // for (size_t i = 0; i < tb_size; i++) {
    //     cout << "lut_share[" << i << "] = " << lut_share[i].get_message().getStr() << endl;
    // }
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
    if(lvt->m_size <= 131072) {
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
BLS12381Element threshold_decrypt_easy(Ciphertext& c, ELGL<IO>* elgl, const ELGL_PK& global_pk, const std::vector<ELGL_PK>& user_pks, MPIOChannel<IO>* io, ThreadPool* pool, int party, int num_party, std::map<std::string, Fr>& P_to_m, LVT<IO>* lvt) {
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

    return pi_ask;
}

template <typename IO>
tuple<Plaintext, vector<Ciphertext>> LVT<IO>::lookup_online(Plaintext& x_share, Ciphertext& x_cipher, vector<Ciphertext>& x_ciphers){
    // cout << "party: " << party << " x_share = " << x_share.get_message().getStr() << endl;
    // cout << "party: " << party << " rotation = " << rotation.get_message().getStr() << endl;
    // cout << "party: " << party << "生成LUT的share" << endl;
    // for (size_t i = 0; i < tb_size; i++) {
    //     cout << "lut_share[" << i << "] = " << lut_share[i].get_message().getStr() << endl;
    // }

    auto start = clock_start();
    int bytes_start = io->get_total_bytes_sent();

    Plaintext out;
    vector<Ciphertext> out_ciphers;
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
    // cout << "party: " << party << " uu = " << uu.get_message().getStr() << endl;
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
        // cout << "u = " << u.getStr() << endl;
        // cout << "uu = " << uu.get_message().getStr() << endl;
        cout << "error: in online lookup" << endl;
        exit(1);
    }
    
    mcl::Vint tbs;
    tbs.setStr(to_string(tb_size));
    mcl::Vint u_mpz = u.getMpz(); 
    mcl::gmp::mod(u_mpz, u_mpz, tbs);

    mcl::Vint index_mpz;
    index_mpz.setStr(u_mpz.getStr());
    size_t index = static_cast<size_t>(index_mpz.getLow32bit());

    out = this->lut_share[index];
    // cout << "party: " << party << " out = " << out.get_message().getStr() << endl;
    out_ciphers.resize(num_party);
    for (size_t i = 0; i < num_party; i++){
        Ciphertext tmp(user_pk[i].get_pk(),cip_lut[i][index]);
        out_ciphers[i] = tmp;
    }
    // cout << "party: " << party << " index = " << index << endl;

    int bytes_end = io->get_total_bytes_sent();
    double comm_kb = double(bytes_end - bytes_start) / 1024.0;
    // std::cout << "Online time: " << std::fixed << std::setprecision(6) << time_from(start) / 1e6 << " seconds, " << std::fixed << std::setprecision(3) << "Online communication: " << comm_kb << " KB" << std::endl;

    return std::make_tuple(out, out_ciphers);
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

    BLS12381Element u = threshold_decrypt_easy(c, elgl, global_pk, user_pk, elgl->io, pool, party, num_party, P_to_m, this);

    BLS12381Element tmp(uu.get_message());
    for (int i = 0; i <= num_party * 2; i++){
        if (u == tmp){
            size_t index = static_cast<size_t>(q1.getLow32bit());
            out = lut_share[index];
            return;
        }
        tmp += G_tbs;
    }
    // cout << "error: in online lookup" << endl;
    Fr re = threshold_decrypt(c, elgl, global_pk, user_pk, elgl->io, pool, party, num_party, P_to_m, this);
    // cout << "palintext of u = " << re.getStr() << endl;
    // cout << "uu = " << uu.get_message().getStr() << endl;
    exit(1);
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

Fr alpha_init(int num) {
    Plaintext alpha;
    const mcl::Vint p("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
    const mcl::Vint g("5");
    mcl::Vint tb_size = mcl::Vint(1) << num;
    mcl::Vint alpha_vint;
    mcl::gmp::powMod(alpha_vint, g, (p - 1) / tb_size, p);
    alpha.assign(alpha_vint.getStr());
    return alpha.get_message();
}