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

#if defined(__APPLE__) || defined(__MACH__)
    #include <filesystem>
    namespace fs = std::filesystem;
#else
    #include <experimental/filesystem>
    namespace fs = std::experimental::filesystem;
#endif

const int thread_num = 8;
// #include "cmath"
// #include <poll.h>

namespace emp{

void deserializeTable(vector<int64_t>& table, const char* filename, size_t table_size = 1<<16) {
    ifstream inFile(filename, ios::binary);
    if (!inFile) {
        cerr << "Error: Unable to open file for reading.\n";
        exit(1);
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
    static void initialize(std::string name, LVT<IO>*& lvt_ptr_ref, int num_party, int party, MPIOChannel<IO>* io, ThreadPool* pool, ELGL<IO>* elgl, Fr& alpha_fr, int table_size, int m_bits);
    static void initialize_fake(std::string name, LVT<IO>*& lvt_ptr_ref, int num_party, int party, MPIOChannel<IO>* io, ThreadPool* pool, ELGL<IO>* elgl, Fr& alpha_fr, int table_size, int m_bits);
    ELGL_PK DistKeyGen();
    ~LVT();
    void generate_shares(vector<Plaintext>& lut_share, Plaintext& rotation, vector<int64_t> table);
    void generate_shares_fake(vector<Plaintext>& lut_share, Plaintext& rotation, vector<int64_t> table);
    tuple<Plaintext, vector<Ciphertext>> lookup_online(Plaintext& x_share, Ciphertext& x_cipher, vector<Ciphertext>& x_ciphers);
    tuple<vector<Plaintext>, vector<vector<Ciphertext>>> lookup_online_fake(vector<Plaintext>& x_share, vector<Ciphertext>& x_cipher);
    Plaintext lookup_online_easy(Plaintext& x_share);
    void save_full_state(const std::string& filename);
    void load_full_state(const std::string& filename);
    Plaintext Reconstruct(Plaintext input, vector<Ciphertext> input_cips, ELGL<IO>* elgl, const ELGL_PK& global_pk, const std::vector<ELGL_PK>& user_pks, MPIOChannel<IO>* io, ThreadPool* pool, int party, int num_party, mcl::Vint modulo);
    Plaintext Reconstruct_interact(Plaintext input, Ciphertext input_cip, ELGL<IO>* elgl, const ELGL_PK& global_pk, const std::vector<ELGL_PK>& user_pks, MPIOChannel<IO>* io, ThreadPool* pool, int party, int num_party, mcl::Vint modulo);
    Plaintext Reconstruct_easy(Plaintext input, ELGL<IO>* elgl, MPIOChannel<IO>* io, ThreadPool* pool, int party, int num_party, mcl::Vint modulo);

    LVT(): num_party(0), party(0), io(nullptr), pool(nullptr), elgl(nullptr), alpha(Fr()), tb_size(0), m_size(0) {};
};

template <typename IO>
void LVT<IO>::save_full_state(const std::string& filename) {
    std::ofstream out(filename, std::ios::binary);
    if (!out) throw std::runtime_error("Failed to open file for writing");
    
    // 使用内存映射写入数据
    size_t total_size = sizeof(int) * 2 +  // num_party, party
                       sizeof(size_t) * 2 +  // tb_size, m_size
                       sizeof(Fr) +         // rotation
                       tb_size * sizeof(Fr) + // lut_share
                       sizeof(Fr) +         // secret key
                       sizeof(size_t) +     // table size
                       table.size() * sizeof(int64_t) + // table data
                       num_party * tb_size * sizeof(G1) + // cip_lut
                       num_party * 2 * sizeof(G1) +    // cr_i
                       sizeof(G1) +         // global_pk
                       num_party * sizeof(G1) + // user_pk
                       sizeof(Fr) +         // alpha
                       sizeof(G1) * 2;      // G_tbs and g

    // 预分配内存
    std::vector<char> buffer(total_size);
    char* ptr = buffer.data();
    
    // 写入基本参数
    memcpy(ptr, &num_party, sizeof(int)); ptr += sizeof(int);
    memcpy(ptr, &party, sizeof(int)); ptr += sizeof(int);
    memcpy(ptr, &tb_size, sizeof(size_t)); ptr += sizeof(size_t);
    memcpy(ptr, &m_size, sizeof(size_t)); ptr += sizeof(size_t);
    
    // 写入 rotation
    const Fr& rot_fr = rotation.get_message();
    memcpy(ptr, &rot_fr, sizeof(Fr)); ptr += sizeof(Fr);
    
    // 写入 lut_share
    for (size_t i = 0; i < tb_size; i++) {
        const Fr& fr = lut_share[i].get_message();
        memcpy(ptr, &fr, sizeof(Fr)); ptr += sizeof(Fr);
    }
    
    // 写入 secret key
    const Fr& sk_fr = elgl->kp.get_sk().get_sk();
    memcpy(ptr, &sk_fr, sizeof(Fr)); ptr += sizeof(Fr);
    
    // 写入 table
    size_t table_size = table.size();
    memcpy(ptr, &table_size, sizeof(size_t)); ptr += sizeof(size_t);
    memcpy(ptr, table.data(), table_size * sizeof(int64_t)); ptr += table_size * sizeof(int64_t);
    
    // 写入 cip_lut
    for (int i = 0; i < num_party; ++i) {
        for (size_t j = 0; j < tb_size; ++j) {
            const G1& point = cip_lut[i][j].getPoint();
            memcpy(ptr, &point, sizeof(G1)); ptr += sizeof(G1);
        }
    }
    
    // 写入 cr_i
    for (int i = 0; i < num_party; ++i) {
        const G1& c0 = cr_i[i].get_c0().getPoint();
        const G1& c1 = cr_i[i].get_c1().getPoint();
        memcpy(ptr, &c0, sizeof(G1)); ptr += sizeof(G1);
        memcpy(ptr, &c1, sizeof(G1)); ptr += sizeof(G1);
    }
    
    // 写入 global_pk
    const G1& global_point = global_pk.get_pk().getPoint();
    memcpy(ptr, &global_point, sizeof(G1)); ptr += sizeof(G1);
    
    // 写入 user_pk
    for (int i = 0; i < num_party; ++i) {
        const G1& user_point = user_pk[i].get_pk().getPoint();
        memcpy(ptr, &user_point, sizeof(G1)); ptr += sizeof(G1);
    }

    // 写入 alpha
    memcpy(ptr, &alpha, sizeof(Fr)); ptr += sizeof(Fr);

    // 写入 G_tbs
    const G1& g_tbs_point = G_tbs.getPoint();
    memcpy(ptr, &g_tbs_point, sizeof(G1)); ptr += sizeof(G1);

    // 写入 g
    const G1& g_point = g.getPoint();
    memcpy(ptr, &g_point, sizeof(G1));
    
    // 一次性写入所有数据
    out.write(buffer.data(), total_size);
    out.close();
}

template <typename IO>
void LVT<IO>::load_full_state(const std::string& filename) {
    std::ifstream in(filename, std::ios::binary);
    if (!in) throw std::runtime_error("Failed to open file for reading");
    
    // 获取文件大小
    in.seekg(0, std::ios::end);
    size_t file_size = in.tellg();
    in.seekg(0, std::ios::beg);
    
    // 一次性读取所有数据
    std::vector<char> buffer(file_size);
    in.read(buffer.data(), file_size);
    const char* ptr = buffer.data();
    
    // 读取基本参数
    memcpy(&num_party, ptr, sizeof(int)); ptr += sizeof(int);
    memcpy(&party, ptr, sizeof(int)); ptr += sizeof(int);
    memcpy(&tb_size, ptr, sizeof(size_t)); ptr += sizeof(size_t);
    memcpy(&m_size, ptr, sizeof(size_t)); ptr += sizeof(size_t);
    
    // 读取 rotation
    Fr rot_fr;
    memcpy(&rot_fr, ptr, sizeof(Fr)); ptr += sizeof(Fr);
    rotation.set_message(rot_fr);
    
    // 读取 lut_share
    lut_share.resize(tb_size);
    for (size_t i = 0; i < tb_size; i++) {
        Fr fr;
        memcpy(&fr, ptr, sizeof(Fr)); ptr += sizeof(Fr);
        lut_share[i].set_message(fr);
    }
    
    // 读取 secret key
    Fr sk_fr;
    memcpy(&sk_fr, ptr, sizeof(Fr)); ptr += sizeof(Fr);
    ELGL_SK key;
    key.sk = sk_fr;
    elgl->kp.sk = key;
    
    // 读取 table
    size_t table_size;
    memcpy(&table_size, ptr, sizeof(size_t)); ptr += sizeof(size_t);
    table.resize(table_size);
    memcpy(table.data(), ptr, table_size * sizeof(int64_t)); ptr += table_size * sizeof(int64_t);
    
    // 读取 cip_lut
    cip_lut.resize(num_party);
    for (int i = 0; i < num_party; ++i) {
        cip_lut[i].resize(tb_size);
        for (size_t j = 0; j < tb_size; ++j) {
            G1 point;
            memcpy(&point, ptr, sizeof(G1)); ptr += sizeof(G1);
            BLS12381Element elem;
            elem.point = point;
            cip_lut[i][j] = elem;
        }
    }
    
    // 读取 cr_i
    cr_i.resize(num_party);
    for (int i = 0; i < num_party; ++i) {
        G1 c0, c1;
        memcpy(&c0, ptr, sizeof(G1)); ptr += sizeof(G1);
        memcpy(&c1, ptr, sizeof(G1)); ptr += sizeof(G1);
        
        BLS12381Element e0, e1;
        e0.point = c0;
        e1.point = c1;
        cr_i[i] = Ciphertext(e0, e1);
    }
    
    // 读取 global_pk
    G1 global_point;
    memcpy(&global_point, ptr, sizeof(G1)); ptr += sizeof(G1);
    BLS12381Element global_elem;
    global_elem.point = global_point;
    global_pk.assign_pk(global_elem);
    
    // 读取 user_pk
    user_pk.resize(num_party);
    for (int i = 0; i < num_party; ++i) {
        G1 user_point;
        memcpy(&user_point, ptr, sizeof(G1)); ptr += sizeof(G1);
        BLS12381Element user_elem;
        user_elem.point = user_point;
        user_pk[i].assign_pk(user_elem);
    }

    // 读取 alpha
    memcpy(&alpha, ptr, sizeof(Fr)); ptr += sizeof(Fr);

    // 读取 G_tbs
    G1 g_tbs_point;
    memcpy(&g_tbs_point, ptr, sizeof(G1)); ptr += sizeof(G1);
    G_tbs.point = g_tbs_point;

    // 读取 g
    G1 g_point;
    memcpy(&g_point, ptr, sizeof(G1));
    g.point = g_point;

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
    this->global_pk = DistKeyGen();
}

// 在类外定义initialize函数
template <typename IO>
void LVT<IO>::initialize(std::string func_name, LVT<IO>*& lvt_ptr_ref, int num_party, int party, MPIOChannel<IO>* io, ThreadPool* pool, ELGL<IO>* elgl, Fr& alpha_fr, int table_size, int m_bits) {
    std::string full_state_path = "../../build/cache/lvt_" + func_name + "_size" + std::to_string(table_size) + "-P" + std::to_string(party) + ".bin";
    
    // 创建缓存目录
    fs::create_directories("../../build/cache");
    
    lvt_ptr_ref = new LVT<IO>(num_party, party, io, pool, elgl, func_name, alpha_fr, table_size, m_bits);

    // 检查缓存文件是否存在
    if (fs::exists(full_state_path)) {
        auto start = clock_start();
        lvt_ptr_ref->load_full_state(full_state_path);
        std::cout << "Loading cached state time: " << std::fixed << std::setprecision(6) << time_from(start) / 1e6 << " seconds" << std::endl;
    } else {
        auto start = clock_start();
        cout << "Generating new state..." << endl;
        lvt_ptr_ref->generate_shares(lvt_ptr_ref->lut_share, lvt_ptr_ref->rotation, lvt_ptr_ref->table);
        cout << "Generate shares finished" << endl;
        lvt_ptr_ref->save_full_state(full_state_path);
        std::cout << "Generate and cache state time: " << std::fixed << std::setprecision(6) << time_from(start) / 1e6 << " seconds" << std::endl;
    }
}

// 在类外定义initialize函数
template <typename IO>
void LVT<IO>::initialize_fake(std::string func_name, LVT<IO>*& lvt_ptr_ref, int num_party, int party, MPIOChannel<IO>* io, ThreadPool* pool, ELGL<IO>* elgl, Fr& alpha_fr, int table_size, int m_bits) {
    std::string full_state_path = "../../build/cache/lvt_fake_" + func_name + "_size" + std::to_string(table_size) + "-P" + std::to_string(party) + ".bin";
    
    // 创建缓存目录
    fs::create_directories("../../build/cache");
    
    lvt_ptr_ref = new LVT<IO>(num_party, party, io, pool, elgl, func_name, alpha_fr, table_size, m_bits);

    // 检查缓存文件是否存在
    if (fs::exists(full_state_path)) {
        auto start = clock_start();
        lvt_ptr_ref->load_full_state(full_state_path);
        std::cout << "Loading cached state time: " << std::fixed << std::setprecision(6) << time_from(start) / 1e6 << " seconds" << std::endl;
    } else {
        auto start = clock_start();
        cout << "Generating new state..." << endl;
        lvt_ptr_ref->generate_shares_fake(lvt_ptr_ref->lut_share, lvt_ptr_ref->rotation, lvt_ptr_ref->table);
        cout << "Generate shares finished" << endl;
        lvt_ptr_ref->save_full_state(full_state_path);
        std::cout << "Generate and cache state time: " << std::fixed << std::setprecision(6) << time_from(start) / 1e6 << " seconds" << std::endl;
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
    for (size_t i = 0; i <= 1UL << 18; ++i) {
        BLS12381Element g_i(i);
        g_i.getPoint().normalize();
        P_to_m[g_i.getPoint().getStr()] = Fr(i);
    }
    serialize_P_to_m(P_to_m, filename);
}

template <typename IO>
LVT<IO>::LVT(int num_party, int party, MPIOChannel<IO>* io, ThreadPool* pool, ELGL<IO>* elgl, string func_name, Fr& alpha, int table_size, int m_bits)
    : LVT(num_party, party, io, pool, elgl, alpha, table_size, m_bits) {
    
    // 创建缓存目录
    fs::create_directories("../../build/cache");
    std::string tableFile = "../../build/bin/table_" + func_name + ".txt";
    
    // 缓存文件路径
    std::string table_cache = "../../build/cache/table_" + func_name + "_" + std::to_string(table_size) + ".bin";
    std::string p_to_m_cache = "../../build/cache/p_to_m_" + std::to_string(m_bits) + ".bin";
    std::string bsgs_cache = "../../build/cache/bsgs_32.bin";
    
    // 1. 处理 table 数据
    if (fs::exists(table_cache)) {
        // 从缓存加载 table
        std::ifstream in(table_cache, std::ios::binary);
        if (!in) throw std::runtime_error("Failed to open table cache");
        
        size_t size;
        in.read(reinterpret_cast<char*>(&size), sizeof(size_t));
        table.resize(size);
        in.read(reinterpret_cast<char*>(table.data()), size * sizeof(int64_t));
        in.close();
    } else {
        // 生成新的 table 数据
        deserializeTable(table, tableFile.c_str(), tb_size);
        
        // 保存到缓存
        std::ofstream out(table_cache, std::ios::binary);
        if (!out) throw std::runtime_error("Failed to create table cache");
        
        size_t size = table.size();
        out.write(reinterpret_cast<const char*>(&size), sizeof(size_t));
        out.write(reinterpret_cast<const char*>(table.data()), size * sizeof(int64_t));
        out.close();
    }
    
    // 2. 处理 P_to_m 数据
    if (m_bits <= 14) {
        if (fs::exists(p_to_m_cache)) {
            // 从缓存加载 P_to_m
            std::ifstream in(p_to_m_cache, std::ios::binary);
            if (!in) throw std::runtime_error("Failed to open P_to_m cache");
            
            size_t size;
            in.read(reinterpret_cast<char*>(&size), sizeof(size_t));
            P_to_m.clear();
            
            for (size_t i = 0; i < size; ++i) {
                size_t key_len;
                in.read(reinterpret_cast<char*>(&key_len), sizeof(size_t));
                std::string key(key_len, '\0');
                in.read(&key[0], key_len);
                
                Fr value;
                in.read(reinterpret_cast<char*>(&value), sizeof(Fr));
                P_to_m[key] = value;
            }
            in.close();
        } else {
            // 生成新的 P_to_m 数据
            build_safe_P_to_m(P_to_m, num_party, m_size);
            
            // 保存到缓存
            std::ofstream out(p_to_m_cache, std::ios::binary);
            if (!out) throw std::runtime_error("Failed to create P_to_m cache");
            
            size_t size = P_to_m.size();
            out.write(reinterpret_cast<const char*>(&size), sizeof(size_t));
            
            for (const auto& pair : P_to_m) {
                size_t key_len = pair.first.length();
                out.write(reinterpret_cast<const char*>(&key_len), sizeof(size_t));
                out.write(pair.first.c_str(), key_len);
                out.write(reinterpret_cast<const char*>(&pair.second), sizeof(Fr));
            }
            out.close();
        }
    }
    
    // 3. 处理 BSGS 表
    uint64_t N = 1ULL << 32;
    if (fs::exists(bsgs_cache)) {
        try {
            bsgs.deserialize(bsgs_cache.c_str());
        } catch (const std::exception& e) {
            // 如果反序列化失败，重新生成
            bsgs.precompute(g, N);
            bsgs.serialize(bsgs_cache.c_str());
        }
    } else {
        bsgs.precompute(g, N);
        bsgs.serialize(bsgs_cache.c_str());
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

// cout << "begin" << endl;
//     mcl::Vint fd(to_string(m_size)); 
//     for (size_t j = 0; j < tb_size; j++){
//         vector<Ciphertext> tmp;
//         for (int i = 0; i < num_party; i++){
//             Ciphertext tmp_;
//             tmp_.set(user_pk[i].get_pk(), cip_lut[i][j]);
//             tmp.push_back(tmp_);
//         }
//         this->Reconstruct(lut_share[j], tmp, elgl, this->global_pk, this->user_pk, this->io, this->pool, this->party, this->num_party, fd);
//     }
// cout << "end" << endl;

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
    cr_i[party-1] = global_pk.encrypt(rotation);

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
    cr_i[party-1].pack(cip_lut_stream);
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
                cr_i[i-1].unpack(decoded_stream);

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

    // mcl::Vint fd(to_string(m_size)); 
    // for (size_t j = 0; j < tb_size; j++){
    //     vector<Ciphertext> tmp;
    //     for (int i = 0; i < num_party; i++){
    //         Ciphertext tmp_;
    //         tmp_.set(user_pk[i].get_pk(), cip_lut[i][j]);
    //         tmp.push_back(tmp_);
    //     }
    //     this->Reconstruct_easy(lut_share[j], elgl, this->io, this->pool, this->party, this->num_party, fd);
    // }


    // cout << "party: " << party << "生成LUT share结束" << endl;
    // cout << "rotation: " << rotation.get_message().getStr() << endl;
    // for (size_t i = 0; i < tb_size; i++) {
    //     cout << "lut_share[" << i << "] = " << lut_share[i].get_message().getStr() << endl;
    // }
}


template <typename IO>
ELGL_PK LVT<IO>::DistKeyGen(){
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
    Ciphertext tmp; tmp.set(global_pk.get_pk(), global_pk.get_pk());
    elgl->serialize_sendall(tmp);
    for (size_t i = 1; i <= num_party; i++){
        Ciphertext tmp_; 
        if (i!= party){
            elgl->deserialize_recv(tmp_, i);
            if (tmp != tmp_){
                std::cerr << "[Error] global_pk_ not equal to sum of other's pk!" << std::endl;
                exit(1);
            }
        }
    }
    return global_pk;
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
    BLS12381Element y1 = user_pks[party-1].get_pk();
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
        bool t = 1;
        if (it == P_to_m.end()) {
            // std::cout << "In decrypt: not found *** try to use bsgs." << std::endl;
            t = 0;
        }
        if (t) return it->second;
    } 
    y = lvt->bsgs.solve_parallel_with_pool(pi_ask, pool, thread_num);
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
tuple<Plaintext, vector<Ciphertext>> LVT<IO>::lookup_online(Plaintext& x_share, Ciphertext& x_cipher, vector<Ciphertext>& x_ciphers){ // TODO: 与fake offline不兼容需要修改
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
        Ciphertext tmp(user_pk[i].get_pk(), cip_lut[i][index]);
        out_ciphers[i] = tmp;
    }
    // cout << "party: " << party << " index = " << index << endl;

    int bytes_end = io->get_total_bytes_sent();
    double comm_kb = double(bytes_end - bytes_start) / 1024.0;
    // std::cout << "Online time: " << std::fixed << std::setprecision(6) << time_from(start) / 1e6 << " seconds, " << std::fixed << std::setprecision(3) << "Online communication: " << comm_kb << " KB" << std::endl;

    return std::make_tuple(out, out_ciphers);
}

template <typename IO>
tuple<vector<Plaintext>, vector<vector<Ciphertext>>> LVT<IO>::lookup_online_fake(vector<Plaintext>& x_share, vector<Ciphertext>& x_cipher){
    auto start = clock_start();
    int bytes_start = io->get_total_bytes_sent();

    int x_size = x_share.size();
    vector<std::future<void>> res;
    vector<vector<Plaintext>> u_shares(x_size, vector<Plaintext>(num_party));
    vector<vector<Ciphertext>> x_ciphers(x_size, vector<Ciphertext>(num_party));

    for (size_t i = 0; i < x_size; i++) {
        res.push_back(pool->enqueue([this, i, &x_share, &u_shares](){
            u_shares[i][party-1] = x_share[i] + this->rotation;
        }));
    }
    for (auto& v : res)
        v.get();
    res.clear();

    for (size_t i = 0; i < x_size; i++) {
        for (size_t j = 1; j <= num_party; j++){
            res.push_back(pool->enqueue([this, i, j, &u_shares](){
                if (j != party){
                    Plaintext u_share;
                    elgl->deserialize_recv(u_share, j);
                    u_shares[i][j-1] = u_share;
                }
            }));
        }
    }
    for (size_t i = 0; i < x_size; i++) {
        elgl->serialize_sendall(u_shares[i][party-1]);
    }
    for (auto& v : res)
        v.get();
    res.clear();

    for (size_t i = 0; i < x_size; i++) {
        for (size_t j = 1; j <= num_party; j++){
            res.push_back(pool->enqueue([this, i, j, &x_ciphers](){
                if (j != party){
                    Ciphertext x_cip;
                    elgl->deserialize_recv(x_cip, j);
                    x_ciphers[i][j-1] = x_cip;
                }
            }));
        }
    }
    for (size_t i = 0; i < x_size; i++) {
        elgl->serialize_sendall(x_cipher[i]);
    }
    for (auto& v : res)
        v.get();
    res.clear();

    vector<Ciphertext> c(x_size);
    vector<Plaintext> uu(x_size);
    for (size_t i = 0; i < x_size; i++) {
        res.push_back(pool->enqueue([this, i, &x_ciphers, &u_shares, &c, &uu](){
            c[i] = x_ciphers[i][0] + this->cr_i[party-1];  // 修改这里，使用cr_i[party-1]而不是cr_i[i]
            uu[i] = u_shares[i][0];
        }));
    }
    for (auto& v : res)
        v.get();
    res.clear();

    for (size_t j = 0; j < x_size; j++) {
        res.push_back(pool->enqueue([this, j, &x_ciphers, &u_shares, &c, &uu](){
            for (size_t i=1; i<num_party; i++){
                c[j] +=  x_ciphers[j][i] + this->cr_i[i-1];  // 这里也需要修改，使用cr_i[i-1]
                uu[j] += u_shares[j][i];
            }
        }));
    }
    for (auto& v : res)
        v.get();
    res.clear();

    vector<Plaintext> out(x_size);
    vector<vector<Ciphertext>> out_ciphers(x_size, vector<Ciphertext>(num_party));

    mcl::Vint tbs;
    tbs.setStr(to_string(tb_size));
    for (size_t i = 0; i < x_size; i++) {
        res.push_back(pool->enqueue([this, i, &uu, &out, &out_ciphers, &tbs](){
            mcl::Vint u_mpz = uu[i].get_message().getMpz(); 
            mcl::gmp::mod(u_mpz, u_mpz, tbs);

            mcl::Vint index_mpz;
            index_mpz.setStr(u_mpz.getStr());
            size_t index = static_cast<size_t>(index_mpz.getLow32bit());

            out[i] = this->lut_share[index];
            out_ciphers[i].resize(num_party);
            for (size_t j = 0; j < num_party; j++){
                Ciphertext tmp(this->user_pk[j].get_pk(), this->cip_lut[j][index]);
                out_ciphers[i][j] = tmp;
            }
        }));
    }
    for (auto& v : res)
        v.get();
    res.clear();

    int bytes_end = io->get_total_bytes_sent();
    double comm_kb = double(bytes_end - bytes_start) / 1024.0;

    return std::make_tuple(out, out_ciphers);
}

template <typename IO>
Plaintext LVT<IO>::lookup_online_easy(Plaintext& x_share){
    // cout << "party: " << party << " x_share = " << x_share.get_message().getStr() << endl;
    vector<std::future<void>> res;
    vector<Plaintext> u_shares;
    u_shares.resize(num_party);
    u_shares[party-1] = x_share + this->rotation;

    // accept cipher from all party
    for (size_t i = 1; i <= num_party; i++){
        res.push_back(pool->enqueue([this, i, &u_shares](){
            if (i != party){
                Plaintext u_share;
                elgl->deserialize_recv(u_share, i);
                u_shares[i-1] = u_share;
            }
        }));
    }
    elgl->serialize_sendall(u_shares[party-1], party);
    for (auto& v : res)
        v.get();
    res.clear();

    Plaintext uu = u_shares[0];
    for (size_t i=1; i<num_party; i++){
        uu += u_shares[i];
    }
    // uu mod tb_size
    mcl::Vint h;
    h.setStr(to_string(tb_size));
    mcl::Vint q1 = uu.get_message().getMpz();
    mcl::gmp::mod(q1, q1, h);

    size_t index = static_cast<size_t>(q1.getLow32bit());
    Plaintext out = this->lut_share[index];

    return out;
}

template <typename IO>
Plaintext LVT<IO>::Reconstruct(Plaintext input, vector<Ciphertext> input_cips, ELGL<IO>* elgl, const ELGL_PK& global_pk, const std::vector<ELGL_PK>& user_pks, MPIOChannel<IO>* io, ThreadPool* pool, int party, int num_party, mcl::Vint modulo){
    Plaintext out = input;
    Ciphertext out_cip = input_cips[party-1];

    elgl->serialize_sendall(input);

    for (int i = 1; i <= num_party; i++){
        if (party != i) {
            Plaintext tmp;
            elgl->deserialize_recv(tmp, i);
            out += tmp;
            out_cip += input_cips[i-1];
        }
    }
    Fr out_ = threshold_decrypt(out_cip, elgl, global_pk, user_pks, io, pool, party, num_party, P_to_m, this); 
    mcl::Vint o = out_.getMpz();
    o %= modulo;

    mcl::Vint o_ = out.get_message().getMpz();
    o_ %= modulo;
    
    if (o_ != o) {
        cout << "o_: " << o_ << endl; 
        cout << "o: " << o << endl;
        error("Reconstruct error");
    }
    out.assign(o_);
    // cout << "o_ " << o_ << endl; 
    return out;
}

template <typename IO>
Plaintext LVT<IO>::Reconstruct_interact(Plaintext input, Ciphertext input_cip, ELGL<IO>* elgl, const ELGL_PK& global_pk, const std::vector<ELGL_PK>& user_pks, MPIOChannel<IO>* io, ThreadPool* pool, int party, int num_party, mcl::Vint modulo){
    Plaintext out = input;
    Ciphertext out_cip = input_cip;

    elgl->serialize_sendall(input);
    for (int i = 1; i <= num_party; i++){
        if (party != i) {
            Plaintext tmp;
            elgl->deserialize_recv(tmp, i);
            out += tmp;
        }
    }

    elgl->serialize_sendall(input_cip);
    for (int i = 1; i <= num_party; i++){
        if (party != i) {
            Ciphertext tmp_cip;
            elgl->deserialize_recv(tmp_cip, i);
            out_cip += tmp_cip;
        }
    }

    Fr out_ = threshold_decrypt(out_cip, elgl, global_pk, user_pks, io, pool, party, num_party, P_to_m, this);
    mcl::Vint o = out_.getMpz();
    o %= modulo;

    mcl::Vint o_ = out.get_message().getMpz();
    o_ %= modulo;
    
    if (o_ != o) {
        error("Reconstruct_interact error");
    }
    out.assign(o_);
    return out;
}

template <typename IO>
Plaintext LVT<IO>::Reconstruct_easy(Plaintext input, ELGL<IO>* elgl, MPIOChannel<IO>* io, ThreadPool* pool, int party, int num_party, mcl::Vint modulo){
    Plaintext out = input;
    elgl->serialize_sendall(input);

    for (int i = 1; i <= num_party; i++){
        if (party != i) {
            Plaintext tmp;
            elgl->deserialize_recv(tmp, i);
            out += tmp;
        }
    }
    mcl::Vint o_ = out.get_message().getMpz();
    o_ %= modulo;
    out.assign(o_);
    return out;
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