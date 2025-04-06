#pragma once
#include "libelgl/elgl/BLS12381Element.h"
#include "emp-aby/utils.h"
#include "emp-aby/elgl_interface.hpp"
#include "libelgl/elgl/FFT.h"
#include "libelgl/elgl/Ciphertext.h"
#include "libelgl/elgloffline/RotationProof.h"
#include "libelgl/elgloffline/RotationProver.h"
#include "libelgl/elgloffline/RotationVerifier.h"

#include "libelgl/elgloffline/Range_Proof.h"
#include "libelgl/elgloffline/Range_Prover.h"
#include "libelgl/elgloffline/Range_Verifier.h"

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
    private:
    int num_used = 0;
    ThreadPool* pool;
    Fr rotation;
    std::map<std::string, Fr> P_to_m;
    vector<vector<BLS12381Element>> cip_lut;


    ELGL<IO>* elgl;
    MPIOChannel<IO>* io;
    std::vector<Ciphertext> cr_i;
    PRG prg;
    Fr alpha;
    size_t tb_size;
    // void shuffle(Ciphertext& c, bool* rotation, size_t batch_size, size_t i);

    public:
    ELGL_PK global_pk;
    std::vector<ELGL_PK> user_pk;
    vector<Plaintext> lut_share;
    int num_party;
    int party;
    vector<int64_t> table;
    LVT(int num_party, int party, MPIOChannel<IO>* io, ThreadPool* pool, ELGL<IO>* elgl, Fr& alpha, int table_size);
    LVT(int num_party, int party, MPIOChannel<IO>* io, ThreadPool* pool, ELGL<IO>* elgl, std::string tableFile, Fr& alpha, int table_size);
    void DistKeyGen();
    ~LVT();
    void generate_shares(vector<Plaintext>& lut_share, Plaintext& rotation, vector<int64_t> table);
    void lookup_online(Plaintext& out, vector<Plaintext>& lut_share, Fr& rotate, Plaintext& x_share, vector<Ciphertext> x_cipher);
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
    BLS12381Element::init();
}

template <typename IO>
LVT<IO>::LVT(int num_party, int party, MPIOChannel<IO>* io, ThreadPool* pool, ELGL<IO>* elgl, string tableFile, Fr& alpha, int table_size)
    : LVT(num_party, party, io, pool, elgl, alpha, table_size) {
    // load table from file
    deserializeTable(table, tableFile.c_str(), tb_size);
        // everybody calculate their own P_to_m table
    for (size_t i = 0; i < tb_size * static_cast<size_t>(num_party); i++){
        P_to_m[BLS12381Element(i).getPoint().getStr()] = i;
    }
}


template <typename IO>
void LVT<IO>::generate_shares(vector<Plaintext>& lut_share, Plaintext& rotation, vector<int64_t> table) {
    std::cout <<"alpha:" << alpha << std::endl;
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
    RangeProof Range_proof(global_pk, bound);
    RangeVerifier Range_verifier(Range_proof);
    RangeProver Range_prover(Range_proof);

    c0.resize(tb_size);
    c1.resize(tb_size);
    c0_.resize(tb_size);
    c1_.resize(tb_size);
    // rotation.set_random(tb_size); //ok
    // Ciphertext cipher_rot =  elgl->kp.get_pk().encrypt(rotation); //ok
    // cr_i[party-1] = cipher_rot;

    // tasks.push_back(pool->enqueue([this, cipher_rot]() {
    //     elgl->serialize_sendall(cipher_rot);
    // }));


    // for (size_t i = 0; i < num_party; i++) {
    //     if (i + 1 != party) {
    //         tasks.push_back(pool->enqueue([this, i]() {
    //             elgl->deserialize_recv(cr_i[i], i + 1);
    //         }));
    //     }
    // }

    // for (auto & task : tasks) {
    //     task.get();
    // }
    // tasks.clear();


    if (party == ALICE) {
        // encrypt the table
        std::stringstream comm, response, encMap;
        elgl->DecProof(comm, response, encMap, table, tb_size, c0, c1);
        // print comm response encMap
        std::stringstream comm_, response_, encMap_;        
        std::string comm_raw = comm.str();
        comm_ << base64_encode(comm_raw);
        std::string response_raw = response.str();
        response_ << base64_encode(response_raw);
        std::string encMap_raw = encMap.str();
        encMap_ << base64_encode(encMap_raw);

        elgl->serialize_sendall_(response_);
        elgl->serialize_sendall_(comm_);
        elgl->serialize_sendall_(encMap_);
    }else{
        std::stringstream comm, response, encMap;
        std::string comm_raw, response_raw, encMap_raw;
        std::stringstream comm_, response_, encMap_;
        elgl->deserialize_recv_(response, ALICE);
        elgl->deserialize_recv_(comm, ALICE);
        elgl->deserialize_recv_(encMap, ALICE);
        
        comm_raw = comm.str();
        comm_ << base64_decode(comm_raw);
        response_raw = response.str();
        response_ << base64_decode(response_raw);
        encMap_raw = encMap.str();
        encMap_ << base64_decode(encMap_raw);
        elgl->DecVerify(comm_, response_, encMap_, c0, c1, tb_size);
    }

    vector<BLS12381Element> ak;
    vector<BLS12381Element> bk;
    vector<BLS12381Element> dk;
    vector<BLS12381Element> ek;
    ak.resize(tb_size);
    bk.resize(tb_size);
    dk.resize(tb_size);
    ek.resize(tb_size);
    mcl::Unit N(tb_size);
    FFT(c0, ak, alpha, N);
    FFT(c1, bk, alpha, N);
    Plaintext alpha_inv;
    alpha_inv.assign("39946203658912138033548902979326710369783929861401978374778960978475302091493");
    vector<BLS12381Element> c0_fft;
    vector<BLS12381Element> c1_fft;
    Fr N_inv;
    // Fr::inv(omega_inv, alpha);
    Fr::inv(N_inv, N);
    cout << "N * N_inv: " << N * N_inv << endl;

    cout << "alpha * alpha_inv: " << alpha * alpha_inv.get_message()  << endl;

    FFT(ak, c0_fft, alpha_inv.get_message(), N);
    FFT(bk, c1_fft, alpha_inv.get_message(), N);

    for (size_t i = 0; i < tb_size; i++)
    {
        c0_fft[i] *= N_inv; 
        c1_fft[i] *= N_inv;
    }
    
    for (size_t i = 0; i < tb_size; ++i) {
        if (c0[i] != c0_fft[i]){
            std::cout << i << "错误" << std::endl;
            // return 1;
        }
        if (c1_fft[i] != c1[i] ){
            std::cout << i << "错误" << std::endl;
            // return 1;
        }
    }



    if (party == ALICE)
    {
        mcl::Vint bound;
        bound.setStr(to_string(tb_size));
        rotation.set_random(bound);

        Ciphertext cipher_rot =  elgl->kp.get_pk().encrypt(rotation);
        cr_i[party-1] = cipher_rot;

        Plaintext beta;
        vector<Plaintext> betak;
        betak.resize(tb_size);

        Plaintext::pow(beta, alpha, rotation);
        vector<Plaintext> sk;
        sk.resize(tb_size);
        for (size_t i = 0; i < tb_size; i++)
        {
            sk[i].set_random();
        }
        
        for (size_t i = 0; i < tb_size; i++){
            if (i==0) {betak[i].assign(1);}
            else {betak[i] = betak[i - 1] * beta;}
            dk[i] = BLS12381Element(1) * sk[i].get_message();
            dk[i] += ak[i] * betak[i].get_message();
            // e_k = bk ^ betak * h^sk
            ek[i] = global_pk.get_pk() * sk[i].get_message();
            ek[i] += bk[i] * betak[i].get_message();
        }
        
        std::stringstream commit_ro, response_ro;
        Rot_prover.NIZKPoK(rot_proof, commit_ro, response_ro, global_pk, global_pk, dk, ek, ak, bk, beta, sk);
        std::stringstream comm_ro_, response_ro_;        
        std::string comm_raw = commit_ro.str();
        comm_ro_ << base64_encode(comm_raw);
        std::string response_raw = response_ro.str();
        response_ro_ << base64_encode(response_raw);
        // print comm_ response_ cipher_rot

        elgl->serialize_sendall_(comm_ro_);
        elgl->serialize_sendall_(response_ro_);
        elgl->serialize_sendall(cipher_rot);
    }
    
    for (size_t i = 1; i <= num_party -1; i++){
        size_t index = i - 1;
        if (i == party) {
            continue;
        }else{
            res.push_back(pool->enqueue([this, i, index, &c0, &c1, &dk, &ek, &Rot_prover,&rot_proof, &Rot_verifier, &rotation]() {
                vector<BLS12381Element> mk;
                vector<BLS12381Element> nk;
                vector<BLS12381Element> qk;
                vector<BLS12381Element> wk;
                mk.resize(tb_size);
                nk.resize(tb_size);
                qk.resize(tb_size);
                wk.resize(tb_size);
                Ciphertext cipher_rot;
                // TODO: read ciphertexts and proof
                std::stringstream comm_ro, response_ro;
                std::string comm_raw, response_raw;
                std::stringstream comm_, response_;

                elgl->deserialize_recv_(comm_ro, i);
                elgl->deserialize_recv_(response_ro, i);
                elgl->deserialize_recv(cipher_rot, i);

                comm_raw = comm_ro.str();
                response_raw = response_ro.str();

                comm_ << base64_decode(comm_raw);
                response_ << base64_decode(response_raw);
                
                this->cr_i[index] = cipher_rot;
                Rot_verifier.NIZKPoK(qk, wk, mk, nk, comm_, response_, this->global_pk, this->global_pk);
                if (i == this->party - 1)
                {
                    vector<BLS12381Element> dk_;
                    vector<BLS12381Element> ek_;
                    dk_.resize(tb_size);
                    ek_.resize(tb_size);
                    mcl::Vint bound;
                    bound.setStr(to_string(tb_size));
                    rotation.set_random(bound);
                    Ciphertext cipher_rot =  elgl->kp.get_pk().encrypt(rotation);
                    this->cr_i[this->party] = cipher_rot;
                    Plaintext beta, betak;
                    Plaintext::pow(beta, alpha, rotation);
                    betak.assign("1");
                    vector<Plaintext> sk;
                    sk.resize(this->num_party);
                    for (size_t i = 0; i < tb_size; i++){
                        dk_[i] = qk[i] * betak.get_message();
                        ek_[i] = wk[i] * betak.get_message();
                        betak *= beta;
                        // TODO: here use power function can parallel
                        sk[i].set_random();
                        dk_[i] += BLS12381Element(sk[i].get_message());
                        ek_[i] += global_pk.get_pk() * sk[i].get_message();
                    }
                    std::stringstream commit_ro, response_ro;
                    Rot_prover.NIZKPoK(rot_proof, commit_ro, response_ro, global_pk, global_pk, dk_, ek_, qk, wk, beta, sk);
            
                    elgl->serialize_sendall_(commit_ro);
                    elgl->serialize_sendall_(response_ro);
                    elgl->serialize_sendall(cipher_rot);
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

    // all party wait for the last party
    Ciphertext cipher_rot;
    // TODO: read ciphertexts and proof
    std::stringstream comm_ro, response_ro;
    elgl->deserialize_recv_(comm_ro, num_party);
    elgl->deserialize_recv_(response_ro, num_party);
    elgl->deserialize_recv(cipher_rot, num_party);
    cr_i[num_party-1] = cipher_rot;
    dk.clear();
    ek.clear();
    ak.clear();
    bk.clear();
    Rot_verifier.NIZKPoK(dk, ek, ak, bk, comm_ro, response_ro, global_pk, global_pk);
    
    IFFT(dk, c0_, alpha, tb_size);
    IFFT(ek, c1_, alpha, tb_size);

    if (party == ALICE) {
        vector<Plaintext> y_alice;
        vector<Plaintext> d;
        vector<BLS12381Element> L;
        Plaintext exp;
        ;
        exp = Plaintext(Fr(to_string(tb_size))) * Plaintext(Fr(to_string(num_party))) - Plaintext(Fr(to_string(tb_size)));
        vector<BLS12381Element> l_alice(tb_size,BLS12381Element(exp.get_message()));
        
        vector<BLS12381Element> l_(num_party);

        // for each c_1
        for (size_t i = 2; i <= num_party; i++)
        {
            vector<BLS12381Element> y3;
            vector<BLS12381Element> y2;
            std::stringstream commit_ro, response_ro;
            elgl->deserialize_recv_(commit_ro, i);
            elgl->deserialize_recv_(response_ro, i);
            
            BLS12381Element pk__ = user_pk[i-1].get_pk();
            Range_verifier.NIZKPoK(pk__, y3, y2, commit_ro, response_ro, c0_, global_pk);
            for (size_t j = 0; j < tb_size; j++)
            {
                l_alice[j] += y2[j];
            }
            
            cip_lut[i-1] = y3;
        }
        
        for (size_t i = 0; i < tb_size; i++){
            l_alice[i] += c1_[i];
        }


        // cal c0^-sk * l
        for (size_t i = 0; i < tb_size; i++){
            BLS12381Element Y = l_alice[i] - c0_[i] * elgl->kp.get_sk().get_sk(); 
            Fr y = P_to_m[Y.getPoint().getStr()];
            mcl::Vint q_, r_;
            mcl::Vint y_;
            y_ = y.getMpz();
            mcl::gmp::divmod(q_, r_, y_, num_party);
            Fr q, r;
            q.setMpz(q_);
            r.setMpz(r_);
            lut_share.push_back(r);
            d.push_back(q);
            BLS12381Element l(q);
            l += c0_[i] * elgl->kp.get_sk().get_sk();
            L.push_back(l);
            BLS12381Element pk_tmp = global_pk.get_pk();
            cip_lut[0][i] = BLS12381Element(r) + pk_tmp * elgl->kp.get_sk().get_sk();
        }

        std::stringstream commit_ss, response_ss;
        
        
        Range_prover.NIZKPoK(Range_proof, commit_ss, response_ss, global_pk, c0_, cip_lut[0], L, lut_share, elgl->kp.get_sk().get_sk());

        elgl->serialize_sendall_(commit_ss);
        elgl->serialize_sendall_(response_ss);
        // serialize d

    }else{
        // sample x_i
        mcl::Vint bound(to_string(tb_size));
        // std::stringstream l_stream;
        // std::stringstream cip_i_stream;
        std::stringstream commit_ss;
        std::stringstream response_ss;
        vector<BLS12381Element> l_1_v;
        vector<BLS12381Element> cip_v;
        for (size_t i = 0; i < tb_size; i++)
        {
            lut_share[i].set_random(bound);
            // cal l_1
            BLS12381Element l_1, cip_;
            Plaintext share_x_i_neg = lut_share[i];
            Plaintext ski_neg = elgl->kp.get_sk().get_sk();
            share_x_i_neg.negate();
            ski_neg.negate();
            l_1 = BLS12381Element(share_x_i_neg.get_message());
            l_1 += c0_[i] * ski_neg.get_message();
            l_1_v.push_back(l_1);
            // pack l_1 into l_stream
            // l_1.pack(l_stream);

            // cal cip_i
            cip_ = BLS12381Element(lut_share[i].get_message());
            cip_ += global_pk.get_pk() * elgl->kp.get_sk().get_sk();
            cip_v.push_back(cip_);
            // pack cip_i into cip_i_stream
            // cip_.pack(cip_i_stream);
        }
        cip_lut[party-1] = cip_v;

        Range_prover.NIZKPoK(Range_proof, commit_ss, response_ss, global_pk, c0_, cip_v, l_1_v, lut_share, elgl->kp.get_sk().get_sk());

        // sendall
        elgl->serialize_sendall_(commit_ss);
        elgl->serialize_sendall_(response_ss);

        // receive all others commit and response
        for (size_t i = 2; i <= num_party; i++){
            if (i != party)
            {
                vector<BLS12381Element> y3;
                vector<BLS12381Element> y2;
                std::stringstream commit_ro, response_ro;
                elgl->deserialize_recv_(commit_ro, i);
                elgl->deserialize_recv_(response_ro, i);
                BLS12381Element pk__ = user_pk[i-1].get_pk();
                Range_verifier.NIZKPoK(pk__, y3, y2, commit_ro, response_ro, c0_, global_pk);
                cip_lut[i-1] = y3;
            }
        }

        // accept broadcast from alice
        std::stringstream commit_ro, response_ro;
        elgl->deserialize_recv_(commit_ro, ALICE);
        elgl->deserialize_recv_(response_ro, ALICE);
        vector<BLS12381Element> y2;
        vector<BLS12381Element> y3;
        BLS12381Element pk__ = user_pk[0].get_pk();
        Range_verifier.NIZKPoK(pk__, y3, y2, commit_ro, response_ro, c0_, global_pk);
        cip_lut[0] = y3;
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
    // cal global pk_
    BLS12381Element global_pk_ = BLS12381Element(0);
    for (auto& pk : user_pk){
        global_pk_ += pk.get_pk();
    }
    global_pk.assign_pk(global_pk_);
}

template <typename IO>
void LVT<IO>::lookup_online(Plaintext& out,  vector<Plaintext>& lut_share, Fr& rotate, Plaintext& x_share, vector<Ciphertext> x_cipher){
    vector<std::future<void>> res;
    res.push_back(pool->enqueue([this, rotate, lut_share, x_share, x_cipher, &out](){
        // cal c
        Ciphertext c = cr_i[0] + x_cipher[0];
        for (int i=1; i<num_party; i++){
            c += cr_i[i] + x_cipher[i];
        }
        Plaintext ui = rotate + x_share;
        elgl->serialize_sendall(ui);
        Plaintext tmp;
        for (size_t i = 1; i <= num_party; i++)
        {
            if (i!= party){
                elgl->deserialize_recv(tmp, i);
                ui += tmp;
            }
        }
        uint64_t index = ui.get_message().getUint64();
        out = lut_share[index];
    }));
    for (auto& v : res)
        v.get();
    res.clear();
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

