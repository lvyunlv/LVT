#pragma once
#include "emp-aby/elgl/BLS12381Element.h"
#include "emp-aby/utils.h"
#include "emp-aby/elgl_interface.hpp"
#include "emp-aby/elgl/FFT.h"
#include "emp-aby/elgl/Ciphertext.h"
#include "emp-aby/elgloffline/RotationProof.h"
#include "emp-aby/elgloffline/RotationProver.h"
#include "emp-aby/elgloffline/RotationVerifier.h"

#include "emp-aby/elgloffline/Range_Proof.h"
#include "emp-aby/elgloffline/Range_Prover.h"
#include "emp-aby/elgloffline/Range_Verifier.h"

// #include "cmath"
// #include <poll.h>

namespace emp{

template <typename IO>
class LVT{
    private:
    int num_used = 0;
    ThreadPool* pool;
    Fr* rotation;
    std::map<std::string, Fr> P_to_m;
    vector<vector<BLS12381Element>> ciph_;

    std::vector<ELGL_PK> user_pk;
    ELGL_PK global_pk;
    ELGL<IO>* elgl;
    MPIOChannel<IO>* io;
    PRG prg;
    Fr alpha;
    size_t tb_size;
    // void shuffle(Ciphertext& c, bool* rotation, size_t batch_size, size_t i);

    public:
    vector<Plaintext> lut_share;
    int num_party;
    int party;
    vector<int64_t> table;
    LVT(int num_party, int party, MPIOChannel<IO>* io, ThreadPool* pool, ELGL<IO>* elgl, Fr& alpha, int table_size);
    LVT(int num_party, int party, MPIOChannel<IO>* io, ThreadPool* pool, ELGL<IO>* elgl, std::string tableFile, Fr& alpha, int table_size);
    void DistKeyGen();
    ~LVT();
    void generate_shares(vector<Plaintext>& lut_share, Plaintext rotation, int num_shares, vector<int64_t> table);
    void lookup(int64_t* out, bool* in, size_t length);
};

template <typename IO>
LVT<IO>::LVT(int num_party, int party, MPIOChannel<IO>* io, ThreadPool* pool, ELGL<IO>* elgl, Fr& alpha, int table_size){
    this->io = io;
    this->party = party;
    this->num_party = num_party;
    this->pool = pool;
    this->elgl = elgl;
    this->user_pk.resize(num_party);
    this->user_pk[party] = elgl->kp.get_pk();
    this->tb_size = 1 << table_size;
    this->ciph_.resize(num_party);
}

template <typename IO>
LVT<IO>::LVT(int num_party, int party, MPIOChannel<IO>* io, ThreadPool* pool, ELGL<IO>* elgl, string tableFile, Fr& alpha, int table_size)
    : LVT(num_party, party, io, pool, elgl, alpha, table_size) {
    // load table from file
    deserializeTable(this->table, this->tb_size, table.c_str());
}


template <typename IO>
void LVT<IO>::generate_shares(vector<Plaintext>& lut_share, Plaintext rotation, int num_shares, vector<int64_t> table) {
    std::vector<Ciphertext> ciphertexts;
    vector<std::future<void>> res;
    // everybody calculate their own P_to_m table
    for (size_t i = 0; i < tb_size; i++){
        P_to_m[BLS12381Element(table[i]).getPoint().getStr()] = table[i];
    }

    res.push_back(pool->enqueue([this, rotation, &ciphertexts, table, lut_share](){
        vector<BLS12381Element> c0;
        vector<BLS12381Element> c1;
        vector<BLS12381Element> c0_;
        vector<BLS12381Element> c1_;
        RotationProof proof(global_pk, global_pk, tb_size);
        RotationVerifier verifier(proof);
        if (party == ALICE) {
            // encrypt the table
            std::stringstream comm, response, encMap;
            elgl->DecProof(comm, response, encMap, table, tb_size, c0, c1);
            elgl->serialize_sendall(comm);
            elgl->serialize_sendall(response);
            elgl->serialize_sendall(encMap);
        }else{
            std::stringstream comm, response, encMap;
            elgl->deserialize_recv(comm, ALICE);
            elgl->deserialize_recv(response, ALICE);
            elgl->deserialize_recv(encMap, ALICE);
            elgl->DecVerify(comm, response, encMap, c0, c1, tb_size);
        }

        // everybody cal DFT
        vector<BLS12381Element> ak;
        vector<BLS12381Element> bk;
        FFT(c0, ak, alpha, tb_size);
        FFT(c1, bk, alpha, tb_size);
        vector<BLS12381Element> dk;
        vector<BLS12381Element> ek;
        // read cipher before party
        for (size_t i = 1; i < party; i++)
        {
            vector<BLS12381Element> mk;
            vector<BLS12381Element> nk;
            // TODO: read ciphertexts and proof
            std::stringstream comm_ro, response_ro;
            elgl->deserialize_recv(comm_ro, i);
            elgl->deserialize_recv(response_ro, i);
            verifier.NIZKPoK(ak, bk, mk, nk, comm_ro, response_ro, global_pk, global_pk);
        }
        // rotate
        rotation.set_random(tb_size);
        Plaintext beta, betak;
        Plaintext::pow(beta, alpha, rotation);
        betak.assign("1");
        vector<Plaintext> sk;
        sk.resize(num_party);

        for (size_t i = 0; i < tb_size; i++){
            dk[i] = ak[i] * betak;
            ek[i] = ak[i] * betak;
            betak *= beta;
            sk[i].set_random();
            dk[i] += BLS12381Element(sk[i]);
            ek[i] += global_pk.get_pk()[i] * sk[i];
        }

        
        RotationProver prover(proof);
        std::stringstream commit_ro, response_ro;
        prover.NIZKPoK(proof, commit_ro, response_ro, global_pk, global_pk, dk, ek, ak, bk,beta, sk);

        elgl->serialize_sendall(commit_ro);
        elgl->serialize_sendall(response_ro);


        
        // TODO: read ciphertexts after party
        for (size_t i = party + 1; i <= num_party; i++){
            std::stringstream comm_ro, response_ro;
            elgl->deserialize_recv(comm_ro, i);
            elgl->deserialize_recv(response_ro, i);
            verifier.NIZKPoK(dk, ek, ak, bk, comm_ro, response_ro, global_pk, global_pk);
        }

        // do idft and e to a
        IFFT(dk, c0_, alpha, tb_size);
        IFFT(ek, c1_, alpha, tb_size);

        // E2A
        if (party == ALICE) {
            vector<Plaintext> y_alice;
            vector<Plaintext> d;
            vector<BLS12381Element> L;
            Plaintext exp;
            exp = tb_size * num_party;
            exp -= tb_size;
            vector<BLS12381Element> l_alice(tb_size,BLS12381Element(exp.get_message()));
            
            vector<BLS12381Element> l_(num_party);

            // for each c_1
            for (size_t i = 2; i <= num_party; i++)
            {
                vector<BLS12381Element> y3;
                vector<BLS12381Element> y2;
                std::stringstream commit_ro, response_ro;
                elgl->deserialize_recv(commit_ro, i);
                elgl->deserialize_recv(response_ro, i);
                RangeVerifier verifier(proof);
                verifier.NIZKPoK(user_pk[i-1], y3, y2, commit_ro, response_ro, c0_, global_pk);
                for (size_t j = 0; j < tb_size; j++)
                {
                    l_alice[j] += y2[j];
                }
                
                ciph_[i-1] = y3;
            }
            
            for (size_t i = 0; i < tb_size; i++){
                l_alice[i] += c1_[i];
            }


            // cal c0^-sk * l
            for (size_t i = 0; i < tb_size; i++){
                BLS12381Element Y = l_alice[i] - c0_[i] * elgl->kp.get_sk().get_sk(); 
                Fr y = P_to_m[Y.getPoint().getStr()];
                Fr q, r;
                mcl::gmp::divmod(q, r, y, num_party);
                lut_share.push_back(r);
                d.push_back(q);
                BLS12381Element l(q);
                l += c0_[i] * elgl->kp.get_sk().get_sk();
                L.push_back(l);
                ciph_[0][i] = BLS12381Element(r) + global_pk * elgl->kp.get_sk().get_sk();
            }

            std::stringstream commit_ss, response_ss;
            RangeProof proof(global_pk, tb_size);
            RangeProver prover(proof);
            prover.NIZKPoK(proof, commit_ss, response_ss, global_pk, c0_, ciph_[0], L, lut_share, elgl->kp.get_sk().get_sk());

            elgl->serialize_sendall(commit_ss);
            elgl->serialize_sendall(response_ss);
            // serialize d

            
            
        }else{
            // sample x_i
            mcl::Vint bound = tb_size;
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
                Plaintext ski_neg = elgl.kp.get_sk();
                share_x_i_neg.negate();
                ski_neg.negate();
                l_1 = BLS12381Element(share_x_i_neg.get_message());
                l_1 += c0_[i] * ski_neg;
                l_1_v.push_back(l_1);
                // pack l_1 into l_stream
                // l_1.pack(l_stream);

                // cal cip_i
                cip_ = BLS12381Element(lut_share[i].get_message());
                cip_ += global_pk.get_pk().getPoint() * elgl->kp.get_sk().get_sk();
                cip_v.push_back(cip_);
                // pack cip_i into cip_i_stream
                // cip_.pack(cip_i_stream);
            }
            ciph_[party] = cip_v;
            RangeProof proof(global_pk, tb_size);
            RangeProver prover(proof);

            prover.NIZKPoK(proof, commit_ss, response_ss, global_pk, c0_, cip_v, l_1_v, lut_share, elgl->kp.get_sk());

            // sendall
            elgl->serialize_sendall(commit_ss);
            elgl->serialize_sendall(response_ss);

            // receive all others commit and response
            for (size_t i = 2; i <= num_party; i++){
                if (i != party)
                {
                    vector<BLS12381Element> y3;
                    vector<BLS12381Element> y2;
                    std::stringstream commit_ro, response_ro;
                    elgl->deserialize_recv(commit_ro, i);
                    elgl->deserialize_recv(response_ro, i);
                    RangeVerifier verifier(proof);
                    verifier.NIZKPoK(user_pk[i], y3, y2, commit_ro, response_ro, c0_, global_pk);
                    ciph_[i] = y3;
                }
            }

            // accept broadcast from alice
            std::stringstream commit_ro, response_ro;
            elgl->deserialize_recv(commit_ro, ALICE);
            elgl->deserialize_recv(response_ro, ALICE);
            RangeVerifier verifier(proof);
            vector<BLS12381Element> y2;
            vector<BLS12381Element> y3;
            verifier.NIZKPoK(user_pk[0], y3, y2, commit_ro, response_ro, c0_, global_pk);
            ciph_[0] = y3;
        }
    }
    ));
}

template <typename IO>
void LVT<IO>::DistKeyGen(){
    // first broadcast my own pk
    vector<std::future<void>> tasks;
    global_pk = elgl->kp.get_pk();
    elgl->serialize_sendall(elgl->kp.get_pk());
    for (size_t i = 1; i <= num_party; i++){
        if (i != party){
            tasks.push_back(pool->enqueue([this, i](){
                // rcv other's pk
                ELGL_PK pk;
                elgl->deserialize_recv(pk, i);
                this->user_pk[i] = pk;
            }));
        }
    }
    // cal global pk_
    for (auto& pk : user_pk){
        global_pk += pk;
    }
}

template <typename IO>
LVT<IO>::~LVT(){
    delete[] rotation;
    delete[] lut_share;
}

}

void serializeTable(vector<int64_t>& table, size_t table_size = 1<<20, const char* filename) {
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

void deserializeTable(vector<int64_t>& table, size_t table_size = 1<<20, const char* filename) {
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