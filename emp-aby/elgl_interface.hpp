#pragma once



#include "emp-aby/io/mp_io_channel.h"
#include "emp-aby/elgl/Ciphertext.h"
#include "emp-aby/elgl/ELGL_Key.h"
#include "emp-aby/elgl/Plaintext.h"
#include "emp-aby/elgloffline/Exp_proof.h"
#include "emp-aby/elgloffline/Exp_prover.h"
#include "emp-aby/elgloffline/Exp_verifier.h"

// // Required to compile on mac, remove on ubuntu
// #ifdef __APPLE__
//     std::shared_ptr<lbcrypto::PRNG> lbcrypto::PseudoRandomNumberGenerator::m_prng = nullptr;
// #endif

namespace emp {
    // whaaaaat?
    #define MAX_MULT_DEPTH 10

    template <typename IO>
    class ELGL{
        private:
            ThreadPool* pool;
        public:
            ELGL_KeyPair kp;
            PRG prg;
            int party, mult_depth = 3, add_count = 100;
            MPIOChannel<IO>* io;
            int num_party;
            vector<Ciphertext> ciphertext;
            ELGL_PK pk_global;
            
            ELGL(int num_party, MPIOChannel<IO>* io, ThreadPool* pool, int party, int mult_depth = -1, bool keygen = true, bool mult = false, int add_count = 100){
                BLS12381Element::init();
                this->io = io;
                this->party = party;
                this->pool = pool;
                this->num_party = num_party;
                this->mult_depth = mult_depth;
                this->add_count = add_count;
                if (mult_depth == -1) {
                    if (num_party <= MAX_MULT_DEPTH) {
                        this->mult_depth = num_party;
                    }
                    else {
                        this->mult_depth = MAX_MULT_DEPTH;
                        // whaaat?
                        int num_bootstrapping_parties = floor((double)(num_party - 1) / (double)this->mult_depth);
                        this->mult_depth = ceil((double)num_party / (double)(num_bootstrapping_parties + 1));
                    }
                }else{
                    if (mult) {
                        this->mult_depth = 1;
                    }
                }
                if (Ciphertext::DeserializFromFile("data/cc_" + std::to_string(party) + "_" + std::to_string(num_party) + ".txt", ciphertext)){
                    
                    ELGL_PK::DeserializeFromFile("data/pk_" + std::to_string(party) + "_" + std::to_string(num_party) + ".txt", pk);
                    ELGL_PK::DeserializeFromFile("data/kp_public_" + std::to_string(party) + "_" + std::to_string(num_party) + ".txt", kp.publicKey);
                    ELGL_SK::DeserializeFromFile("data/kp_secret_" + std::to_string(party) + "_" + std::to_string(num_party) + ".txt", kp.secretKey);
                    // Ciphertext::DeserializeFromFile("data/eval_mult_key_" + std::to_string(party) + "_" + std::to_string(num_party) + ".txt", kp.evalMultKey);

                }else{
                    if (keygen){
                        kp.generate();
                    }
                }
            }

            ~ELGL(){
                ELGL_PK::SerializeToFile("data/pk_" + std::to_string(party) + "_" + std::to_string(num_party) + ".txt", pk);
                ELGL_PK::SerializeToFile("data/kp_public_" + std::to_string(party) + "_" + std::to_string(num_party) + ".txt", kp.publicKey);
                ELGL_SK::SerializeToFile("data/kp_secret_" + std::to_string(party) + "_" + std::to_string(num_party) + ".txt", kp.secretKey);

            }

            void encryptMap(vector<Ciphertext> vec, int64_t* table, unsigned table_size){
                vec.clear();
                Ciphertext ct;
                for (size_t i = 0; i < table_size; i++){
                    pk.encrypt(ct, table[i]);
                    vec.push_back(ct);
                }
            }

            // 证明： (g, h, g^x, h^x)
            void DecProof(std::stringstream& commitment, std::stringstream& response, std::stringstream& encMap, int64_t* table, unsigned table_size,vector<BLS12381Element>& EncTable_c0, vector<BLS12381Element>& EncTable_c1){
                ExpProof proof(pk_global, table_size);
                vector<BLS12381Element> y3;
                vector<Plaintext> x(table_size);
                // convert int 64 to Plaintext
                for(size_t i = 0; i < table_size; i++){
                    x[i] = Plaintext(strconv.Itoa(table[i]));
                }
                EncTable_c0.resize(table_size);
                EncTable_c1.resize(table_size);
                y3.resize(table_size);
                Plaintext r1,r2;
                for(size_t i = 0; i < table_size; i++){
                    r1.set_random();
                    //y1 = g^r, y2 = gpk^r
                    EncTable_c0[i] = BLS12381Element(r1.get_message());
                    y3[i] = pk_global * r1.get_message();
                    EncTable_c1[i] =  y3[i] + BLS12381Element(x[i]);
                    EncTable_c1[i].pack(encMap);
                }
                std::cout << "finish g1,y1,y2 gen" << std::endl;
                std::cout << "prove start" << std::endl;

                ExpProver prover(proof);
                prover.NIZKPoK(proof, commitment, response, pk_global, EncTable_c0, y3, x);
            }

            void DecVerify(std::stringstream& commitment, std::stringstream& response, std::stringstream& encMap, vector<BLS12381Element>& EncTable_c0, vector<BLS12381Element>& EncTable_c1, unsigned table_size){
                // verify
                ExpProof proof(pk_global, table_size);
                ExpVerifier verifier(proof);
                vector<BLS12381Element> y3;
                verifier.NIZKPoK(pk_global, EncTable_c0, y3, commitment, response);

                for (size_t i = 0; i < 1<< table_size; i++){
                    EncTable_c1[i].unpack(encMap);
                }
            }

            template <typename T>
            void serialize_send(T& obj, int i, int j = 0, MESSAGE_TYPE mt = NORM_MSG){
                std::stringstream s;
                obj.pack(s);
                string str      = s.str();
                int string_size = str.size();
                char* c         = (char*)malloc(string_size);
                s.read(c, string_size);
                io->send_data(i, c, string_size, j, mt);
                io->flush(i, j);
                free(c);
                s.clear();
            }
        
        
            template <typename T>
            void serialize_sendall(T& obj, int j = 0, MESSAGE_TYPE mt = NORM_MSG){
                std::stringstream s;
                obj.pack(s);
                string str      = s.str();
                int string_size = str.size();
                char* c         = (char*)malloc(string_size);
                s.read(c, string_size);
            std::vector<std::future<void>> res;
            for (int i = 1; i <= num_party; ++i) {
                if (i != party) {
                    res.push_back(std::async([this, i, c, string_size, j, mt]() {
                        io->send_data(i, c, string_size, j, mt);
                        io->flush(i, j);
                    }));
                }
            }
            for (auto& fut : res)
                fut.get();
            res.clear();
            free(c);
            s.clear();
        }
        
            template <typename T>
            void deserialize_recv(T& obj, int i, int j = 0, MESSAGE_TYPE mt = NORM_MSG) {
                std::stringstream s;
                int string_size = 0;
                char* c         = (char*)io->recv_data(i, string_size, j, mt);
                s.write(c, string_size);
                // printf("%d %d\n", party, string_size);
                free(c);
                obj.unpack(s);
                s.clear();
            }
    };



}