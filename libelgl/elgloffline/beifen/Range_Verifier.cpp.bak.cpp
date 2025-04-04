#include "Range_Verifier.h"
#include <future>
RangeVerifier::RangeVerifier(RangeProof& proof) :
    P(proof)
{
}


void RangeVerifier::NIZKPoK(const BLS12381Element y1, std::vector<BLS12381Element>& y3, std::vector<BLS12381Element>& y2, std::stringstream& ciphertexts, std::stringstream& cleartexts, const std::vector<BLS12381Element>& g1,
    const ELGL_PK& pk){
    

    ciphertexts.seekg(0, std::ios::beg);
    cleartexts.seekg(0, std::ios::beg);
    P.set_challenge(ciphertexts);
    ciphertexts.seekg(0, std::ios::beg);
    

    // mpz_class bound_;
    // bound_.load(ciphertexts);
    // std::cout << "bound: " << bound_ << std::endl;

    for (int i = 0; i < P.n_proofs; i++){
        y2[i].unpack(ciphertexts);
        y3[i].unpack(ciphertexts);
    }

    // bigint tmp;

    std::vector<Plaintext> sx_tmp, sr_tmp;
    std::vector<BLS12381Element> t1, t2, t3;
    sx_tmp.resize(P.n_proofs);
    sr_tmp.resize(P.n_proofs);
    t1.resize(P.n_proofs);
    t2.resize(P.n_proofs);
    t3.resize(P.n_proofs);

    for (size_t i = 0; i < P.n_proofs; i++)
    {
        sx_tmp[i].unpack(cleartexts);
        sr_tmp[i].unpack(cleartexts);
        t1[i].unpack(ciphertexts);
        t2[i].unpack(ciphertexts);
        t3[i].unpack(ciphertexts);

        std::cout << "sx: " << sx_tmp[i].get_message() << std::endl;
        std::cout << "sr: " << sr_tmp[i].get_message() << std::endl;
    }

    std::cout << "verify:" << std::endl;
    std::vector<std::future<void>> futures;
    futures.reserve(P.n_proofs);
    for (int i = 0; i < P.n_proofs; i++){
        futures.push_back(std::async(std::launch::async, [&, i]() {
        // g^sr 1 eq left
        BLS12381Element gsr, gsx, gsxhsr;
        // modp y_1_tmp, y_2_tmp;
        BLS12381Element t1y1lamda, t2y2lamda;        
        // bigint sx_bigint;
        BLS12381Element gsxg1sr, t3y3lambda;

        gsr = BLS12381Element(sr_tmp[i].get_message());
        gsx = BLS12381Element(sx_tmp[i].get_message());
        
        // g^sx * h^sr2 2 eq left
        gsxhsr = pk.get_pk() * sr_tmp[i].get_message();
        gsxhsr += gsx;

        // t1 * y1^lambda 1 eq right 
        // RangeProof::Power_modp(t1y1lamda, c[i].get_c0(), P.challenge, pk);
        t1y1lamda = y1 * P.challenge.get_message();
        t1y1lamda +=t1[i];
        gsr.print_str();
        t1y1lamda.print_str();

        // t2 * y2^lambda 2 eq right
        t2y2lamda = y2[i] * P.challenge.get_message();
        t2y2lamda += t2[i];

        // g^sx * g1^sr 3 eq left
        gsxg1sr = g1[i] * sr_tmp[i].get_message();
        gsxg1sr += gsx;
        gsxg1sr.print_str();
        t2y2lamda.print_str();

        // t3 * y3^lambda 3 eq right
        t3y3lambda = y3[i] * P.challenge.get_message();
        t3y3lambda += t3[i];
        gsxhsr.print_str();
        t3y3lambda.print_str();

        if (gsr != t1y1lamda){
            throw std::runtime_error("invalid proof: gsr!= t1y1lamda");
        }
        if (gsxg1sr!= t2y2lamda){
            throw std::runtime_error("invalid proof: gsxg1sr!= t2y2lamda");
        }
        if (gsxhsr!= t3y3lambda){
            throw std::runtime_error("invalid proof: gsxhsr!= t3y3lambda");
        }
        if (gsr != t1y1lamda || gsxhsr != t3y3lambda || gsxg1sr != t2y2lamda){
            throw std::runtime_error("invalid proof");
        }
        }));
        
    }
    for (auto& f : futures) {
        f.get();
    }
    futures.clear();
    std::cout << "valid proof" << std::endl;
}