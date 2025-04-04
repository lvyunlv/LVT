#include "Range_Prover.h"
#include <future>
#include <mutex>
#include <iostream>

RangeProver::RangeProver(RangeProof& proof) {
    r1.resize(proof.n_proofs);
    r2.resize(proof.n_proofs);
}

struct thread_return1 {
    BLS12381Element t1;
    BLS12381Element t2;
    BLS12381Element t3;
    Plaintext rr1;
    Plaintext rr2;
};

struct thread_return2 {
    Plaintext sr;
    Plaintext sx;
};

size_t RangeProver::NIZKPoK(RangeProof& P,
                            std::stringstream& ciphertexts,
                            std::stringstream& cleartexts,
                            const ELGL_PK& pk,
                            const std::vector<BLS12381Element>& g1,
                            const std::vector<BLS12381Element>& y3,
                            const std::vector<BLS12381Element>& y2,
                            const std::vector<Plaintext>& x,
                            const Plaintext& ski) {

    std::cout << "prover bound: " << P.bound << std::endl;

    // Pack y3 and y2 into ciphertexts
    for (unsigned int i = 0; i < y3.size(); ++i) {
        y2[i].pack(ciphertexts);
        y3[i].pack(ciphertexts);
    }

    std::vector<std::future<thread_return1>> futures1;
    futures1.reserve(P.n_proofs);

    for (size_t i = 0; i < P.n_proofs; ++i) {
        futures1.emplace_back(std::async(std::launch::async, [this, &pk, &g1, i]() -> thread_return1 {
            Plaintext rr1, rr2;
            rr1.set_random();
            rr2.set_random();

            BLS12381Element t1 = BLS12381Element(rr1.get_message());

            BLS12381Element t2 = g1[i] * rr1.get_message();
            t2 += BLS12381Element(rr2.get_message());

            BLS12381Element t3 = pk.get_pk() * rr1.get_message();
            t3 += BLS12381Element(rr2.get_message());

            return {t1, t2, t3, rr1, rr2};
        }));
    }
    BLS12381Element t1y1lamda;
    for (auto& f : futures1) {
        thread_return1 result = f.get();
        result.t1.pack(ciphertexts);
        result.t2.pack(ciphertexts);
        result.t3.pack(ciphertexts);
        t1y1lamda = BLS12381Element(ski.get_message()) * P.challenge.get_message() + result.t1;
        r1.push_back(result.rr1);
        r2.push_back(result.rr2);
    }

    futures1.clear();

    P.set_challenge(ciphertexts);

    std::vector<std::future<thread_return2>> futures2;
    futures2.reserve(P.n_proofs);

    for (size_t i = 0; i < P.n_proofs; ++i) {
        futures2.emplace_back(std::async(std::launch::async, [&, i]() -> thread_return2 {
            Plaintext sx = P.challenge * x[i];
            sx += r2[i];
            Plaintext sr = P.challenge * ski;
            sr += r1[i];
            return {sr, sx};
        }));
    }

    for (auto& f : futures2) {
        thread_return2 result = f.get();
        result.sx.pack(cleartexts);
        result.sr.pack(cleartexts);
        std::cout << "sx: " << result.sx.get_message() << std::endl;
        std::cout << "sr: " << result.sr.get_message() << std::endl;
        BLS12381Element gsr = BLS12381Element(result.sr.get_message());
        if (gsr != t1y1lamda){
            std::cout << "gsr != t1y1lamda" << std::endl;
            std::cout << "gsr: " << gsr << std::endl;
            std::cout << "t1y1lamda: " << t1y1lamda << std::endl;
        }else{
            std::cout << "gsr == t1y1lamda" << std::endl;
        }

    }

    futures2.clear();

    // ceshi
    // cal gsr

    return report_size();
}

size_t RangeProver::report_size() {
    size_t res = 0;
    res += r1.size() * sizeof(r1[0]);
    res += r2.size() * sizeof(r2[0]);
    return res;
}
