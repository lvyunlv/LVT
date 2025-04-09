#include "Exp_prover.h"
#include <future>
ExpProver::ExpProver(ExpProof& proof) {
    k.resize(proof.n_proofs);
}

struct thread1Ret
{
    BLS12381Element v;
};

struct thread2Ret
{
    Plaintext s;
};
// not parallel yet
size_t ExpProver::NIZKPoK(ExpProof& P, std::stringstream&  ciphertexts, std::stringstream&  cleartexts,
               const vector<BLS12381Element>& g1,
               const vector<BLS12381Element>& y1,
               const vector<BLS12381Element>& y2,
               const vector<Plaintext>& x){
                // TODO: check if allocate is enough


    Plaintext z;

    for (unsigned int i = 0; i < y1.size(); i++){
        g1[i].pack(ciphertexts);
        y1[i].pack(ciphertexts);
        y2[i].pack(ciphertexts);
    }
    // z = H(g1,y1,y2)

    z.setHashof(ciphertexts.str().c_str(), ciphertexts.str().size()); 


    BLS12381Element v;

    // v = (g^z * g1)^k, z = H(y1,y2)
    for (int i = 0; i < P.n_proofs; i++) {
        
        k[i].set_random();
        v = BLS12381Element(z.get_message()) + g1[i];
        v = v * k[i].get_message();
        v.pack(ciphertexts);
    }

    P.set_challenge(ciphertexts);



    Plaintext s;

    // s = k - x * challenge
    for (int i = 0; i < P.n_proofs; i++){
        s = k[i];
        s -= x[i] * P.challenge;
        s.pack(cleartexts);
    }
    return report_size();
}

size_t ExpProver::NIZKPoK(ExpProof& P, std::stringstream&  ciphertexts, std::stringstream&  cleartexts,
    const BLS12381Element& g1,
    const vector<BLS12381Element>& y1,
    const vector<BLS12381Element>& y2,
    const vector<Plaintext>& x){
     // TODO: check if allocate is enough


    Plaintext z;
    g1.pack(ciphertexts);
    for (unsigned int i = 0; i < y1.size(); i++){
        y1[i].pack(ciphertexts);
        y2[i].pack(ciphertexts);
    }
    // z = H(g1,y1,y2)

    z.setHashof(ciphertexts.str().c_str(), ciphertexts.str().size()); 
    // int V = P.n_proofs;


    

    std::vector<std::future<thread1Ret>> futures1;
    // v = (g^z * g1)^k, z = H(y1,y2)
    for (int i = 0; i < P.n_proofs; i++) {
        futures1.emplace_back(std::async(std::launch::async, [this, &g1, &z, i]() -> thread1Ret {
            BLS12381Element v;
            this->k[i].set_random();
            v = BLS12381Element(z.get_message()) + g1;
            v = v * k[i].get_message();
            return {v};
        }));
    }

    for (auto& f : futures1) {
        thread1Ret result = f.get();
        result.v.pack(ciphertexts);
    }

    P.set_challenge(ciphertexts);


    std::vector<std::future<thread2Ret>> futures2;
    // s = k - x * challenge
    for (int i = 0; i < P.n_proofs; i++){
        futures2.emplace_back(std::async(std::launch::async, [this, &x, &P, i]() -> thread2Ret {
            Plaintext s;
            s = this->k[i];
            s -= x[i] * P.challenge;
            return {s};
        }));
    }

    for (auto & f : futures2) {
        thread2Ret result = f.get();
        result.s.pack(cleartexts);
    }
    futures1.clear();
    futures2.clear();
    return report_size();
}

size_t ExpProver::report_size(){
    size_t res = 0;
    res += sizeof(k);
    res *= k.size();
    return res;
}

// void ExpProver::report_size(MemoryUsage& res)
// {
//   res.update("prover k", k.size());
// }

