#include "Exp_prover.h"

ExpProver::ExpProver(ExpProof& proof) {
    k.resize(proof.n_proofs);
}


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


BLS12381Element v;

// v = (g^z * g1)^k, z = H(y1,y2)
for (int i = 0; i < P.n_proofs; i++) {

k[i].set_random();
v = BLS12381Element(z.get_message()) + g1;
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

