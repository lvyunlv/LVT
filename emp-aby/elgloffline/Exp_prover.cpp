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
    // size_t allocate = (3 * y1.size() + 2) * sizeof(y1[0]);
    // ciphertexts.resize_precise(allocate);
    // ciphertexts.reset_write_head();

    Plaintext z;

    for (unsigned int i = 0; i < y1.size(); i++){
        g1[i].pack(ciphertexts);
        y1[i].pack(ciphertexts);
        y2[i].pack(ciphertexts);
    }
    // z = H(g1,y1,y2)
    auto* buf = ciphertexts.rdbuf();
    std::streampos size = buf->pubseekoff(0,ciphertexts.end, ciphertexts.in);
    buf->pubseekpos(0, ciphertexts.in);
    char* tmp = new char[size];
    buf->sgetn(tmp, size);
    z.setHashof(tmp, size); 
    // int V = P.n_proofs;

    // PRNG G;
    // G.ReSeed();

    // ciphertexts.store(V);

    BLS12381Element v;

    // v = (g^z * g1)^k, z = H(y1,y2)
    for (int i = 0; i < P.n_proofs; i++) {
        
        k[i].set_random();
        v = BLS12381Element(z.get_message()) + g1[i];
        v = v * k[i].get_message();
        v.pack(ciphertexts);
    }

    P.set_challenge(ciphertexts);

    // size_t allocate2 = (P.n_proofs * 1 + 5) * sizeof(x[0]);
    // cleartexts.resize_precise(allocate2);
    // cleartexts.reset_write_head();

    // cleartexts.store(P.n_proofs);

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
// size_t allocate = (3 * y1.size() + 2) * sizeof(y1[0]);
// ciphertexts.resize_precise(allocate);
// ciphertexts.reset_write_head();

Plaintext z;

for (unsigned int i = 0; i < y1.size(); i++){
g1.pack(ciphertexts);
y1[i].pack(ciphertexts);
y2[i].pack(ciphertexts);
}
// z = H(g1,y1,y2)
auto* buf = ciphertexts.rdbuf();
std::streampos size = buf->pubseekoff(0,ciphertexts.end, ciphertexts.in);
buf->pubseekpos(0, ciphertexts.in);
char* tmp = new char[size];
buf->sgetn(tmp, size);
z.setHashof(tmp, size); 
// int V = P.n_proofs;

// PRNG G;
// G.ReSeed();

// ciphertexts.store(V);

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

