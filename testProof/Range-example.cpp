#include "ELGLOffline/Range_Prover.h"
#include "ELGLOffline/Range_Verifier.h"
#include "ELGL/ELGL_Key.h"
#include "ELGL/Plaintext.h"

using namespace std;
int main(){
    BLS12381Element::init();
    ELGL_KeyPair key;
    key.generate();
    
    RangeProof proof(key.get_pk(), 65536, 1);
    Plaintext r;
    r.set_random();
    ELGL_PK pk = key.get_pk();
    // calculate y1 y3
    vector<Plaintext> x;
    BLS12381Element y1;
    vector<BLS12381Element> y2, y3;
    vector<BLS12381Element> g1;
    x.resize(proof.n_proofs);
    g1.resize(proof.n_proofs);
    y2.resize(proof.n_proofs);
    y3.resize(proof.n_proofs);
    y1 = BLS12381Element(r.get_message());

    for(size_t i = 0; i < proof.n_proofs; i++){
        x[i].set_random(proof.bound);
        g1[i] = BLS12381Element(x[i].get_message());
        y2[i] = BLS12381Element(x[i].get_message()) + g1[i] * r.get_message();
        y3[i] = BLS12381Element(x[i].get_message()) + pk.get_pk() * r.get_message();
    }

    RangeProver prover(proof);
    std::stringstream ciphertexts, cleartexts;

    prover.NIZKPoK(proof, ciphertexts, cleartexts, pk, g1, y3, y2, x, r);
    // verifier

    RangeVerifier verifier(proof);
    verifier.NIZKPoK(y1, y3, y2, ciphertexts, cleartexts, g1, pk);
    return 0;
}