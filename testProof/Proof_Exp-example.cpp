#include "libelgl/elgloffline/Exp_proof.h"
#include "libelgl/elgloffline/Exp_prover.h"
#include "libelgl/elgloffline/Exp_verifier.h"
#include "libelgl/elgl/ELGL_Key.h"
#include "libelgl/elgl/Plaintext.h"
using namespace std;
int main(){
    BLS12381Element::init();
    ELGL_KeyPair keypair;
    keypair.generate();
    ELGL_PK pk = keypair.get_pk();
    size_t n_tilde = 65536;
    ExpProof proof(pk, n_tilde);

    vector<Plaintext> x;
    vector<BLS12381Element> y1, y2;
    vector<BLS12381Element> y1_, y2_;
    BLS12381Element g1;
    x.resize(n_tilde);
    y1.resize(n_tilde);
    y2.resize(n_tilde);
    y1_.resize(n_tilde);
    y2_.resize(n_tilde);
    Plaintext r1,r2;
    g1 = pk.get_pk();
    for(size_t i = 0; i < n_tilde; i++){
        x[i].set_random();
        r1.set_random();
        r2.set_random();
        // g1 = g^r1, y1 = g^x, y2 = g1^x
        y1[i] = BLS12381Element(x[i].get_message());
        y2[i] = g1 * x[i].get_message();
    }

    std::cout << "finish g1,y1,y2 gen" << std::endl;

    std::cout << "prove start" << std::endl;

    ExpProver prover(proof);
    stringstream ciphertexts, cleartexts;
    // stds::cout << ciphertexts.str()<< std::endl;    
    prover.NIZKPoK(proof, ciphertexts, cleartexts, g1, y1, y2, x);
    std::cout << "prove finish" << std::endl;
    // std::cout << ciphertexts.str()<< std::endl;
    BLS12381Element g1_;
    // std::cout << "verify start" << std::endl;
    ExpVerifier verifier(proof);
    verifier.NIZKPoK(g1_, y1_, y2_, ciphertexts, cleartexts);

}