#include "emp-aby/elgloffline/RotationProof.h"
#include "emp-aby/elgloffline/RotationProver.h"
#include "emp-aby/elgloffline/RotationVerifier.h"
#include "emp-aby/elgl/ELGL_Key.h"
#include "emp-aby/elgl/Plaintext.h"

using namespace std;
int main(){

    BLS12381Element::init();
    ELGL_KeyPair keypair;
    keypair.generate();
    ELGL_PK pk = keypair.get_pk();
    size_t n_tilde = 65536;

    RotationProof proof(pk, pk, n_tilde);
    vector<BLS12381Element> ax, bx, dx, ex;
    ax.resize(n_tilde);
    bx.resize(n_tilde);
    dx.resize(n_tilde);
    ex.resize(n_tilde);

    Plaintext exp, alpha, beta;
    exp.set_random();
    alpha.assign("3465144826073652318776269530687742778270252468765361963008");
    Plaintext::pow(beta, alpha, exp);
    std::cout << "finish beta gen" << std::endl;

    Plaintext a;
    for (size_t i = 0; i < proof.n_tilde; i++){
        a.set_random();
        ax[i] = BLS12381Element(a.get_message());
        a.set_random();
        bx[i] = BLS12381Element(a.get_message());
    }

    std::cout << "finish ax bx gen" << std::endl;

    vector<Plaintext> sk_k;
    sk_k.resize(n_tilde);
    for (size_t i = 0; i < proof.n_tilde; i++){
        sk_k[i].set_random();
    }
    std::cout << "finish sk_k gen" << std::endl;
    //  calculate beta

    vector <Plaintext> betak;
    betak.resize(n_tilde);

    for (size_t i = 0; i < proof.n_tilde; i++){
        // calculate beta^k
        if (i == 0) {betak[i].assign(1);}
        else {betak[i] = betak[i - 1] * beta;}
        dx[i] = BLS12381Element(1) * sk_k[i].get_message();
        dx[i] += ax[i] * betak[i].get_message();
        // e_k = bk ^ betak * h^sk
        ex[i] = pk.get_pk() * sk_k[i].get_message();
        ex[i] += bx[i] * betak[i].get_message();
    }
    std::cout << "finish dk ek gen" << std::endl;
    
    // 增加时间测试prove时长
    std::cout << "prove start" << std::endl;
    auto start = std::chrono::high_resolution_clock::now();
    RotationProver prover(proof);
    stringstream ciphertexts, cleartexts;
    prover.NIZKPoK(proof, ciphertexts, cleartexts, pk, pk, dx, ex, ax, bx, beta, sk_k);
    auto end = std::chrono::high_resolution_clock::now(); 
    std::chrono::duration<double, std::milli> duration = end - start;
    std::cout << "prove end. Time: " << duration.count() << " ms" << std::endl;
    std::cout << "prove end" << std::endl;

    // verifier
    std::cout << "verify start" << std::endl;
    auto start2 = std::chrono::high_resolution_clock::now();
    RotationVerifier verifier(proof);
    verifier.NIZKPoK(dx, ex, ax, bx, ciphertexts, cleartexts, pk, pk);
    auto end2 = std::chrono::high_resolution_clock::now(); 
    std::chrono::duration<double, std::milli> duration2 = end2 - start2;
    std::cout << "verify end. Time: " << duration2.count() << " ms" << std::endl;
    std::cout << "verify end" << std::endl;
}