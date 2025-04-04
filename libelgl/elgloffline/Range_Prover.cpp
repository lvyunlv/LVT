#include "Range_Prover.h"
#include <future>

RangeProver::RangeProver(RangeProof& proof) {
    r1.resize(proof.n_proofs);
    r2.resize(proof.n_proofs);
}


size_t RangeProver::NIZKPoK(RangeProof& P,
    std::stringstream& ciphertexts,
    std::stringstream& cleartexts,
    const ELGL_PK& pk,
    const std::vector<BLS12381Element>& g1,
    const std::vector<BLS12381Element>& y3,
    const std::vector<BLS12381Element>& y2,
    const std::vector<Plaintext>& x,
    const Plaintext& ski){
    // TODO: check if allocate is enough

    for (unsigned int i = 0; i < y3.size(); ++i) {
        y2[i].pack(ciphertexts);
        y3[i].pack(ciphertexts);
    }
    
    int V = P.n_proofs;

    BLS12381Element c_0, c_1, c_2, c_3;

    for (int i = 0; i < V; i++) {
        // init r1 r2
        r1[i].set_random();
        r2[i].set_random();

        // t1 = g^r1
        c_0 = BLS12381Element(r1[i].get_message());

        // t3 = pk^r1 * g^r2
        c_1 = pk.get_pk() * r1[i].get_message();

        c_2 = BLS12381Element(r2[i].get_message());

        c_1 += c_2;

        // t2 = g1^r1 * g^r2
        c_2 = g1[i] * r1[i].get_message(); 
        c_3 = BLS12381Element(r2[i].get_message());
        c_2 += c_3;
        
        c_0.pack(ciphertexts);
        c_2.pack(ciphertexts);
        c_1.pack(ciphertexts);
        // print c_0 c_1 c_2
        std::cout << "prover c_0: " << std::endl;
        c_0.print_str();
        std::cout << "prover c_1: " << std::endl;
        c_1.print_str();
        std::cout << "prover c_2: " << std::endl;
        c_2.print_str();
    }

    P.set_challenge(ciphertexts);


    // cleartexts.store(P.n_proofs);
    // // print n_proofs
    // std::cout << "prover n_proofs: " << P.n_proofs << std::endl;

    Plaintext sx, sr;

    for (int i = 0; i < P.n_proofs; i++){
        sx = P.challenge * x[i];
        sx += r2[i];
        sx.pack(cleartexts);

        sr = P.challenge * ski;
        sr += r1[i];
        sr.pack(cleartexts);
        // print sx sr
        std::cout << "prover sx: " << sx.get_message() << std::endl;
        std::cout << "prover sr: " << sr.get_message() << std::endl;
    }
    return report_size();
}

size_t RangeProver::report_size(){
    size_t res = 0;
    res += r1.size() * sizeof(r1[0]);
    return res;
}

// void RangeProver::report_size(MemoryUsage& res)
// {
//   res.update("prover r1", r1.size() * sizeof(r1[0]));
//   res.update("prover r2", r2.size() * sizeof(r2[0]));
// }

