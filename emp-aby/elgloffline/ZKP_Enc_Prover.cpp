#include "ZKP_Enc_Prover.h"


EncProver::EncProver(Proof& proof)
{
    r1.resize(proof.n_proofs);
    r2.resize(proof.n_proofs);
}

void EncProver::NIZKPoK(Proof& P, std::stringstream& ciphertexts, std::stringstream& cleartexts, const ELGL_PK& pk, const std::vector<Ciphertext>& c, const std::vector<Plaintext>& x, const Proof::Random_C& r) {

    for (unsigned int i = 0; i < c.size(); i++){
      c[i].pack(ciphertexts);
    }

    int V = P.n_proofs;

    // PRNG G;
    // G.ReSeed();
    
    // ciphertexts.store(V);

    BLS12381Element c_0, c_1, c_2;
    // r1: vector of r_1, r2: vector of r_2
    for (int i = 0; i < V; i++) {
        r1[i].set_random();
        r2[i].set_random();

        c_0 = BLS12381Element(r1[i].get_message());

        c_1 = pk.get_pk() * r1[i].get_message();

        c_2 = BLS12381Element(r2[i].get_message());

        // Mul(c_1, c_1, c_2, pk.get_params().get_plaintext_field_data().get_prD());
        c_1 = c_1 + c_2;

        // print c_0 c_1
        std::cout << "c_0: " << c_0.getPoint().getStr() << std::endl;
        std::cout << "c_1: " << c_1.getPoint().getStr() << std::endl;

        // ciphertext.set(c_0, c_1);
        // ciphertext.pack(ciphertexts);
        c_0.pack(ciphertexts);
        c_1.pack(ciphertexts);

    }

    // Challenge
    P.set_challenge(ciphertexts);

    // cleartexts.store(P.n_proofs);

    Plaintext sx, sr;

    for (int i = 0; i < P.n_proofs; i++) {
        // sx = r2 + challenge * x
        // Proof::Mul_under_q_minus_one(sx, P.challenge, x[i].get_p(), pk);
        sx = P.challenge * x[i];
        sx += r2[i];
        sr = P.challenge * r[i];
        sr += r1[i];
        // Proof::Add_under_q_minus_one(sr, sr, r1[i], pk);

        sx.pack(cleartexts);
        sr.pack(cleartexts);
        // print sx sr
    }

  // 返回证明过程中使用的内存大小，包括容量和易失性内存
//   return report_size();
}