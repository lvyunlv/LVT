#include "Range_Verifier.h"

RangeVerifier::RangeVerifier(RangeProof& proof) :
    P(proof)
{
}


void RangeVerifier::NIZKPoK(const ELGL_PK pki, std::vector<BLS12381Element>& y3, std::vector<BLS12381Element>& y2, std::stringstream& ciphertexts, std::stringstream& cleartexts, const std::vector<BLS12381Element>& g1,
    const ELGL_PK& pk){
    

    
    P.set_challenge(ciphertexts);

    mpz_class bound_;
    bound_.load(ciphertexts);
    std::cout << "bound: " << bound_ << std::endl;

    for (int i = 0; i < P.n_proofs; i++){
        y3[i].unpack(ciphertexts);
        y2[i].unpack(ciphertexts);
    }

    // bigint tmp;

    BLS12381Element t1, t2, t3;
    
    Plaintext sx_tmp, sr_tmp;

    BLS12381Element gsr, gsx, gsxhsr;
    // modp y_1_tmp, y_2_tmp;
    BLS12381Element t1y1lamda, t2y2lamda;        
    // bigint sx_bigint;
    BLS12381Element gsxg1sr, t3y3lambda;
    for (int i = 0; i < P.n_proofs; i++){
        sx_tmp.unpack(cleartexts);
        sr_tmp.unpack(cleartexts);
        // print sx and sr

        std::cout << "sx[" << i << "]: " << sx_tmp.get_message() << std::endl;
        std::cout << "sr[" << i << "]: " << sr_tmp.get_message() << std::endl;

        t1.unpack(ciphertexts);
        t2.unpack(ciphertexts);
        t3.unpack(ciphertexts);
        // print t1 t2 t3
        std::cout << "t1[" << i << "]: " << std::endl;
        t1.print_str();
        std::cout << "t2[" << i << "]: " << std::endl;
        t2.print_str();
        std::cout << "t3[" << i << "]: " << std::endl;
        t3.print_str();

        // g^sr 1 eq left
        gsr = BLS12381Element(sr_tmp.get_message());
        gsx = BLS12381Element(sx_tmp.get_message());
        
        // g^sx * h^sr2 2 eq left
        gsxhsr = pk.get_pk() * sr_tmp.get_message();
        gsxhsr += gsx;

        // t1 * y1^lambda 1 eq right 
        // RangeProof::Power_modp(t1y1lamda, c[i].get_c0(), P.challenge, pk);
        t1y1lamda = pki.get_pk() * P.challenge.get_message();
        t1y1lamda += t1;

        // t2 * y2^lambda 2 eq right
        t2y2lamda = y2[i] * P.challenge.get_message();
        t2y2lamda += t2;

        // g^sx * g1^sr 3 eq left
        gsxg1sr = g1[i] * sr_tmp.get_message();
        gsxg1sr += gsx;

        // t3 * y3^lambda 3 eq right
        t3y3lambda = y3[i] * P.challenge.get_message();
        t3y3lambda += t3;
        if (gsr != t1y1lamda){
            throw std::runtime_error("invalid proof: gsr!= t1y1lamda");
        }
        if (gsxhsr!= t3y3lambda){
            throw std::runtime_error("invalid proof: gsxhsr!= t3y3lambda");
        }
        if (gsxg1sr!= t2y2lamda){
            throw std::runtime_error("invalid proof: gsxg1sr!= t2y2lamda");
        }
        if (gsr != t1y1lamda || gsxhsr != t3y3lambda || gsxg1sr != t2y2lamda){
            throw std::runtime_error("invalid proof");
        }
    }
    std::cout << "valid proof" << std::endl;
}