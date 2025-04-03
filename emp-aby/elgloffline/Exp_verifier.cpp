#include "Exp_verifier.h"

ExpVerifier::ExpVerifier(ExpProof& proof) :
    P(proof)
{
    s.resize(proof.n_proofs);
}

void ExpVerifier::NIZKPoK(vector<BLS12381Element>& g1, vector<BLS12381Element>& y1,vector<BLS12381Element>& y2, std::stringstream& ciphertexts, std::stringstream&  cleartexts){
    P.set_challenge(ciphertexts);

    // bigint bound;
    // bound.unpack(cleartexts);
    Plaintext z;
    // z = H(g1,y1,y2)
    for (int i = 0; i < P.n_proofs; i++){
        // remember initial
        g1[i].unpack(ciphertexts);
        y1[i].unpack(ciphertexts);
        y2[i].unpack(ciphertexts);
    }
    auto* buf = ciphertexts.rdbuf();
    std::streampos size = buf->pubseekoff(0,ciphertexts.end, ciphertexts.in);
    buf->pubseekpos(0, ciphertexts.in);
    char* tmp = new char[size];
    buf->sgetn(tmp, size);
    z.setHashof(tmp, size); 
    // ciphertexts.get(V);
    // if (V != P.n_proofs)
    //     throw length_error("number of received commitments incorrect");

    BLS12381Element t1, t2, t3;
    
    // v = (g^z * g1)^s * (y1^z * y2)^challenge, 
    Plaintext s;

    BLS12381Element v, Right1, Right2;
    for (int i = 0; i < P.n_proofs; i++){
        s.unpack(cleartexts);
        v.unpack(ciphertexts);

        Right1 = BLS12381Element(z.get_message()) + g1[i];
        Right1 = Right1 * s.get_message();
        
        Right2 = y1[i] * z.get_message() + y2[i];
        Right2 = Right2 * P.challenge.get_message();

        Right1 += Right2;

        if (v != Right1 ){
            throw runtime_error("invalid proof");
        }
    }
    cout << "valid proof" << endl;
}

void ExpVerifier::NIZKPoK(BLS12381Element& g1, vector<BLS12381Element>& y1,vector<BLS12381Element>& y2, std::stringstream&  ciphertexts, std::stringstream&  cleartexts){
    P.set_challenge(ciphertexts);

    // bigint bound;
    // bound.unpack(cleartexts);
    Plaintext z;
    // z = H(g1,y1,y2)
    for (int i = 0; i < P.n_proofs; i++){
        // remember initial
        g1.unpack(ciphertexts);
        y1[i].unpack(ciphertexts);
        y2[i].unpack(ciphertexts);
    }
    auto* buf = ciphertexts.rdbuf();
    std::streampos size = buf->pubseekoff(0,ciphertexts.end, ciphertexts.in);
    buf->pubseekpos(0, ciphertexts.in);
    char* tmp = new char[size];
    buf->sgetn(tmp, size);
    z.setHashof(tmp, size); 
    // ciphertexts.get(V);
    // if (V != P.n_proofs)
    //     throw length_error("number of received commitments incorrect");

    BLS12381Element t1, t2, t3;
    
    // v = (g^z * g1)^s * (y1^z * y2)^challenge, 
    Plaintext s;

    BLS12381Element v, Right1, Right2;
    for (int i = 0; i < P.n_proofs; i++){
        s.unpack(cleartexts);
        v.unpack(ciphertexts);

        Right1 = BLS12381Element(z.get_message()) + g1;
        Right1 = Right1 * s.get_message();
        
        Right2 = y1[i] * z.get_message() + y2[i];
        Right2 = Right2 * P.challenge.get_message();

        Right1 += Right2;

        if (v != Right1 ){
            throw runtime_error("invalid proof");
        }
    }
    cout << "valid proof" << endl;
}