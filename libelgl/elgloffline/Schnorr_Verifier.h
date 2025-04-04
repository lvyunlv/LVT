#ifndef SCHNORR_VERIFIER_H
#define SCHNORR_VERIFIER_H

#include "Schnorr_Proof.h"

class Schnorr_Verifier{
    // std::vector<modp> rd;
    Schnorr_Proof &P;
    public:
    Schnorr_Verifier(Schnorr_Proof& proof);

    void NIZKPoK(std::vector<BLS12381Element>& c, std::stringstream& ciphertexts, std::stringstream& cleartexts);

    // size_t report_size(){return rd.size() * sizeof(modp);};
};

#endif