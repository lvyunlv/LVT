#include "ELGL_Key.h"

ELGL_PK::ELGL_PK(ELGL_SK& sk){
    pk = BLS12381Element(sk.get_sk());
}

void ELGL_PK::encrypt(Ciphertext &c, const Plaintext& m, std::map<Fp, Fr>& P_to_m) const{
    Fr r;
    r.setByCSPRNG();
    BLS12381Element rG1 = BLS12381Element(r);
    c = Ciphertext(rG1, pk * r + BLS12381Element(m.get_message()));
    P_to_m[BLS12381Element(m.get_message()).getPoint().x] = m.get_message();
}

Ciphertext ELGL_PK::encrypt(const Plaintext& m, std::map<Fp, Fr>& P_to_m) const{
    Fr r;
    r.setByCSPRNG();
    BLS12381Element rG1 = BLS12381Element(r);
    P_to_m[BLS12381Element(m.get_message()).getPoint().x] = m.get_message();
    return Ciphertext(rG1, pk * r + BLS12381Element(m.get_message()));
}

void ELGL_PK::encrypt(Ciphertext& c, const Plaintext& mess, const Random_C rc, std::map<Fp, Fr>& P_to_m) const{
    BLS12381Element rG1 = BLS12381Element(rc);
    c = Ciphertext(rG1, pk * rc + BLS12381Element(mess.get_message()));
    P_to_m[BLS12381Element(mess.get_message()).getPoint().x] = mess.get_message();
}

Ciphertext ELGL_PK::encrypt(const Plaintext& mess, const Random_C rc, std::map<Fp, Fr>& P_to_m) const{
    BLS12381Element rG1 = BLS12381Element(rc);
    P_to_m[BLS12381Element(mess.get_message()).getPoint().x] = mess.get_message();
    return Ciphertext(rG1, pk * rc + BLS12381Element(mess.get_message()));
}

void ELGL_PK::KeyGen(ELGL_SK & sk){
    pk = BLS12381Element(sk.get_sk());
}
void ELGL_SK::decrypt(Plaintext &m, const Ciphertext& c, const std::map<Fp, Fr>& P_to_m) const{
    BLS12381Element tmp = c.get_c0() * sk;
    tmp = c.get_c1() - tmp;
    m.set_message(P_to_m.at(tmp.getPoint().x));
}

Plaintext ELGL_SK::decrypt(const Ciphertext& c, const std::map<Fp, Fr>& P_to_m) const{
    BLS12381Element tmp = c.get_c0() * sk;
    tmp = c.get_c1() - tmp;
    std::cout<< tmp.getPoint().x << std::endl;
    return Plaintext(P_to_m.at(tmp.getPoint().x));
}

void KeyGen(ELGL_PK& PK, ELGL_SK& SK){
    Fr sk_;
    sk_.setByCSPRNG();
    SK.assign_sk(sk_);
    PK.KeyGen(SK);
}