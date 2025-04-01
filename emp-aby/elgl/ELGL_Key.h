#ifndef _ELGL_Key
#define _ELGL_Key

#include "Ciphertext.h"
#include "BLS12381Element.h"
#include "ELGL/Plaintext.h"
class ELGL_PK;
class Ciphertext;
class ELGL_SK{
    Fr sk;

    public:
    // don't know why it returns 0
    static int size(){return 0;};

    Fr get_sk() const{return sk;};

    void assign_sk(const Fr& sk_){sk = sk_;};

    void assign_sk(const bigint& sk_){
        sk.setMpz(sk_);
    };

    ELGL_SK(){};

    void pack(octetStream& os) const{
        std::ostringstream ss;
        sk.save(ss);
        std::string str = ss.str();
        os.store_int(str.size(), 8);
        os.append((octet*)str.c_str(), str.size());
    };

    void unpack(octetStream& os){
        size_t length = os.get_int(8);
        assert(length > 0);
        std::string str((char*)os.consume(length), length);
        std::istringstream ss(str);
        sk.load(ss);
    };
    void decrypt(Plaintext &m, const Ciphertext& c, const std::map<Fp, Fr>& P_to_m) const;

    Plaintext decrypt(const Ciphertext& c, const std::map<Fp, Fr>& P_to_m) const;

    friend void KeyGen(ELGL_PK& PK, ELGL_SK& SK);

    ELGL_SK& operator+=(const ELGL_SK& c){
        Fr::add(sk, sk, c.sk);
        return *this;
    }

    ELGL_SK operator+(const ELGL_SK& x) const {
        ELGL_SK result;
        Fr::add(result.sk, sk, x.sk);
        return result;
    }

    bool operator!=(const ELGL_SK& other) const{
        return sk != other.sk;
    }
};

class ELGL_PK{
    BLS12381Element pk;
    public:
    typedef Fr Random_C;
    BLS12381Element get_pk() const{return pk;};
    void assign_pk(const BLS12381Element& pk_){pk = pk_;};

    ELGL_PK(){pk = BLS12381Element();};

    ELGL_PK(ELGL_SK& sk);

    void encrypt(Ciphertext &c, const Plaintext& m, std::map<Fp, Fr>& P_to_m) const;

    Ciphertext encrypt(const Plaintext& mess, std::map<Fp, Fr>& P_to_m) const;

    void encrypt(Ciphertext& c, const Plaintext& mess, const Random_C rc, std::map<Fp, Fr>& P_to_m) const;

    Ciphertext encrypt(const Plaintext& mess, const Random_C rc, std::map<Fp, Fr>& P_to_m) const;

    friend void KeyGen(ELGL_PK& PK, ELGL_SK& SK);
    void KeyGen(ELGL_SK & sk);

    void pack(octetStream& os) const {pk.pack(os);};

    void unpack(octetStream& os) {pk.unpack(os);};

    bool operator!= (const ELGL_PK& other) const{
        return pk!= other.pk;
    };
};

class ELGL_KeyPair{
    ELGL_PK pk;
    ELGL_SK sk;
    public:
    ELGL_KeyPair(){};
    void generate(){
        KeyGen(pk, sk);
    };
    ELGL_PK get_pk() const{return pk;};
    ELGL_SK get_sk() const{return sk;};
};

#endif