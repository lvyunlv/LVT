#include "Plaintext.h"
// #include "gmpxx.h"

Plaintext::Plaintext(){
    message.clear();
}

Plaintext::Plaintext(const Plaintext& other){
    message = other.message;
}

Plaintext::Plaintext(const Fr& other){
    message = other;
}

void Plaintext::assign_zero(){
    message.clear();
}

void Plaintext::assign_one(){
    message = Fr(1);
}
void Plaintext::set_random(){
    message.setByCSPRNG();
}

void Plaintext::set_random(unsigned int bound){
    message.setByCSPRNG();
    if (message.getMpz() > bound){
        message.setMpz(message.getMpz() % bound);
    }
}


void Plaintext::setHashof(const void *msg, size_t msgSize){
    message.setHashOf(msg, msgSize);
}

void Plaintext::assign(const bigint& num){
    message.setMpz(num);
}

void Plaintext::add(Plaintext &z, const Plaintext &x, const Plaintext &y) const{
    Fr::add(z.message, x.message, y.message);
}
void Plaintext::sub(Plaintext &z, const Plaintext &x, const Plaintext &y) const{
    Fr::sub(z.message, x.message, y.message);
}
void Plaintext::mul(Plaintext &z, const Plaintext &x, const Plaintext &y) const{
    Fr::mul(z.message, x.message, y.message);
}
void Plaintext::div(Plaintext &z, const Plaintext &x, const Plaintext &y) const{
    Fr::div(z.message, x.message, y.message);
}
void Plaintext::sqr(Plaintext &z, const Plaintext &x) const{
    Fr::sqr(z.message, x.message);
}

void Plaintext::pow(Plaintext &ret, const Plaintext &x, const Plaintext &exp){
    mpz_class a_mpz, b_mpz, p_mpz, result;

    // 将FpT转换为mpz_class
    x.get_message().getMpz(a_mpz);
    exp.get_message().getMpz(b_mpz);
    std::string p;
    Fr::getModulo(p);
    p_mpz.set_str(p, 10);


    // 计算a^b mod p
    mpz_powm(result.get_mpz_t(), a_mpz.get_mpz_t(), b_mpz.get_mpz_t(), p_mpz.get_mpz_t());
    ret.assign(result);
}


void Plaintext::negate(){
    Fr::neg(message, message);
}

bool Plaintext::equals(const Plaintext &other) const{
    return message == other.message;
}

void Plaintext::pack(octetStream& os) const{
    std::ostringstream ss;
    this->message.save(ss);
    std::string str = ss.str();
    os.store_int(str.size(), 8);
    os.append((octet*)str.c_str(), str.size());

}
void Plaintext::unpack(octetStream& os){
    size_t length = os.get_int(8);
    assert(length > 0);
    std::string str((char*)os.consume(length), length);
    std::istringstream ss(str);
    message.load(ss);
}
