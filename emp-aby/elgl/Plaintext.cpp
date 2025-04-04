#include "emp-aby/elgl/Plaintext.h"
#include <fstream>
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

void Plaintext::set_random(mcl::Vint bound){
    message.setByCSPRNG();
    if (message.getMpz() > bound){
        message.setMpz(message.getMpz() % bound);
    }
}


void Plaintext::setHashof(const void *msg, size_t msgSize){
    message.setHashOf(msg, msgSize);
}

void Plaintext::assign(const std::string num){
    message.setStr(num);
}

void Plaintext::assign(const mpz_class num){
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
    p_mpz.setStr(p, 10);


    // 计算a^b mod p
    mcl::gmp::powMod(result, a_mpz, b_mpz, p_mpz);
    ret.assign(result);
    ret.assign(result);
}


void Plaintext::negate(){
    Fr::neg(message, message);
}

bool Plaintext::equals(const Plaintext &other) const{
    return message == other.message;
}

void Plaintext::pack(std::stringstream& os) const{
    this->message.save(os);

}
void Plaintext::unpack(std::stringstream& os){
    message.load(os);
}

bool Plaintext::DeserializFromFile(std::string filepath, Plaintext& p){
    // load message from file
    std::ifstream file(filepath);
    if (file.is_open()){
        p.message.load(file);
        file.close();
        return true;
    } else {
        std::cerr << "Unable to open file";
        return false;
    }
}

bool Plaintext::SerializeToFile(std::string filepath, Plaintext& p){
    // pack message into file
    std::ofstream file(filepath);
    if (file.is_open()){
        p.message.save(file);
        file.close();
        return true;
    }else{
        std::cerr << "Unable to open file";
        return false;
    }
}