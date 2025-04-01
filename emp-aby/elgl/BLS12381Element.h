#ifndef BLS12381_BLS12381ELEMENT_H_
#define BLS12381_BLS12381ELEMENT_H_
#include <mcl/bls12_381.hpp>

using namespace mcl::bn;


class BLS12381Element{
    public:
        // typedef gfp_<2, 4> Scalar;
    private:
    G1 point;

    public:
    static int size() { return 0; }
    // TODO: check if this is correct
    static int length() { return 384; }
    static std::string type_string() { return "BLS12381"; }
    void print_str() const;

    G1 getPoint() { return point; }

    static void init();
    static void finish();

    BLS12381Element();
    BLS12381Element(const BLS12381Element& other);
    BLS12381Element(const Fr& other);
    ~BLS12381Element();

    BLS12381Element& operator=(const BLS12381Element& other);

    void check();
    // Scalar x() const;

    BLS12381Element operator+(const BLS12381Element& other) const;
    BLS12381Element operator-(const BLS12381Element& other) const;
    BLS12381Element operator*(const Fr& other) const;

    BLS12381Element& operator+=(const BLS12381Element& other);
    BLS12381Element& operator*=(const Fr& other);
    BLS12381Element& operator/=(const Fr& other);

    bool operator==(const BLS12381Element& other) const;
    bool operator!=(const BLS12381Element& other) const;

    void pack(octetStream& os, int = -1) const;
    void unpack(octetStream& os, int = -1);
    
    void output(ostream& s, bool human) const;

    friend ostream& operator<<(ostream& s, const BLS12381Element& x);
};

BLS12381Element operator*(const Fr& a, const BLS12381Element& b);
#endif