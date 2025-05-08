#include "FixedPointConverter.h"
#include <iostream>
#include <vector>
#include <iomanip>

int main() {
    std::vector<double> test_values = {
        0.0, 1.0, -1.0, 3.14159, -2.71828,
        12345.6789, -12345.6789, 0.00001, -0.00001
    };

    std::cout << std::fixed << std::setprecision(6);
    std::cout << "=== Q8.16 Fixed Point Encoding Test ===\n";

    for (double val : test_values) {
        uint64_t encoded = FixedPointConverter::encode(val);
        double decoded = FixedPointConverter::decode(encoded);

        std::cout << "Original: " << val
                  << " -> Encoded: " << encoded
                  << " -> Decoded: " << decoded << "\n";
    }
    double a = -127.99999, b = 127.99999, a_plus_b = 0.0;
    uint64_t encoded_a = FixedPointConverter::encode(a);
    uint64_t encoded_b = FixedPointConverter::encode(b);
    uint64_t encoded_a_plus_b = FixedPointConverter::encode(a_plus_b);

    std::cout << "Encoded a: " << encoded_a << ", Encoded b: " << encoded_b << std::endl;
    std::cout << "Encoded a + b: " << encoded_a_plus_b << std::endl;

    uint64_t encoded_a_plus_b_2 = encoded_a + encoded_b;
    std::cout << "Encoded a + b: " << encoded_a_plus_b_2 << std::endl;
 
    uint64_t field_size = 1ULL << 24;
    encoded_a_plus_b_2 = encoded_a_plus_b_2 % field_size;
    double decoded_a_plus_b = FixedPointConverter::decode(encoded_a_plus_b_2);
    std::cout << "Decoded a + b: " << decoded_a_plus_b << std::endl;
    return 0;
}
