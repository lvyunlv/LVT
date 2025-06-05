#pragma once
#include <mcl/vint.hpp>
#include <cstdint>
#include <cmath>
#include <cstdlib>
#include <iostream>
#include <vector>
#include <bitset>

class FixedPointConverter {
public:
    static constexpr int FRACTIONAL_BITS = 16;
    static constexpr float SCALE = 1 << FRACTIONAL_BITS;
    
    static uint64_t float_to_fixed(float value) {
        return static_cast<uint64_t>(std::round(value * SCALE));
    }
    
    static float fixed_to_float(uint64_t value) {
        return static_cast<float>(value) / SCALE;
    }

    // 使用 Q8.16（24-bit 定点）
    static constexpr int total_bits = 24;
    static constexpr uint32_t FIELD_SIZE = 1UL << total_bits;  // 2^24 = 16,777,216

    // 将 float 编码为 Vint
    static uint64_t encode(float value) {
        int64_t fixed_val = static_cast<int64_t>(std::round(value * SCALE));
        if (fixed_val < 0) {
            fixed_val += FIELD_SIZE;  // 映射负数到 [2^23, 2^24-1]
        }
        uint64_t result = fixed_val;
        return result;
    }

    // 解码 Vint 为 float
    static float decode(const uint64_t& fixed) {
        uint64_t val = fixed;
        if (val >= (FIELD_SIZE >> 1)) { // 负数区间
            val = val - FIELD_SIZE;
        }
        return static_cast<float>(static_cast<int64_t>(val)) / SCALE;
    }

    // 定点数乘法，处理缩放
    static uint64_t multiply_fixed(uint64_t a, uint64_t b) {
        // 转换为有符号数进行计算
        int64_t a_signed = (a >= (FIELD_SIZE >> 1)) ? (a - FIELD_SIZE) : a;
        int64_t b_signed = (b >= (FIELD_SIZE >> 1)) ? (b - FIELD_SIZE) : b;
        
        // 执行乘法并处理缩放
        int64_t result = (a_signed * b_signed) >> FRACTIONAL_BITS;
        
        // 处理负数
        if (result < 0) {
            result += FIELD_SIZE;
        }
        
        return static_cast<uint64_t>(result) % FIELD_SIZE;
    }

    static std::vector<uint64_t> encode_vector(const std::vector<float>& values) {
        std::vector<uint64_t> encoded;
        encoded.reserve(values.size());
        for (float v : values) {
            encoded.push_back(encode(v));
        }
        return encoded;
    }

    static std::vector<float> decode_vector(const std::vector<uint64_t>& fixed_values) {
        std::vector<float> decoded;
        decoded.reserve(fixed_values.size());
        for (const auto& v : fixed_values) {
            decoded.push_back(decode(v));
        }
        return decoded;
    }

    // 打印定点数的详细信息
    static void print_fixed_point_info(uint64_t fixed) {
        std::cout << "Fixed point value: " << fixed << std::endl;
        std::cout << "Decoded value: " << decode(fixed) << std::endl;
        std::cout << "Binary representation: ";
        for (int i = total_bits - 1; i >= 0; i--) {
            std::cout << ((fixed >> i) & 1);
            if (i == total_bits - 1) std::cout << " ";  // 符号位
            if (i == FRACTIONAL_BITS) std::cout << " ";  // 小数点位置
        }
        std::cout << std::endl;
    }

    // 验证定点数乘法的正确性
    static bool verify_multiplication(uint64_t a, uint64_t b, uint64_t result) {
        float a_val = decode(a);
        float b_val = decode(b);
        float result_val = decode(result);
        float expected = a_val * b_val;
        return std::fabs(result_val - expected) < 1e-4;
    }

    // 验证截断操作的正确性
    static bool verify_truncation(uint64_t original, uint64_t truncated, int f) {
        float orig_val = decode(original);
        float trunc_val = decode(truncated);
        float expected = std::round(orig_val * (1 << f)) / (1 << f);
        bool result = std::fabs(trunc_val - expected) < 1e-4;
        
        if (!result) {
            std::cout << "Truncation verification failed:" << std::endl;
            std::cout << "Original value: " << orig_val << std::endl;
            std::cout << "Truncated value: " << trunc_val << std::endl;
            std::cout << "Expected value: " << expected << std::endl;
            std::cout << "Difference: " << std::fabs(trunc_val - expected) << std::endl;
        }
        
        return result;
    }

    // 获取定点数的符号
    static bool is_negative(uint64_t fixed) {
        return fixed >= (FIELD_SIZE >> 1);
    }

    // 获取定点数的绝对值
    static uint64_t abs(uint64_t fixed) {
        if (is_negative(fixed)) {
            return FIELD_SIZE - fixed;
        }
        return fixed;
    }
};

// 将二进制比特拼接成十进制数的函数，第 0 位会作为二进制字符串的最高位，而最后一位会作为二进制字符串的最低位。
uint64_t bits_to_decimal(const std::vector<int>& bits, uint32_t field) {
    std::string binary_str;
    for (int bit : bits) {
        binary_str += std::to_string(bit);
    }
    return std::bitset<64>(binary_str).to_ullong() % field; // 假设总比特数不超过 64 位
}