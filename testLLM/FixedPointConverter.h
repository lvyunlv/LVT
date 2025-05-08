#pragma once
#include <mcl/vint.hpp>
#include <cstdint>
#include <cmath>
#include <cstdlib>
#include <iostream>

class FixedPointConverter {
public:
    // 使用 Q8.16（24-bit 定点）
    static constexpr int fractional_bits = 16;
    static constexpr int total_bits = 24;
    static constexpr int64_t scale = int64_t(1) << fractional_bits;
    static constexpr uint32_t FIELD_SIZE = 1UL << total_bits;  // 2^24 = 16,777,216
    // 将 double 编码为 Vint
    static uint64_t encode(double value) {
        int64_t fixed_val = static_cast<int64_t>(std::round(value * scale));
        if (fixed_val < 0) {
            fixed_val += FIELD_SIZE;  // 映射负数到 [2^23, 2^24-1]
        }
        uint64_t result = fixed_val;
        return result;
    }

    // 解码 Vint 为 double
    static double decode(const uint64_t& fixed) {
        uint64_t val = fixed;
        if (val >= (FIELD_SIZE >> 1)) { // 负数区间
            val = val - FIELD_SIZE;
        }
        return static_cast<double>(static_cast<int64_t>(val)) / scale;
    }

    // 定点数乘法，处理缩放
    static uint64_t multiply_fixed(uint64_t a, uint64_t b) {
        // 转换为有符号数进行计算
        int64_t a_signed = (a >= (FIELD_SIZE >> 1)) ? (a - FIELD_SIZE) : a;
        int64_t b_signed = (b >= (FIELD_SIZE >> 1)) ? (b - FIELD_SIZE) : b;
        
        // 执行乘法并处理缩放
        int64_t result = (a_signed * b_signed) >> fractional_bits;
        
        // 处理负数
        if (result < 0) {
            result += FIELD_SIZE;
        }
        
        return static_cast<uint64_t>(result) % FIELD_SIZE;
    }

    static std::vector<uint64_t> encode_vector(const std::vector<double>& values) {
        std::vector<uint64_t> encoded;
        encoded.reserve(values.size());
        for (double v : values) {
            encoded.push_back(encode(v));
        }
        return encoded;
    }

    static std::vector<double> decode_vector(const std::vector<uint64_t>& fixed_values) {
        std::vector<double> decoded;
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
            if (i == fractional_bits) std::cout << " ";  // 小数点位置
        }
        std::cout << std::endl;
    }

    // 验证定点数乘法的正确性
    static bool verify_multiplication(uint64_t a, uint64_t b, uint64_t result) {
        double a_val = decode(a);
        double b_val = decode(b);
        double result_val = decode(result);
        double expected = a_val * b_val;
        return std::fabs(result_val - expected) < 1e-4;
    }

    // 验证截断操作的正确性
    static bool verify_truncation(uint64_t original, uint64_t truncated, int f) {
        double orig_val = decode(original);
        double trunc_val = decode(truncated);
        double expected = std::round(orig_val * (1 << f)) / (1 << f);
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
