#include <iostream>
#include <vector>
#include <cmath>
#include <cstdint>
#include <iomanip>

// 定点数参数
constexpr int FRAC_BITS = 16;
constexpr int FIXED_ONE = 1 << FRAC_BITS;
constexpr int LUT_BITS = 9;                      // 2^9 = 512
constexpr int LUT_SIZE = 1 << LUT_BITS;
constexpr int8_t INPUT_MIN = -128;
constexpr int8_t INPUT_MAX = 127;

// 将浮点数转换为定点整数（仅用于 LUT 构建阶段）
int32_t float_to_fixed(double x) {
    return static_cast<int32_t>(std::round(x * FIXED_ONE));
}

// 仅用于测试输出
double fixed_to_float(int32_t x) {
    return static_cast<double>(x) / FIXED_ONE;
}

// 构建查找表（预计算定点整数形式的 sigmoid 和导数值）
void build_lookup_tables(std::vector<int32_t>& T1, std::vector<int32_t>& T2, int32_t scale, int32_t shift) {
    for (int i = 0; i < LUT_SIZE; ++i) {
        // 预计算中心点：x_i = (i * step + offset)，以定点数表示
        int32_t x_fixed = ((i << FRAC_BITS) / LUT_SIZE) * scale + shift;
        double x_real = static_cast<double>(x_fixed) / FIXED_ONE;
        double sig = 1.0 / (1.0 + std::exp(-x_real));
        double sig_deriv = sig * (1.0 - sig);
        T1[i] = float_to_fixed(sig);
        T2[i] = float_to_fixed(sig_deriv);
    }
}

// 插值函数（全部定点计算，无 float/double）
int32_t interpolate_sigmoid_fixed(int32_t x_input_fixed, const std::vector<int32_t>& T1, const std::vector<int32_t>& T2, int32_t scale, int32_t shift) {
    // 调整输入：从 [-128,127] 映射到 [0, LUT_SIZE)
    int32_t relative = (x_input_fixed - shift) / scale;
    if (relative < 0) relative = 0;
    if (relative >= LUT_SIZE) relative = LUT_SIZE - 1;

    // 查表
    int32_t t1 = T1[relative];
    int32_t t2 = T2[relative];

    // 计算 delta（剩余部分）：x - center
    int32_t step_size = scale * FIXED_ONE << LUT_BITS;
    int32_t center = (relative * step_size) + shift;
    int32_t delta = x_input_fixed - center;

    // 插值: t1 + t2 * delta >> FRAC_BITS
    int32_t interpolated = t1 + ((int64_t)t2 * delta >> FRAC_BITS);
    return interpolated;
}