#include "table_setup.hpp"

int main() {
    // 构建查找表：输入 [-8, 8] 对应定点 [-524288, 524288]
    std::vector<int32_t> T1(LUT_SIZE), T2(LUT_SIZE);
    int32_t input_range = 16 * FIXED_ONE;   // total input range [-8, +8]
    int32_t scale = input_range / (INPUT_MAX - INPUT_MIN); // 每个输入单位所对应的定点范围
    int32_t shift = -INPUT_MIN * scale;     // 输入 x=0 映射到定点上的位置

    build_lookup_tables(T1, T2, scale, shift);

    std::cout << "x (int) | approx_fixed | approx_float | sigmoid(x) | error\n";
    std::cout << "---------------------------------------------------------------\n";
    for (int x = -128; x <= 127; x += 8) {
        int32_t x_fixed = x * scale + shift;
        int32_t approx_fixed = interpolate_sigmoid_fixed(x_fixed, T1, T2, scale, shift);
        double approx = fixed_to_float(approx_fixed);
        double exact = 1.0 / (1.0 + std::exp(-((double)x_fixed / FIXED_ONE)));
        std::cout << std::setw(5) << static_cast<int>(x)
                  << "     | " << std::setw(12) << approx_fixed
                  << " | " << std::setw(10) << approx
                  << " | " << std::setw(10) << exact
                  << " | " << std::setw(10) << std::abs(approx - exact) << "\n";
    }

    return 0;
}