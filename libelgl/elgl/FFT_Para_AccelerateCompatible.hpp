#pragma once
#include <vector>
#include <cmath>
#include <Accelerate/Accelerate.h>
#include "BLS12381Element.h"
#include <mcl/bn.hpp>

using namespace std;
using namespace mcl::bn;

/**
 * Apple Silicon (M1/M2) FFT 实现，兼容接口 FFT_Para(...)
 * - input/output: vector<BLS12381Element>
 * - omega: Fr （不使用，仅为接口保持一致）
 * - N: 必须是 2 的幂
 */
void FFT_Para(
    const vector<BLS12381Element>& input,
    vector<BLS12381Element>& output,
    const Fr& omega, // unused
    size_t N
) {
    assert((N & (N - 1)) == 0); // 必须是2的幂
    assert(input.size() == N);

    output.resize(N);

    // 准备浮点数组（使用 BLS 点的 x 值模拟）
    vector<double> real(N, 0.0);
    vector<double> imag(N, 0.0);

    for (size_t i = 0; i < N; i++) {
        real[i] = input[i].getPoint().x.getDouble(); // 模拟值（非加密安全）
        imag[i] = 0.0; // 如需模拟复数 FFT 可用 y.getDouble()
    }

    // 生成 FFT 配置
    FFTSetupD setup = vDSP_create_fftsetupD(log2(N), kFFTRadix2);
    if (!setup) {
        throw runtime_error("Failed to create vDSP FFT setup");
    }

    // 封装为 Accelerate 支持的结构
    DSPSplitComplex splitComplex = {
        .realp = real.data(),
        .imagp = imag.data()
    };

    // 执行 FFT
    vDSP_fft_zipD(setup, &splitComplex, 1, log2(N), FFTDirection(FFT_FORWARD));
    vDSP_destroy_fftsetupD(setup);

    // 将结果映射回 output
    for (size_t i = 0; i < N; i++) {
        // ⚠ 注意：这里只是模拟，将 double 映射为 BLS12381Element
        double re = real[i];
        Fr val;
        val.setDouble(re);
        output[i] = BLS12381Element(val); // 只用实部模拟结果
    }
}
