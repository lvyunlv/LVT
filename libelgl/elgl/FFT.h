#ifndef _FFT
#define _FFT

#include <mcl/bls12_381.hpp>
#include "libelgl/elgl/BLS12381Element.h"
#include <vector>

/**
 * 对 BLE12381 椭圆曲线 G1 群元素序列执行 FFT 运算。
 * @param input 输入的 G1 群元素序列，长度为 N。
 * @param output 输出的 G1 群元素序列，长度为 N。
 * @param alpha 阶为 N 的单位根（G1 群中的生成元）。
 * @param N 序列长度，必须为 2 的幂次。
 */
void FFT(const std::vector<BLS12381Element>& input, 
    std::vector<BLS12381Element>& output, 
    const Fr& alpha, 
    size_t N);
// void IFFT(const std::vector<BLS12381Element>& input, 
//     std::vector<BLS12381Element>& output, 
//     const Fr& alpha, 
//     size_t N);

void FFT_Para(const std::vector<BLS12381Element>& input, std::vector<BLS12381Element>& output, const Fr &omega, size_t n);

#endif