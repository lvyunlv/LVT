// FFT_IFFT_example.cpp
#include <iostream>
#include <vector>
#include <cassert>
#include "BLS12381Element.h" 
#include "Plaintext.h"
#include <mcl/bn.hpp>

#include <future>

using namespace std;
using namespace mcl::bn;

//------------------------------------------------------
// 递归实现 FFT
//------------------------------------------------------
/**
 * 递归实现 FFT。参数说明：
 * @param a 输入向量（长度为 n），其中 a[i] 为 G1 中的点。
 * @param A 输出向量（长度为 n），存储 FFT 后的结果。
 * @param omega 当前层使用的单位根（n-th 根）。
 * @param n 当前 FFT 长度，必须为 2 的幂。
 */
void FFT_recursive(const vector<BLS12381Element>& a, vector<BLS12381Element>& A, const Fr &omega, size_t n) {
    if (n == 1) {
        A[0] = a[0];  // 递归基
        return;
    }
    size_t m = n / 2;
    vector<BLS12381Element> a_even(m), a_odd(m);
    // 分离偶数、奇数下标
    for (size_t i = 0; i < m; i++) {
        a_even[i] = a[2 * i];
        a_odd[i] = a[2 * i + 1];
    }
    vector<BLS12381Element> A_even(m), A_odd(m);
    // omega² 为 n/2 个点的单位根
    Fr omegaSquared = omega * omega;
    FFT_recursive(a_even, A_even, omegaSquared, m);
    FFT_recursive(a_odd, A_odd, omegaSquared, m);

    // 合并阶段
    Fr w(1); 
    for (size_t j = 0; j < m; j++) {
        BLS12381Element t = A_odd[j] * w;
        A[j] = A_even[j] + t;
        A[j + m] = A_even[j] - t;
        w *= omega;
    }
}

/**
 * FFT 主函数。计算输入向量 input 的 FFT，单位根为 omega，向量长度 n 必须为 2 的幂。
 */
void FFT(const vector<BLS12381Element>& input, vector<BLS12381Element>& output, const Fr &omega, size_t n) {
    assert(n == input.size());
    output.resize(n);
    FFT_recursive(input, output, omega, n);
}

//------------------------------------------------------
// 递归实现 IFFT
//------------------------------------------------------
/**
 * IFFT 使用 FFT 计算，只需传入单位根的逆元。
 */
void IFFT(const vector<BLS12381Element>& input, vector<BLS12381Element>& output, const Fr &omega, size_t n) {
    // 计算 omega 的逆元：我们将使用 omega_inv 替代 omega 进行 FFT
    Fr omega_inv;
    Fr::inv(omega_inv, omega);
    vector<BLS12381Element> temp;
    FFT(input, temp, omega_inv, n);
    // 归一化：每个元素乘以 1/n
    Fr invN;
    Fr::inv(invN, Fr(n)); // n 的逆元
    output.resize(n);
    for (size_t i = 0; i < n; i++) {
        output[i] = temp[i] * invN;
    }
}


void FFT_recursive_para(const std::vector<BLS12381Element>& a, std::vector<BLS12381Element>& A, const Fr &omega, size_t n) {
    if (n == 1) {
        A[0] = a[0];
        return;
    }

    size_t m = n / 2;
    std::vector<BLS12381Element> a_even(m), a_odd(m);
    
    // Split the input into even and odd parts
    for (size_t i = 0; i < m; i++) {
        a_even[i] = a[2 * i];
        a_odd[i] = a[2 * i + 1];
    }
    
    // Prepare storage for the results of the recursive calls
    std::vector<BLS12381Element> A_even(m), A_odd(m);
    
    // omega^2 for the smaller FFT
    Fr omegaSquared = omega * omega;
    
    // Execute the recursive FFT calls asynchronously using std::async
    auto future_even = std::async(std::launch::async, [&]() {
        FFT_recursive(a_even, A_even, omegaSquared, m);
    });
    auto future_odd = std::async(std::launch::async, [&]() {
        FFT_recursive(a_odd, A_odd, omegaSquared, m);
    });

    // Wait for both asynchronous FFT calls to finish
    future_even.get();
    future_odd.get();
    
    // Combine the results
    Fr w(1); // w will be the powers of omega
    for (size_t j = 0; j < m; j++) {
        BLS12381Element t = A_odd[j] * w;
        A[j] = A_even[j] + t;
        A[j + m] = A_even[j] - t;
        w *= omega;
    }
}

// Main FFT function
void FFT_Para(const std::vector<BLS12381Element>& input, std::vector<BLS12381Element>& output, const Fr &omega, size_t n) {
    assert(n == input.size());
    output.resize(n);
    FFT_recursive_para(input, output, omega, n);
}