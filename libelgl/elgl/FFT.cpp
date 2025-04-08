// FFT_IFFT_example.cpp
#include <iostream>
#include <vector>
#include <cassert>
#include "BLS12381Element.h" 
#include "Plaintext.h"
#include <mcl/bn.hpp>

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

// //------------------------------------------------------
// // 主函数：设置 FFT 参数，执行 FFT 和 IFFT 验证
// //------------------------------------------------------
// int main() {
//     // 初始化 BLS12-381 参数（MCL库调用）
//     BLS12381Element::init();
//     srand((unsigned)time(NULL));

//     // 设定 FFT 长度 N，必须为 2 的幂。真实应用可取 N = 2^16，此处为了调试取较小值。
//     size_t N = 64;
//     cout << "FFT length N = " << N << endl;

//     // 构造 G1 群的生成元 G
//     BLS12381Element G = BLS12381Element(Fr(1)); // 此处构造方式表示 G = g*1

//     // 获取 Fr 的阶 p（Fr::getOp().mp 为 Fr 的模，注意 p 较大）
//     mpz_class p = Fr::getOp().mp;

//     // 为 FFT 需要找到一个 N-th 原始单位根 ω ∈ Fr。
//     // 方法：令 exp = (p - 1) / N，然后令 ω = g^exp，其中 g 取为一个生成元。
//     // 这里我们用 Plaintext 类计算（你们的 Plaintext 支持大整数运算）。
//     Plaintext g_plain;
//     g_plain.assign(5); // 选定一个数 5（假设它是 Fr 的生成元之一）
//     Plaintext exp;
//     exp.assign((p - 1) / N);
//     Plaintext omega_pt;
//     Plaintext::pow(omega_pt, g_plain, exp);
//     cout << "Computed omega (as plaintext integer): " << omega_pt.get_message() << endl;

//     // 将 omega_pt 转换为 Fr。注意：这里假设 omega_pt.get_message() 返回一个可转换为字符串的整数表示，
//     // 并用 Fr 的构造函数进行初始化。
//     Fr omega;
//     omega = Fr(omega_pt.get_message());
//     // 输出 omega 以检查（可以通过 omega.getStr() 查看）
//     cout << "omega in Fr: " << omega << endl;

//     // 构造 FFT 输入向量：长度为 N 的 BLS12381Element 数组。这里我们简单设定 input[i] = G * i,
//     // 即将 Fr(i) 与 G 做标量乘法。
//     vector<BLS12381Element> input(N);
//     for (size_t i = 0; i < N; i++) {
//         Fr scalar(i);
//         input[i] = G * scalar;
//     }

//     // 执行 FFT
//     vector<BLS12381Element> output;
//     FFT(input, output, omega, N);

//     // 执行 IFFT
//     vector<BLS12381Element> inv_output;
//     IFFT(output, inv_output, omega, N);

//     // 验证 IFFT 结果是否与输入完全相同
//     bool ok = true;
//     for (size_t i = 0; i < N; i++) {
//         // 如果需要比较前归一化，可调用 BLS12381Element::check() 或对点归一化后比较
//         if (inv_output[i] != input[i]) {
//             cout << "Mismatch at index " << i << endl;
//             ok = false;
//         }
//     }
//     if (ok)
//         cout << "FFT and IFFT verified successfully." << endl;
//     else
//         cout << "FFT/IFFT verification failed." << endl;

//     return 0;
// }
