import numpy as np
import matplotlib.pyplot as plt

# 参数配置
FRAC_BITS = 16         # 定点小数位
TABLE_BITS = 8         # LUT 输入位宽
TABLE_SIZE = 1 << TABLE_BITS  # LUT 大小 256
INT_TYPE = np.int32    # 定点整数类型

# 定点转换
def float_to_fixed(x, frac_bits=FRAC_BITS):
    return np.round(x * (1 << frac_bits)).astype(INT_TYPE)

def fixed_to_float(x, frac_bits=FRAC_BITS):
    return x.astype(np.float32) / (1 << frac_bits)

# 构建查找表：输入为整数 [0, 255]，映射到实际区间 [-8, 8]
def build_fixed_lookup_table():
    table_input = np.arange(TABLE_SIZE, dtype=INT_TYPE)
    # 把输入映射到 [-8.0, 8.0] 区间（定点计算，避免浮点）
    # x_float = -8.0 + i * step, step = 16 / 256 = 0.0625
    step_fixed = float_to_fixed(16.0 / TABLE_SIZE)  # 即 0.0625 -> 定点
    x_fixed = float_to_fixed(-8.0) + table_input * step_fixed
    x_float = fixed_to_float(x_fixed)

    # 用浮点构建精确 sigmoid 值，然后转为定点整数（仅在离线）
    sigmoid_fixed = float_to_fixed(1 / (1 + np.exp(-x_float)))
    sigmoid_deriv_fixed = float_to_fixed((np.exp(-x_float)) / ((1 + np.exp(-x_float)) ** 2))

    return x_fixed, sigmoid_fixed, sigmoid_deriv_fixed, step_fixed

# 插值函数（输入整数 index ∈ [0, 255], 输入偏移 delta_fixed 为定点）
def interpolate_fixed(index: int, delta_fixed: int, t1, t2):
    # 插值：f(x) = t1[index] + t2[index] * delta >> FRAC_BITS
    return t1[index] + ((t2[index] * delta_fixed) >> FRAC_BITS)

# 模拟调用过程（输入为 [-8.0, 8.0] 的浮点数 → 转为整数 + 定点偏移）
def simulate_approx_sigmoid(x_inputs_float):
    # 加载查找表
    x_fixed_table, t1, t2, step_fixed = build_fixed_lookup_table()

    # 把输入浮点转为定点
    x_inputs_fixed = float_to_fixed(x_inputs_float)
    x_start = x_fixed_table[0]

    # 计算 index 和 delta_fixed
    delta_total = x_inputs_fixed - x_start
    index = (delta_total // step_fixed).astype(np.int32)
    index = np.clip(index, 0, TABLE_SIZE - 1)
    x_i = x_start + index * step_fixed
    delta_fixed = x_inputs_fixed - x_i

    # 插值输出（定点整数）
    approx_fixed = np.array([
        interpolate_fixed(i, d, t1, t2) for i, d in zip(index, delta_fixed)
    ], dtype=INT_TYPE)
    return fixed_to_float(approx_fixed)

# 主函数测试
def main():
    x_float = np.linspace(-8.0, 8.0, 1000)
    approx_float = simulate_approx_sigmoid(x_float)
    exact_float = 1 / (1 + np.exp(-x_float))

    # 误差分析
    error = np.abs(approx_float - exact_float)
    print(f"最大误差: {np.max(error)}")
    print(f"平均误差: {np.mean(error)}")

    # 可视化
    plt.plot(x_float, exact_float, label="Exact Sigmoid")
    plt.plot(x_float, approx_float, label="Fixed-Point Approx", linestyle="--")
    plt.legend()
    plt.title("Sigmoid Approximation with Integer Lookup and Fixed-Point Arithmetic")
    plt.xlabel("Input")
    plt.ylabel("Output")
    plt.grid(True)
    plt.show()

if __name__ == "__main__":
    main()
