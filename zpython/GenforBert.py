import numpy as np
import os

# 配置定点数参数
FRACTIONAL_BITS = 16
TOTAL_BITS = 24
SCALE = 1 << FRACTIONAL_BITS
INT_MIN = -(1 << (TOTAL_BITS - 1))  # -2^23
INT_MAX = (1 << (TOTAL_BITS - 1)) - 1  # 2^23 - 1

# 非线性函数定义
def relu(x):
    return np.maximum(0, x)

def sigmoid(x):
    return 1 / (1 + np.exp(-x))

def tanh_fn(x):
    return np.tanh(x)

def gelu(x):
    return 0.5 * x * (1 + np.tanh(np.sqrt(2/np.pi) * (x + 0.044715 * np.power(x, 3))))

def inv_fn(x):
    with np.errstate(divide='ignore', invalid='ignore'):
        return np.where(x != 0, 1 / x, 0)

def sqrt_fn(x):
    return np.sqrt(np.maximum(x, 0))

# 查表目标函数列表
activation_functions = {
    "relu": relu,
    "sigmoid": sigmoid,
    "tanh": tanh_fn,
    "gelu": gelu,
    "inverse": inv_fn,
    "sqrt": sqrt_fn,
}

# 每个函数的定义域范围（根据BERT实际使用范围优化）
activation_domains = {
    "relu": (-8.0, 8.0),
    "sigmoid": (-8.0, 8.0),
    "tanh": (-8.0, 8.0),
    "gelu": (-8.0, 8.0),
    "inverse": (1/64, 64.0),
    "sqrt": (0.0, 64.0),
}

# 查表粒度
STEPS = 2**16  # 建议和 LUT 协议匹配

# 输出路径
OUTPUT_DIR = "../build/bin"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# 生成并保存每个函数的查表数据
for name, func in activation_functions.items():
    domain = activation_domains[name]
    x = np.linspace(domain[0], domain[1], STEPS)
    y = func(x)

    # 转换为 Q8.16 定点整数（使用 uint24 表示）
    y_fixed = np.round(y * SCALE).astype(np.int64)

    # 映射负数到 unsigned 格式（模拟底层 uint24 wraparound）
    y_fixed = np.where(y_fixed < 0, (1 << TOTAL_BITS) + y_fixed, y_fixed)
    y_fixed = y_fixed & ((1 << TOTAL_BITS) - 1)

    # 保存文件
    table_path = os.path.join(OUTPUT_DIR, f"table_{name}.txt")
    with open(table_path, "w") as f:
        for val in y_fixed:
            f.write(f"{val}\n")

    print(f"[+] Generated: {table_path}")
