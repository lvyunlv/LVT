import numpy as np
import os

# 配置定点数参数
FRACTIONAL_BITS = 16
TOTAL_BITS = 22
SCALE = 1 << FRACTIONAL_BITS
INT_MIN = -(1 << (TOTAL_BITS - 1))  # -2^23
INT_MAX = (1 << (TOTAL_BITS - 1)) - 1  # 2^23 - 1
FIELD_SIZE = 1 << TOTAL_BITS

# 定点编码（输出为 int64）
def encode_fixed(val):
    fixed = int(np.round(val * SCALE))
    fixed = max(INT_MIN, min(INT_MAX, fixed))
    if fixed < 0:
        fixed += FIELD_SIZE
    return np.int64(fixed & (FIELD_SIZE - 1))

# 解码定点
def decode_fixed(val):
    if val >= (1 << (TOTAL_BITS - 1)):
        val -= FIELD_SIZE
    return val / SCALE

# 非线性函数定义
def relu(x):
    return np.maximum(0, x)

def sigmoid(x):
    return 1 / (1 + np.exp(-x))

def tanh(x):
    return np.tanh(x)

def gelu(x):
    return 0.5 * x * (1 + np.tanh(np.sqrt(2/np.pi) * (x + 0.044715 * np.power(x, 3))))

def inv(x):
    with np.errstate(divide='ignore', invalid='ignore'):
        return np.where(x != 0, 1 / x, 0)

def sqrt(x):
    return np.sqrt(np.maximum(x, 0))

# 查表目标函数列表
activation_functions = {
    "relu": relu,
    "sigmoid": sigmoid,
    "tanh": tanh,
    "gelu": gelu,
    "inverse": inv,
    "sqrt": sqrt,
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
STEPS = 2**22  # 建议和 LUT 协议匹配

# 输出路径
OUTPUT_DIR = "../build/bin"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# 生成并保存每个函数的查表数据
for name, func in activation_functions.items():
    xmin, xmax = activation_domains[name]
    delta = (xmax - xmin) / FIELD_SIZE

    base_table = np.zeros(FIELD_SIZE, dtype=np.uint64)
    
    for i in range(FIELD_SIZE):
        x_base = xmin + (i + 0.5) * delta
        y_base = func(x_base)
        base_enc = encode_fixed(y_base)
        base_table[i] = base_enc
    
    # 输出表格的最大值和最小值
    print(f"Function: {name}")
    print(f"  Base table: max = {np.max(base_table)}, min = {np.min(base_table)}")
    
    # # 保存文件
    # table_path = os.path.join(OUTPUT_DIR, f"table_{name}.txt")
    # with open(table_path, "w", encoding="utf-8") as f:
    #     for val in base_table:
    #         f.write(f"{val}\n")

    # print(f"[+] Generated: {table_path}")
    
    # 写入 base 表（二进制格式）
    with open(os.path.join(OUTPUT_DIR, f'table_{name}.txt'), 'wb') as f:
        f.write(base_table.tobytes())