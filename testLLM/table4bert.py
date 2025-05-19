import numpy as np
import os

# 配置定点数参数
FRACTIONAL_BITS = 12
TOTAL_BITS = 20
SCALE = 1 << FRACTIONAL_BITS
INT_MIN = -(1 << (TOTAL_BITS - 1))  # -2^19
INT_MAX = (1 << (TOTAL_BITS - 1)) - 1  # 2^19 - 1
FIELD_SIZE = 1 << TOTAL_BITS


# 定点编码（输出为 int64）
def encode_fixed(val):
    fixed = int(np.round(val * SCALE))
    fixed = max(INT_MIN, min(INT_MAX, fixed))
    if fixed < 0:
        fixed += FIELD_SIZE
    return np.int64(fixed & (FIELD_SIZE - 1))

def encode_fixed_np(val):
    fixed = np.round(val * SCALE)
    fixed = np.clip(fixed, INT_MIN, INT_MAX)
    fixed = np.where(fixed < 0, fixed + FIELD_SIZE, fixed)
    fixed = fixed.astype(np.int64)
    return fixed & (FIELD_SIZE - 1)

# 解码定点
def decode_fixed(val):
    if val >= (1 << (TOTAL_BITS - 1)):
        val -= FIELD_SIZE
    return val / SCALE

def decode_fixed_np(val):
    val_copy = val.copy()
    mask = val_copy >= (1 << (TOTAL_BITS - 1))
    val_copy[mask] -= FIELD_SIZE
    return val_copy / SCALE

# 非线性函数定义
def relu(x):
    return np.maximum(0, x)

def sigmoid(x):
    return 1 / (1 + np.exp(-x))

def tanh(x):
    return np.tanh(x)

def gelu(x):
    return 0.5 * x * (1 + np.tanh(np.sqrt(2 / np.pi) * (x + 0.044715 * np.power(x, 3))))

def inv(x):
    with np.errstate(divide='ignore', invalid='ignore'):
        return np.where(x != 0, 1 / x, 0)

def sqrt(x):
    return np.sqrt(np.maximum(x, 0))

def silu(x):
    return x * sigmoid(x)

# 查表目标函数列表
activation_functions = {
    "relu": relu,
    "sigmoid": sigmoid,
    "tanh": tanh,
    "gelu": gelu,
    "inverse": inv,
    "sqrt": sqrt,
    "silu": silu,
}

# 输出路径
OUTPUT_DIR = "../build/bin"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# 生成并保存每个函数的查表数据
for name, func in activation_functions.items():
    print(f"Generating lookup table for: {name}")
    
    # 生成从0到FIELD_SIZE-1的所有可能的定点整数
    encoded_inputs = np.arange(FIELD_SIZE, dtype=np.int64)
    
    # 解码到浮点数
    float_inputs = decode_fixed_np(encoded_inputs)
    
    a = -2
    print(a)
    aa = encode_fixed(a)
    print(aa)
    fa = func(a)
    print(fa)
    faa = encode_fixed(fa)
    print(faa)
    
    # 应用非线性函数
    float_outputs = func(float_inputs)
    
    # 编码回定点整数
    encoded_outputs = encode_fixed_np(float_outputs)
    
    # 输出表格的最大值和最小值
    print(f"  Output range: max = {np.max(encoded_outputs)}, min = {np.min(encoded_outputs)}")
    print(f"  Decoded float range: min = {np.min(float_inputs):.6f}, max = {np.max(float_inputs):.6f}")
    
    # 保存查找表（二进制格式）
    table_path = os.path.join(OUTPUT_DIR, f'table_{name}.txt')
    with open(table_path, 'wb') as f:
        f.write(encoded_outputs.tobytes())
    
    print(f"  Table saved to: {table_path}")
    print("--------------------------------------------------")