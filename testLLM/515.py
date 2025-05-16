import numpy as np
import os
import struct

# 定点参数
FRACTIONAL_BITS = 16
SCALE = 1 << FRACTIONAL_BITS
TOTAL_BITS = 24
FIELD_SIZE = 1 << TOTAL_BITS
MAX_VAL = (1 << (TOTAL_BITS - 1)) - 1
MIN_VAL = -(1 << (TOTAL_BITS - 1))
TABLE_SIZE = 1 << 12  # 4096
OUTPUT_DIR = '../build/bin'  # 输出目录，可根据需要修改
os.makedirs(OUTPUT_DIR, exist_ok=True)

# 定点编码函数
def encode_fixed(val):
    """将浮点数 val 编码为 Q8.16 定点的无符号整数（24-bit）"""
    fixed = int(np.round(val * SCALE))
    # 限幅
    fixed = max(MIN_VAL, min(MAX_VAL, fixed))
    # 处理负数映射为补码
    if fixed < 0:
        fixed += FIELD_SIZE
    return fixed & (FIELD_SIZE - 1)

# 二进制写入函数
def serialize_table_as_txt(table, filename):
    """将表格以二进制格式写入文件，但文件后缀为 .txt"""
    if len(table) > (1 << 16):  # 默认限制大小为 2^16
        print("Error: Table size exceeds the given limit.")
        return

    with open(filename, 'wb') as f:
        f.write(struct.pack(f'{len(table)}q', *table))  # 写入为 int64_t 格式

# GELU 和 SiLU 的精确导数实现
def gelu(x):
    return 0.5 * x * (1 + np.tanh(np.sqrt(2/np.pi)*(x + 0.044715 * x**3)))

def gelu_prime(x):
    tanh_val = np.tanh(np.sqrt(2/np.pi)*(x + 0.044715 * x**3))
    left = 0.5 * (1 + tanh_val)
    right = (0.5*x*(1 - tanh_val**2) * np.sqrt(2/np.pi)*(1 + 3*0.044715*x**2))
    return left + right

def silu(x):
    return x / (1 + np.exp(-x))

def silu_prime(x):
    sig = 1 / (1 + np.exp(-x))
    return sig + x * sig * (1 - sig)

# 定义函数及导数映射
functions = {
    'reciprocal': (lambda x: 1/x if x != 0 else 0.0, lambda x: -1/(x*x) if x != 0 else 0.0),
    'sqrt':       (lambda x: np.sqrt(x) if x >= 0 else 0.0, lambda x: 1/(2*np.sqrt(x)) if x > 0 else 0.0),
    'invsqrt':    (lambda x: 1/np.sqrt(x) if x > 0 else 0.0, lambda x: -1/(2*x*np.sqrt(x)) if x > 0 else 0.0),
    'log':        (lambda x: np.log(x) if x > 0 else 0.0,  lambda x: 1/x if x > 0 else 0.0),
    'sigmoid':    (lambda x: 1/(1+np.exp(-x)), lambda x: np.exp(-x)/((1+np.exp(-x))**2)),
    'tanh':       (np.tanh,       lambda x: 1 - np.tanh(x)**2),
    'gelu':       (gelu,          gelu_prime),
    'silu':       (silu,          silu_prime),
    'sin':        (np.sin,         np.cos),
    'cos':        (np.cos,         lambda x: -np.sin(x)),
}

# 为每个函数设置安全输入范围，避免数值溢出
safe_ranges = {
    'reciprocal': (0.01, 256.0),
    'sqrt':       (0.0, 256.0),
    'invsqrt':    (0.01, 256.0),
    'log':        (0.01, 256.0),
    'sigmoid':    (-256.0, 256.0),
    'tanh':       (-256.0, 256.0),
    'gelu':       (-10.0, 10.0),
    'silu':       (-20.0, 20.0),
    'sin':        (-256.0, 256.0),
    'cos':        (-256.0, 256.0),
}

# 生成并保存表格
for name, (f, f_prime) in functions.items():
    xmin, xmax = safe_ranges[name]
    delta = (xmax - xmin) / TABLE_SIZE
    A = np.zeros(TABLE_SIZE, dtype=np.int64)
    B = np.zeros(TABLE_SIZE, dtype=np.int64)
    for i in range(TABLE_SIZE):
        x0 = xmin + (i + 0.5) * delta
        y = f(x0)
        dy = f_prime(x0)
        A[i] = encode_fixed(y)
        B[i] = encode_fixed(dy)
    # 打印表格的最大值和最小值
    print(f"Function: {name}, A max: {np.max(A)}, A min: {np.min(A)}, B max: {np.max(B)}, B min: {np.min(B)}")
    if np.max(A) > (FIELD_SIZE-1) or np.min(A) < 0 or np.max(B) > (FIELD_SIZE-1) or np.min(B) < 0:
        print(f"Error: {name} table contains values outside the field.")
    # 写入二进制文件，后缀为 .txt
    a_file = os.path.join(OUTPUT_DIR, f'table_{name}A.txt')
    b_file = os.path.join(OUTPUT_DIR, f'table_{name}B.txt')
    serialize_table_as_txt(A, a_file)
    serialize_table_as_txt(B, b_file)
    print(f'[+] Saved {name}: A -> {a_file}, B -> {b_file}')

print('All tables generated.')
print(FIELD_SIZE)