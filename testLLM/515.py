import numpy as np
import os

# 定点参数
FRACTIONAL_BITS = 16
SCALE = 1 << FRACTIONAL_BITS
TOTAL_BITS = 24
FIELD_SIZE = 1 << TOTAL_BITS
TABLE_SIZE = 1 << 12  # 4096
OUTPUT_DIR = './tables'  # 输出目录，可根据需要修改
os.makedirs(OUTPUT_DIR, exist_ok=True)

# 定点编码函数
def encode_fixed(val):
    """将浮点数 val 编码为 Q8.16 定点的无符号整数（24-bit）"""
    fixed = int(np.round(val * SCALE))
    # 处理负数映射
    if fixed < 0:
        fixed = fixed + FIELD_SIZE
    return fixed & (FIELD_SIZE - 1)

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

# 生成并保存表格
for name, (f, f_prime) in functions.items():
    A = np.zeros(TABLE_SIZE, dtype=np.uint32)
    B = np.zeros(TABLE_SIZE, dtype=np.uint32)
    for i in range(TABLE_SIZE):
        x0 = i / float(1<<4)  # i/16
        y = f(x0)
        dy = f_prime(x0)
        A[i] = encode_fixed(y)
        B[i] = encode_fixed(dy)
    # 写入文本文件
    a_file = os.path.join(OUTPUT_DIR, f'table_{name}_A.txt')
    b_file = os.path.join(OUTPUT_DIR, f'table_{name}_B.txt')
    np.savetxt(a_file, A, fmt='%u')
    np.savetxt(b_file, B, fmt='%u')
    print(f'[+] Saved {name}: A -> {a_file}, B -> {b_file}')

print('All tables generated.')
