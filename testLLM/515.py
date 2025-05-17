import numpy as np
import os

# 定点参数
FRACTIONAL_BITS = 16
SCALE = 1 << FRACTIONAL_BITS
TOTAL_BITS = 24
FIELD_SIZE = 1 << TOTAL_BITS
MAX_VAL = (1 << (TOTAL_BITS - 1)) - 1
MIN_VAL = -(1 << (TOTAL_BITS - 1))
TABLE_SIZE = 1 << 12  # 4096
DELTA_BITS = 4
DELTA_TABLE_SIZE = 1 << DELTA_BITS  # 16
OUTPUT_DIR = '../build/bin'
os.makedirs(OUTPUT_DIR, exist_ok=True)

# 定点编码（输出为 int64）
def encode_fixed(val):
    fixed = int(np.round(val * SCALE))
    fixed = max(MIN_VAL, min(MAX_VAL, fixed))
    if fixed < 0:
        fixed += FIELD_SIZE
    return np.int64(fixed & (FIELD_SIZE - 1))

# 解码定点
def decode_fixed(val):
    if val >= (1 << (TOTAL_BITS - 1)):
        val -= FIELD_SIZE
    return val / SCALE

# 要处理的函数及范围
functions = {
    'sigmoid': (lambda x: 1 / (1 + np.exp(-x))),
    'tanh': np.tanh,
}

safe_ranges = {
    'sigmoid': (-16.0, 16.0),
    'tanh': (-16.0, 16.0),
}

# 生成和保存表
for name, f in functions.items():
    xmin, xmax = safe_ranges[name]
    delta = (xmax - xmin) / TABLE_SIZE
    subdelta = delta / DELTA_TABLE_SIZE

    base_table = np.zeros(TABLE_SIZE, dtype=np.uint64)
    delta_table = np.zeros((TABLE_SIZE, DELTA_TABLE_SIZE), dtype=np.uint64)

    for i in range(TABLE_SIZE):
        x_base = xmin + (i + 0.5) * delta
        y_base = f(x_base)
        base_enc = encode_fixed(y_base)
        base_table[i] = base_enc

        for j in range(DELTA_TABLE_SIZE):
            x_sub = x_base + (j - DELTA_TABLE_SIZE // 2) * subdelta
            y_sub = f(x_sub)
            correction = (encode_fixed(y_sub) - base_enc) % FIELD_SIZE
            delta_table[i, j] = np.uint64(correction)

    # 输出表格的最大值和最小值
    print(f"Function: {name}")
    print(f"  Base table: max = {np.max(base_table)}, min = {np.min(base_table)}")
    print(f"  Delta table: max = {np.max(delta_table)}, min = {np.min(delta_table)}")

    # 写入 base 表（二进制格式）
    with open(os.path.join(OUTPUT_DIR, f'table_{name}_A.txt'), 'wb') as f:
        f.write(base_table.tobytes())

    # 写入 delta 表（二进制格式）
    with open(os.path.join(OUTPUT_DIR, f'table_{name}_delta.txt'), 'wb') as f:
        f.write(delta_table.reshape(-1).tobytes())

    print(f"[+] Saved {name} base and delta tables.")

print('All tables generated.')

# 验证查表精度
for name, f in functions.items():
    xmin, xmax = safe_ranges[name]
    delta = (xmax - xmin) / TABLE_SIZE
    subdelta = delta / DELTA_TABLE_SIZE

    # 读取 base 表
    with open(os.path.join(OUTPUT_DIR, f'table_{name}_A.txt'), 'rb') as f_bin:
        base_table = np.fromfile(f_bin, dtype=np.int64)

    # 读取 delta 表
    with open(os.path.join(OUTPUT_DIR, f'table_{name}_delta.txt'), 'rb') as f_bin:
        delta_table = np.fromfile(f_bin, dtype=np.int64).reshape(TABLE_SIZE, DELTA_TABLE_SIZE)

    errors = []
    for x in np.linspace(xmin, xmax, 10000):
        i = int((x - xmin) / delta)
        i = min(max(i, 0), TABLE_SIZE - 1)

        sub_idx = int(((x - (xmin + (i + 0.5) * delta)) / subdelta) + (DELTA_TABLE_SIZE // 2))
        sub_idx = min(max(sub_idx, 0), DELTA_TABLE_SIZE - 1)

        y_enc = base_table[i] + delta_table[i][sub_idx]
        y_enc = y_enc & (FIELD_SIZE - 1)
        y_pred = decode_fixed(y_enc)
        y_true = f(x)
        errors.append(abs(y_pred - y_true))

    print(f"Function {name}: max error = {np.max(errors):.6e}, mean error = {np.mean(errors):.6e}")
