def split_x(x, delta_bits, sub_bits_list):
    indices = []
    shift = delta_bits
    for bits in sub_bits_list:
        shift -= bits
        mask = (1 << bits) - 1
        indices.append((x >> shift) & mask)
    return indices

def create_sub_tables(T, delta_bits, sub_bits_list, value_bits):
    k = len(sub_bits_list)
    value_sub_bits = [value_bits // k for _ in range(k)]
    sub_tables = []
    for bits in sub_bits_list:
        sub_tables.append([0] * (1 << bits))
    for x in range(len(T)):
        indices = split_x(x, delta_bits, sub_bits_list)
        value = T[x]
        for i in range(k):
            shift = value_bits - sum(value_sub_bits[:i+1])
            part_mask = (1 << value_sub_bits[i]) - 1
            part = (value >> shift) & part_mask
            sub_tables[i][indices[i]] = part
    return sub_tables

def query(x, sub_tables, sub_bits_list, value_bits):
    indices = split_x(x, sum(sub_bits_list), sub_bits_list)
    k = len(sub_tables)
    value_sub_bits = [value_bits // k for _ in range(k)]
    reconstructed = 0
    for i in range(k):
        shift = value_bits - sum(value_sub_bits[:i+1])
        part = sub_tables[i][indices[i]]
        reconstructed |= part << shift
    return reconstructed

# 示例配置
delta_bits = 8  # 原索引x的比特数
value_bits = 8   # 原表值T[x]的比特数
sub_bits_list = [4, 4]  # 每个子索引的比特数，总和须等于delta_bits

# 创建示例原表，假设值为自身（8位）
T = [i for i in range(1 << delta_bits)]

# 创建子表
sub_tables = create_sub_tables(T, delta_bits, sub_bits_list, value_bits)

# 测试查询
x = 0xAB  # 示例索引：二进制10101011
original_value = T[x]
reconstructed_value = query(x, sub_tables, sub_bits_list, value_bits)

print(f"Original T[{x}] = {original_value}")
print(f"Reconstructed value = {reconstructed_value}")
# 输出应相同