import random

# 检查一个数是否是模 p 的生成元
def is_generator(g, p):
    # p-1 的素因子分解（这里假设 p-1 = 2^k * m，其中 m 是奇数）
    factors = [2]  # 2 是 p-1 的一个素因子
    m = (p - 1) // 2
    if m > 1:
        factors.append(m)  # 假设 m 是素数（如果不是，需要进一步分解）

    # 检查 g^(p-1)/factor 是否等于 1 mod p
    for factor in factors:
        if pow(g, (p - 1) // factor, p) == 1:
            return False
    return True

# 找到模 p 的生成元
def find_generator(p):
    for g in range(2, p):
        if is_generator(g, p):
            return g
    return None  # 理论上应当找到生成元

# 主函数
def main():
    # 给定的 p 值
    p = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001

    # 找到生成元 g
    g = find_generator(p)
    if g is not None:
        print(f"模 p 的生成元 g: {g}")
    else:
        print("未找到生成元")
        
    # 计算alpha = g^(p-1)/n
    # n = 65536
    n = 65536
    alpha = pow(g, (p-1) // n, p)
    print(f"alpha = g^(p-1)/n = {alpha}") 
    # 计算alpha的逆元
    alpha_inv = pow(alpha, -1, p)
    print(f"alpha的逆元 = {alpha_inv}")

# 运行主函数
if __name__ == "__main__":
    main()