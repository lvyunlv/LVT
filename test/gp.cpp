#include <mcl/bls12_381.hpp>
#include <iostream>

using namespace mcl::bn;

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cout << "Usage: ./calPoint <Fr>" << std::endl;
        return 1;
    }

    // 初始化 BLS12-381 配对
    initPairing(mcl::BLS12_381);

    // 将命令行参数赋值给 Fr
    Fr x;
    x.setStr(argv[1]);
    // 计算 g^x
    G1 g; // 获取 G1 基点
    std::string g1Str = "1 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb 0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";
    g.setStr(g1Str);

    G1 result;
    G1::mul(result, g, x); // 计算 g^x

    // 输出结果
    std::cout << "g^x = " << result.getStr() << std::endl;

    return 0;
}