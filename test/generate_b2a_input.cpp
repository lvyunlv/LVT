#include <fstream>
#include <iostream>
#include <random>
#include <string>
#include <vector>

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "用法: " << argv[0] << " <比特数量> <参与方个数>" << std::endl;
        return 1;
    }

    const int BITLEN = std::stoi(argv[1]);
    const int NUM_PARTIES = std::stoi(argv[2]);
    const int NUM_VALUES = NUM_PARTIES;  // 每个参与方一个值

    std::ofstream fout("../../test/b2a_input.txt");
    if (!fout.is_open()) {
        std::cerr << "无法写入 b2a_input.txt" << std::endl;
        return 1;
    }

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(0, 1);  // 直接生成0或1

    // 存储所有生成的位
    std::vector<std::vector<int>> all_bits(NUM_VALUES, std::vector<int>(BITLEN));

    for (int i = 0; i < NUM_VALUES; ++i) {
        for (int j = 0; j < BITLEN; ++j) {
            all_bits[i][j] = dist(gen);
            fout << all_bits[i][j] << (j == BITLEN - 1 ? '\n' : ' ');
        }
    }

    fout.close();
    std::cout << "✅ 生成了 " << NUM_VALUES << " 个 " << BITLEN << " 位布尔向量，写入 b2a_input.txt" << std::endl;

    // 计算布尔加法结果（mod 2）
    std::vector<int> sum_result(BITLEN, 0);
    for (int i = 0; i < NUM_VALUES; ++i) {
        for (int j = 0; j < BITLEN; ++j) {
            sum_result[j] += all_bits[i][j];
            sum_result[j] %= 2;
        }
    }

    // 输出布尔加法结果
    std::cout << "布尔加法结果 (mod 2): ";
    for (int j = 0; j < BITLEN; ++j) {
        std::cout << sum_result[j] << " ";
    }
    std::cout << std::endl;


    return 0;
}
