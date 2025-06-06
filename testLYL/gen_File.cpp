#include <iostream>
#include <vector>
#include <string>
#include "emp-aby/lvt.h"
#include "libelgl/elgl/Plaintext.h"
using namespace std;
const size_t message_size = 1ULL << 22; // BLS12381Element length
std::mt19937_64 rng;
int main(int argc, char** argv) {
    if (argc < 2) {
        std::cout << "please input a number" << std::endl;
        return 0;
    }
    // convert the second argument to int
    int num = std::stoi(argv[1]);
    BLS12381Element::init();
    vector<int64_t> table;
    table.resize(1<<num);
    Plaintext p;
    for (size_t i = 0; i < table.size(); i++){
        // table[i] = rng() % message_size;
        table[i] = i;
        // cout << "table[" << i << "] = " << table[i] << endl;
    }
    serializeTable(table, "table_init.txt", table.size());
    return 0;
}