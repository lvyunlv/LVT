#include <iostream>
#include <vector>
#include <string>
#include "emp-aby/lvt.h"
#include "libelgl/elgl/Plaintext.h"
using namespace std;

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
        table[i] = i;
        // cout << "table[" << i << "] = " << table[i] << endl;
    }
    serializeTable(table, "table.txt", table.size());
    return 0;
}