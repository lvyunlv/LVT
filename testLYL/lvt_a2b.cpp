#include "emp-aby/lvt.h"
#include "emp-aby/io/multi-io.hpp"
using namespace emp;
using namespace std;

int party, port;
const static int threads = 8;
int num_party;

int main(int argc, char** argv) {
    BLS12381Element::init();

    if (argc < 4) {
        std::cout << "Format: b2a_conversion PartyID port num_parties" << std::endl;
        return 0;
    }

    parse_party_and_port(argv, &party, &port);
    num_party = std::stoi(argv[3]);

    // === 构造网络配置 ===
    std::vector<std::pair<std::string, unsigned short>> net_config;
    for (int i = 0; i < num_party; ++i) {
        net_config.push_back({"127.0.0.1", port + 4 * num_party * i});
    }

    ThreadPool pool(threads);
    MultiIO* io = new MultiIO(party, num_party, net_config);
    ELGL<MultiIOBase>* elgl = new ELGL<MultiIOBase>(num_party, io, &pool, party);

    // === 设置 alpha 和 LVT 公共参数 ===
    int table_size = 1;
    const mcl::Vint p("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
    const mcl::Vint g("5"); 
    mcl::Vint n = mcl::Vint(1) << table_size;
    mcl::Vint alpha_vint;
    mcl::gmp::powMod(alpha_vint, g, (p - 1) / n, p);
    Plaintext alpha;
    alpha.assign(alpha_vint.getStr());
    Fr alpha_fr = alpha.get_message();

    // === 读取布尔向量（每行一个 party，当前方取自己的行） ===
    ifstream in("../../test/b2a_input.txt");
    if (!in.is_open()) {
        cerr << "Error: Cannot open input.txt" << endl;
        return 1;
    }

    vector<vector<int>> all_bits;
    string line;
    while (getline(in, line)) {
        istringstream iss(line);
        vector<int> bits;
        int b;
        while (iss >> b) {
            if (b != 0 && b != 1) {
                cerr << "Invalid bit in input.txt: " << b << endl;
                return 1;
            }
            bits.push_back(b);
        }
        all_bits.push_back(bits);
    }
    in.close();

    if (party > all_bits.size()) {
        cerr << "Error: Not enough input lines for party " << party << endl;
        return 1;
    }

    vector<int> bool_bits = all_bits[party - 1]; // 当前方的布尔输入
    // 计算布尔输入对应的十进制数并输出
    unsigned long long decimal_result = 0;
    for (size_t i = 0; i < bool_bits.size(); ++i) {
        decimal_result = (decimal_result << 1) | bool_bits[i];
    }
    cout << "Decimal input: " << decimal_result << endl;

    const size_t bitlen = bool_bits.size();

    // === 构建每个 bit 的 LVT 实例（共 bitlen 个） ===
    vector<LVT<MultiIOBase>*> lvt_list;
    for (size_t i = 0; i < bitlen; ++i) {
        auto* lvt = new LVT<MultiIOBase>(num_party, party, io, &pool, elgl, "../../build/bin/table.txt", alpha_fr, table_size);
        lvt->DistKeyGen();
        lvt->generate_shares(lvt->lut_share, lvt->rotation, lvt->table);
        lvt_list.push_back(lvt);
    }

    cout << "lvt_list.size(): " << lvt_list.size() << endl;


    Plaintext pow2_plain(2), bitlen_plain(bitlen);

    vector<Fr> power(bitlen);
    power[0] = 1;
    for (size_t i = 1; i < bitlen; ++i) {
        power[i] = power[i-1] + power[i-1];
    }
    Fr module = power[bitlen-1] * 2;
    cout << "module: " << module.getStr() << endl;

    // === 执行 B2A 并计时 ===
    auto start = chrono::high_resolution_clock::now();
    Fr result = 0;

    for (size_t i = 0; i < bitlen; ++i) {
        int x = bool_bits[i];
        Plaintext x_share;
        x_share.assign(to_string(x));
        Ciphertext x_cipher = lvt_list[i]->global_pk.encrypt(x_share);
        vector<Ciphertext> x_ciphers(num_party);
        Plaintext out;
        lvt_list[i]->lookup_online(out, x_share, x_cipher, x_ciphers);
        Fr out_fr = out.get_message();
        cout << out_fr.getStr() << " ";

        result += out.get_message() * power[i];
        
        mcl::Vint result_mpz = result.getMpz(); 
        mcl::gmp::mod(result_mpz, result_mpz, module.getMpz());
        result.setMpz(result_mpz);
    }

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> elapsed = end - start;
    cout << endl << "[Party " << party << "] B2A time: " << elapsed.count() << " seconds" << endl;

    // === 输出结果 ===
    cout << "[Party " << party << "] B2A result: " << result.getStr() << endl;
    ofstream fout("../../test/b2a_output.txt");
    fout << result.getStr() << endl;
    fout.close();

    // === 清理资源 ===
    for (auto* lvt : lvt_list)
        delete lvt;

    delete io;
    delete elgl;

    return 0;
}
