#pragma once

#include "elgl_interface.hpp"
#include <vector>
#include <random>
#include <chrono>
#include <cassert>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <map>

const int64_t field_size = 65537;

namespace emp {

template <typename IO>
class MASCOT {
public:
    ELGL<IO>* elgl;
    int party;
    int num_parties;
    std::mutex mtx;
    std::condition_variable cv;

    // 用于随机数生成
    std::mt19937_64 rng;

    // MAC 密钥（每方都有一个密钥）
    int64_t mac_key;

    // 带标签的共享值类型，包含 MAC
    struct LabeledShare {
        int64_t value;
        int64_t mac;
        int owner;
        const int64_t* field_size_ptr; // 指向MASCOT的field_size

        LabeledShare() : value(0), mac(0), owner(0), field_size_ptr(nullptr) {}
        LabeledShare(int64_t v, int64_t m, int o, const int64_t* fs) : value(v), mac(m), owner(o), field_size_ptr(fs) {}

        void pack(std::stringstream& ss) const {
            ss.write((char*)&value, sizeof(int64_t));
            ss.write((char*)&mac, sizeof(int64_t));
            ss.write((char*)&owner, sizeof(int64_t));
        }

        void unpack(std::stringstream& ss) {
            ss.read((char*)&value, sizeof(int64_t));
            ss.read((char*)&mac, sizeof(int64_t));
            ss.read((char*)&owner, sizeof(int64_t));
        }

        // 加法重载
        LabeledShare operator+(const LabeledShare& rhs) const {
            int64_t fs = field_size;
            int64_t v = (value + rhs.value) % fs;
            if (v < 0) v += fs;
            int64_t m = (mac + rhs.mac) % fs;
            if (m < 0) m += fs;
            return LabeledShare(v, m, owner, field_size_ptr);
        }
        // 标量乘法重载
        LabeledShare operator*(int64_t scalar) const {
            int64_t fs = field_size;
            scalar = scalar % fs;
            if (scalar < 0) scalar += fs;
            int64_t v = (value * scalar) % fs;
            if (v < 0) v += fs;
            int64_t m = (mac * scalar) % fs;
            if (m < 0) m += fs;
            return LabeledShare(v, m, owner, field_size_ptr);
        }
    };

    // 三元组类型，包含 MAC
    struct Triple {
        int64_t a;
        int64_t b;
        int64_t c;    // c = a * b
        int64_t mac_a;
        int64_t mac_b;
        int64_t mac_c;

        Triple() : a(0), b(0), c(0), mac_a(0), mac_b(0), mac_c(0) {}
        Triple(int64_t a, int64_t b, int64_t c, int64_t mac_a, int64_t mac_b, int64_t mac_c) 
            : a(a), b(b), c(c), mac_a(mac_a), mac_b(mac_b), mac_c(mac_c) {}

        void pack(std::stringstream& ss) const {
            ss.write((char*)&a, sizeof(int64_t));
            ss.write((char*)&b, sizeof(int64_t));
            ss.write((char*)&c, sizeof(c));
            ss.write((char*)&mac_a, sizeof(mac_a));
            ss.write((char*)&mac_b, sizeof(int64_t));
            ss.write((char*)&mac_c, sizeof(int64_t));
        }

        void unpack(std::stringstream& ss) {
            ss.read((char*)&a, sizeof(int64_t));
            ss.read((char*)&b, sizeof(int64_t));
            ss.read((char*)&c, sizeof(int64_t));
            ss.read((char*)&mac_a, sizeof(int64_t));
            ss.read((char*)&mac_b, sizeof(int64_t));
            ss.read((char*)&mac_c, sizeof(int64_t));
        }
    };

    // 用于存储三元组
    std::vector<Triple> triples_pool;

    // 预计算三元组
    void precompute_triples(size_t num_triples) {
        for (size_t i = 0; i < num_triples; i++) {
            generate_triple();
        }
    }

    // 生成单个三元组
    void generate_triple() {
        // 本地生成随机的 a 和 b 值
        int64_t a_local = rng() % field_size;
        int64_t b_local = rng() % field_size;

        // 广播a_local, b_local
        std::stringstream ss;
        ss.write((char*)&a_local, sizeof(int64_t));
        ss.write((char*)&b_local, sizeof(int64_t));
        elgl->serialize_sendall_with_tag(ss, 2000 * party + party);

        // 收集所有a、b
        int64_t a_full = a_local, b_full = b_local;
        for (int i = 1; i <= num_parties; ++i) {
            if (i != party) {
                std::stringstream ss_recv;
                elgl->deserialize_recv_with_tag(ss_recv, i, 2000 * i + i);
                int64_t other_a, other_b;
                ss_recv.read((char*)&other_a, sizeof(int64_t));
                ss_recv.read((char*)&other_b, sizeof(int64_t));
                a_full += other_a;
                b_full += other_b;
            }
        }

        // 计算c = a * b
        int64_t c_full = a_full * b_full;
        int64_t c_local = (party == 1) ? c_full : 0;

        // MAC
        int64_t mac_a = a_local * mac_key;
        int64_t mac_b = b_local * mac_key;
        int64_t mac_c = c_local * mac_key;

        triples_pool.emplace_back(a_local, b_local, c_local, mac_a, mac_b, mac_c);
    }

    Triple get_triple() {
        if (triples_pool.empty()) {
            precompute_triples(10);
        }
        Triple t = triples_pool.back();
        triples_pool.pop_back();
        return t;
    }

    // 检查 MAC 的有效性
    bool check_mac(int64_t value, int64_t mac) const {
        return mac == value * mac_key;
    }

    // 通信辅助函数：发送一个值和其 MAC 给特定方 dst
    void send_value_and_mac(int64_t value, int64_t mac, int dst) {
        std::stringstream ss;
        ss.write((char*)&value, sizeof(int64_t));
        ss.write((char*)&mac, sizeof(int64_t));
        elgl->serialize_send_with_tag(ss, dst, 5000 * dst + party);
    }

    // 通信辅助函数：从src接收一个值和其 MAC
    std::pair<int64_t, int64_t> recv_value_and_mac(int src) {
        std::stringstream ss;
        elgl->deserialize_recv_with_tag(ss, src, 5000 * party + src);
        int64_t value, mac;
        ss.read((char*)&value, sizeof(int64_t));
        ss.read((char*)&mac, sizeof(int64_t));
        std::cout << party << " recv_value_and_mac: " << value << std::endl;
        return {value, mac};
    }

    MASCOT(ELGL<IO>* elgl_instance) : elgl(elgl_instance) {
        party = elgl->party;
        num_parties = elgl->num_party;

        // 初始化随机数生成器
        unsigned seed = std::chrono::system_clock::now().time_since_epoch().count() + party;
        rng.seed(seed);

        // 全局MAC密钥协商
        int64_t local_mac_key = rng() % field_size;
        {
            std::stringstream ss;
            ss.write((char*)&local_mac_key, sizeof(int64_t));
            elgl->serialize_sendall_with_tag(ss, 3000 * party + party);
        }
        int64_t global_mac_key = local_mac_key;
        for (int i = 1; i <= num_parties; ++i) {
            if (i != party) {
                std::stringstream ss_recv;
                elgl->deserialize_recv_with_tag(ss_recv, i, 3000 * i + i);
                int64_t other_key;
                ss_recv.read((char*)&other_key, sizeof(int64_t));
                global_mac_key += other_key;
            }
        }
        mac_key = global_mac_key;

        // 预计算一些三元组
        precompute_triples(20);
    }

    ~MASCOT() {}

    // // 第一个参与方作为可信第三方，创建一个秘密共享，附带 MAC
    // LabeledShare share(int64_t input) {
    //     int64_t local_share = 0;
    //     input = input % field_size;
    //     if (input < 0) input += field_size;

    //     if (party == 1) { // 第一方是输入方
    //         std::vector<int64_t> shares(num_parties, 0);
    //         int64_t remain = input;
    //         for (int i = 2; i <= num_parties; i++) {
    //             shares[i-1] = rng() % field_size;
    //             remain = (remain - shares[i-1]) % field_size;
    //             if (remain < 0) remain += field_size;
    //         }
    //         shares[0] = remain;

    //         for (int i = 2; i <= num_parties; i++) {
    //             int64_t mac = (shares[i-1] * mac_key) % field_size;
    //             if (mac < 0) mac += field_size;
    //             send_value_and_mac(shares[i-1], mac, i);
    //         }

    //         local_share = shares[0];
    //     } else {
    //         auto [share, mac] = recv_value_and_mac(1);
    //         assert(check_mac(share, mac));
    //         local_share = share % field_size;
    //         if (local_share < 0) local_share += field_size;
    //     }

    //     int64_t mac = (local_share * mac_key) % field_size;
    //     if (mac < 0) mac += field_size;
    //     return LabeledShare(local_share, mac, party, &field_size);
    // }

    // 每个参与方都调用，输入自己的xi，返回本地最终share
    LabeledShare distributed_share(int64_t xi) {
        // 1. 生成自己的分片
        std::vector<int64_t> shares(num_parties, 0);
        int64_t remain = xi % field_size;
        // std::cout << party << " remain: " << remain << std::endl;
        if (remain < 0) remain += field_size;
        for (int i = 1; i <= num_parties; ++i) {
            if (i == party) continue;
            shares[i-1] = rng() % field_size;
            remain = (remain - shares[i-1]) % field_size;
            if (remain < 0) remain += field_size;
            // std::cout << party << " others shares[i-1]: " << shares[i-1] << std::endl;
        }
        shares[party-1] = remain;
        // std::cout << party << " owns shares[party-1]: " << shares[party-1] << std::endl;

        std::vector<int64_t> received(num_parties, 0);
        for (int i = 1; i <= num_parties; ++i) {
            if (i == party) continue;
            if (party < i) {
                // 先send再recv
                std::stringstream ss;
                int64_t mac = (shares[i-1] * mac_key) % field_size;
                ss.write((char*)&shares[i-1], sizeof(int64_t));
                ss.write((char*)&mac, sizeof(int64_t));
                elgl->serialize_send_with_tag(ss, i, 4000 * i + party, NORM_MSG);
                // std::cout << party << " send shares[i-1]: " << shares[i-1] << " to " << i << std::endl;

                std::stringstream ss_recv;
                elgl->deserialize_recv_with_tag(ss_recv, i, 4000 * party + i, NORM_MSG);
                int64_t share, mac2;
                ss_recv.read((char*)&share, sizeof(int64_t));
                ss_recv.read((char*)&mac2, sizeof(int64_t));
                assert(check_mac(share, mac2));
                received[i-1] = share % field_size;
                if (received[i-1] < 0) received[i-1] += field_size;
                // std::cout << party << " received[i-1]: " << received[i-1] << std::endl;
            } else {
                // 先recv再send
                std::stringstream ss_recv;
                elgl->deserialize_recv_with_tag(ss_recv, i, 4000 * party + i, NORM_MSG);
                int64_t share, mac2;
                ss_recv.read((char*)&share, sizeof(int64_t));
                ss_recv.read((char*)&mac2, sizeof(int64_t));
                assert(check_mac(share, mac2));
                received[i-1] = share % field_size;
                if (received[i-1] < 0) received[i-1] += field_size;
                // std::cout << party << " received[i-1]: " << received[i-1] << std::endl;

                std::stringstream ss;
                int64_t mac = (shares[i-1] * mac_key) % field_size;
                ss.write((char*)&shares[i-1], sizeof(int64_t));
                ss.write((char*)&mac, sizeof(int64_t));
                elgl->serialize_send_with_tag(ss, i, 4000 * i + party, NORM_MSG);
                // std::cout << party << " send shares[i-1]: " << shares[i-1] << " to " << i << std::endl;
            }
        }
        received[party-1] = remain;

        // 4. 本地求和
        int64_t local_share = 0;
        for (int i = 0; i < num_parties; ++i) {
            local_share = (local_share + received[i]) % field_size;
            if (local_share < 0) local_share += field_size;
        }
        // std::cout << party << " local_share: " << local_share << std::endl;
        int64_t mac = (local_share * mac_key) % field_size;
        if (mac < 0) mac += field_size;
        return LabeledShare(local_share, mac, party, &field_size);
    }

    // 重构秘密，验证 MAC
    int64_t reconstruct(const LabeledShare& share) {
        std::stringstream ss;
        share.pack(ss);
        elgl->serialize_sendall_with_tag(ss, 1000 * party + party);

        int64_t result = share.value % field_size;
        if (result < 0) result += field_size;
        for (int i = 1; i <= num_parties; i++) {
            if (i != party) {
                std::stringstream ss_recv;
                elgl->deserialize_recv_with_tag(ss_recv, i, 1000 * i + i);
                LabeledShare other_share;
                other_share.unpack(ss_recv);
                other_share.field_size_ptr = &field_size;
                assert(check_mac(other_share.value, other_share.mac));
                int64_t v = other_share.value % field_size;
                if (v < 0) v += field_size;
                result = (result + v) % field_size;
                if (result < 0) result += field_size;
            }
        }

        return result;
    }

    // 加法操作，包括 MAC
    LabeledShare add(const LabeledShare& x, const LabeledShare& y) {
        return x + y;
    }

    // 标量乘法，包括 MAC
    LabeledShare mul_const(const LabeledShare& x, int64_t scalar) {
        return x * scalar;
    }

    // 乘法操作，包括 MAC
        // 乘法操作，包括 MAC
    LabeledShare multiply(const LabeledShare& x, const LabeledShare& y) {
        Triple t = get_triple();
        
        // 计算epsilon = x - a 和 delta = y - b，并进行模运算
        int64_t epsilon = (x.value - t.a) % field_size;
        epsilon = (epsilon + field_size) % field_size; // 确保非负
        int64_t delta = (y.value - t.b) % field_size;
        delta = (delta + field_size) % field_size;

        // 构造epsilon和delta的带MAC共享
        LabeledShare eps_share(
            epsilon, 
            (x.mac - t.mac_a + field_size) % field_size, // MAC差值模运算
            party, 
            &field_size
        );
        
        LabeledShare del_share(
            delta,
            (y.mac - t.mac_b + field_size) % field_size,
            party,
            &field_size
        );

        // 重构epsilon和delta（明文值）
        int64_t epsilon_open = reconstruct(eps_share);
        int64_t delta_open = reconstruct(del_share);

        // 计算z = c + epsilon*b + delta*a + epsilon*delta（仅party1添加交叉项）
        int64_t z_value = (t.c + 
                          (epsilon_open * t.b) % field_size + 
                          (delta_open * t.a) % field_size) % field_size;
        
        if (party == 1) {
            z_value = (z_value + (epsilon_open * delta_open) % field_size) % field_size;
        }
        z_value = (z_value + field_size) % field_size; // 最终取模

        // 计算MAC：z_mac = mac_c + epsilon*mac_b + delta*mac_a + epsilon*delta*mac_key
        int64_t z_mac = (t.mac_c + 
                        (epsilon_open * t.mac_b) % field_size + 
                        (delta_open * t.mac_a) % field_size) % field_size;
        
        if (party == 1) {
            z_mac = (z_mac + (epsilon_open * delta_open * mac_key) % field_size) % field_size;
        }
        z_mac = (z_mac + field_size) % field_size;

        // 验证本地z_value的MAC
        assert(check_mac(z_value, z_mac));

        return LabeledShare(z_value, z_mac, party, &field_size);
    }
};

} // namespace emp