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

// SPDZ2k整数域，k=64
const uint64_t spdz2k_field_size = (1ULL << 12) ; // 2^63-1，示例用素数

namespace emp {

inline uint64_t mulmod(uint64_t a, uint64_t b, uint64_t mod) {
    return static_cast<uint64_t>((__uint128_t)a * b % mod);
}

template <typename IO>
class SPDZ2k {
public:
    ELGL<IO>* elgl;
    int party;
    int num_parties;
    std::mutex mtx;
    std::condition_variable cv;
    std::mt19937_64 rng;
    uint64_t mac_key;

    struct LabeledShare {
        uint64_t value;
        uint64_t mac;
        int owner;
        const uint64_t* field_size_ptr;
        LabeledShare() : value(0), mac(0), owner(0), field_size_ptr(nullptr) {}
        LabeledShare(uint64_t v, uint64_t m, int o, const uint64_t* fs) : value(v), mac(m), owner(o), field_size_ptr(fs) {}
        void pack(std::stringstream& ss) const {
            ss << value << " " << mac << " " << owner << " ";
        }
        void unpack(std::stringstream& ss) {
            ss >> value >> mac >> owner;
        }
        LabeledShare operator+(const LabeledShare& rhs) const {
            uint64_t fs = spdz2k_field_size;
            uint64_t v = (value + rhs.value) % fs;
            uint64_t m = (mac + rhs.mac) % fs;
            return LabeledShare(v, m, owner, field_size_ptr);
        }
        LabeledShare operator*(uint64_t scalar) const {
            uint64_t fs = spdz2k_field_size;
            uint64_t s = scalar % fs;
            uint64_t v = (value * s) % fs;
            uint64_t m = (mac * s) % fs;
            return LabeledShare(v, m, owner, field_size_ptr);
        }
    };

    struct Triple {
        uint64_t a, b, c, mac_a, mac_b, mac_c;
        Triple() : a(0), b(0), c(0), mac_a(0), mac_b(0), mac_c(0) {}
        Triple(uint64_t a, uint64_t b, uint64_t c, uint64_t ma, uint64_t mb, uint64_t mc)
            : a(a), b(b), c(c), mac_a(ma), mac_b(mb), mac_c(mc) {}
        void pack(std::stringstream& ss) const {
            ss << a << " " << b << " " << c << " " << mac_a << " " << mac_b << " " << mac_c << " ";
        }
        void unpack(std::stringstream& ss) {
            ss >> a >> b >> c >> mac_a >> mac_b >> mac_c;
        }
    };

    std::vector<Triple> triples_pool;

    void precompute_triples(size_t num_triples) {
        for (size_t i = 0; i < num_triples; i++) {
            generate_triple();
        }
    }
    void generate_triple() {
        uint64_t fs = spdz2k_field_size;
        uint64_t a_local = rng() % fs;
        uint64_t b_local = rng() % fs;
        std::stringstream ss;
        ss << a_local << " " << b_local << " ";
        elgl->serialize_sendall_with_tag(ss, 2000 * party + party);
        uint64_t a_full = a_local, b_full = b_local;
        for (int i = 1; i <= num_parties; ++i) {
            if (i != party) {
                std::stringstream ss_recv;
                elgl->deserialize_recv_with_tag(ss_recv, i, 2000 * i + i);
                uint64_t other_a, other_b;
                ss_recv >> other_a >> other_b;
                a_full = (a_full + other_a) % fs;
                b_full = (b_full + other_b) % fs;
            }
        }
        uint64_t c_full = mulmod(a_full, b_full, fs);
        uint64_t c_local = (party == 1) ? c_full : 0;
        uint64_t mac_a = mulmod(a_local, mac_key, fs);
        uint64_t mac_b = mulmod(b_local, mac_key, fs);
        uint64_t mac_c = mulmod(c_local, mac_key, fs);
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
    bool check_mac(uint64_t value, uint64_t mac) const {
        return mac == mulmod(value, mac_key, spdz2k_field_size);
    }
    void send_value_and_mac(uint64_t value, uint64_t mac, int dst) {
        std::stringstream ss;
        ss << value << " " << mac << " ";
        elgl->serialize_send_with_tag(ss, dst, 5000 * dst + party);
    }
    std::pair<uint64_t, uint64_t> recv_value_and_mac(int src) {
        std::stringstream ss;
        elgl->deserialize_recv_with_tag(ss, src, 5000 * party + src);
        uint64_t value, mac;
        ss >> value >> mac;
        return {value, mac};
    }
    SPDZ2k(ELGL<IO>* elgl_instance) : elgl(elgl_instance) {
        party = elgl->party;
        num_parties = elgl->num_party;
        unsigned seed = std::chrono::system_clock::now().time_since_epoch().count() + party;
        rng.seed(seed);
        uint64_t local_mac_key = rng() % spdz2k_field_size;
        {
            std::stringstream ss;
            ss << local_mac_key << " ";
            elgl->serialize_sendall_with_tag(ss, 3000 * party + party);
        }
        uint64_t global_mac_key = local_mac_key;
        for (int i = 1; i <= num_parties; ++i) {
            if (i != party) {
                std::stringstream ss_recv;
                elgl->deserialize_recv_with_tag(ss_recv, i, 3000 * i + i);
                uint64_t other_key;
                ss_recv >> other_key;
                global_mac_key = (global_mac_key + other_key) % spdz2k_field_size;
            }
        }
        mac_key = global_mac_key;
        precompute_triples(20);
    }
    ~SPDZ2k() {}
    LabeledShare distributed_share(uint64_t xi) {
        uint64_t fs = spdz2k_field_size;
        std::vector<uint64_t> shares(num_parties, 0);
        uint64_t remain = xi % fs;
        for (int i = 1; i <= num_parties; ++i) {
            if (i == party) continue;
            uint64_t tmp = rng() % fs;
            shares[i-1] = tmp;
            remain = (remain + fs - tmp) % fs;
        }
        shares[party-1] = remain;
        std::vector<uint64_t> received(num_parties, 0);
        for (int i = 1; i <= num_parties; ++i) {
            if (i == party) continue;
            if (party < i) {
                std::stringstream ss;
                uint64_t mac = mulmod(shares[i-1], mac_key, fs);
                ss << shares[i-1] << " " << mac << " ";
                elgl->serialize_send_with_tag(ss, i, 4000 * i + party, NORM_MSG);
                std::stringstream ss_recv;
                elgl->deserialize_recv_with_tag(ss_recv, i, 4000 * party + i, NORM_MSG);
                uint64_t share, mac2;
                ss_recv >> share >> mac2;
                assert(check_mac(share, mac2));
                received[i-1] = share % fs;
            } else {
                std::stringstream ss_recv;
                elgl->deserialize_recv_with_tag(ss_recv, i, 4000 * party + i, NORM_MSG);
                uint64_t share, mac2;
                ss_recv >> share >> mac2;
                assert(check_mac(share, mac2));
                received[i-1] = share % fs;
                std::stringstream ss;
                uint64_t mac = mulmod(shares[i-1], mac_key, fs);
                ss << shares[i-1] << " " << mac << " ";
                elgl->serialize_send_with_tag(ss, i, 4000 * i + party, NORM_MSG);
            }
        }
        received[party-1] = remain;
        uint64_t local_share = 0;
        for (int i = 0; i < num_parties; ++i) {
            local_share = (local_share + received[i]) % fs;
        }
        uint64_t mac = mulmod(local_share, mac_key, fs);
        return LabeledShare(local_share, mac, party, &spdz2k_field_size);
    }
    uint64_t reconstruct(const LabeledShare& share) {
        uint64_t fs = spdz2k_field_size;
        std::stringstream ss;
        share.pack(ss);
        elgl->serialize_sendall_with_tag(ss, 1000 * party + party);
        uint64_t result = share.value % fs;
        for (int i = 1; i <= num_parties; i++) {
            if (i != party) {
                std::stringstream ss_recv;
                elgl->deserialize_recv_with_tag(ss_recv, i, 1000 * i + i);
                LabeledShare other_share;
                other_share.unpack(ss_recv);
                other_share.field_size_ptr = &spdz2k_field_size;
                assert(check_mac(other_share.value, other_share.mac));
                uint64_t v = other_share.value % fs;
                result = (result + v) % fs;
            }
        }
        return result % fs;
    }
    LabeledShare add(const LabeledShare& x, const LabeledShare& y) {
        return x + y;
    }
    LabeledShare mul_const(const LabeledShare& x, uint64_t scalar) {
        return x * scalar;
    }
    LabeledShare multiply(const LabeledShare& x, const LabeledShare& y) {
        Triple t = get_triple();
        uint64_t fs = spdz2k_field_size;
        uint64_t epsilon = (x.value + fs - t.a) % fs;
        uint64_t delta = (y.value + fs - t.b) % fs;
        LabeledShare eps_share(
            epsilon,
            (x.mac + fs - t.mac_a) % fs,
            party,
            &spdz2k_field_size
        );
        LabeledShare del_share(
            delta,
            (y.mac + fs - t.mac_b) % fs,
            party,
            &spdz2k_field_size
        );
        uint64_t epsilon_open = reconstruct(eps_share);
        uint64_t delta_open = reconstruct(del_share);
        uint64_t z_value = (t.c + mulmod(epsilon_open, t.b, fs) + mulmod(delta_open, t.a, fs)) % fs;
        if (party == 1) {
            z_value = (z_value + mulmod(epsilon_open, delta_open, fs)) % fs;
        }
        uint64_t z_mac = (t.mac_c + mulmod(epsilon_open, t.mac_b, fs) + mulmod(delta_open, t.mac_a, fs)) % fs;
        if (party == 1) {
            z_mac = (z_mac + mulmod(mulmod(epsilon_open, delta_open, fs), mac_key, fs)) % fs;
        }
        assert(check_mac(z_value, z_mac));
        return LabeledShare(z_value, z_mac, party, &spdz2k_field_size);
    }
};

} // namespace emp
