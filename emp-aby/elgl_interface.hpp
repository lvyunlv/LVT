#pragma once



#include "emp-aby/io/mp_io_channel.h"

// Required to compile on mac, remove on ubuntu
#ifdef __APPLE__
    std::shared_ptr<lbcrypto::PRNG> lbcrypto::PseudoRandomNumberGenerator::m_prng = nullptr;
#endif

namespace emp {
    // whaaaaat?
    #define MAX_MULT_DEPTH 10

    template <typename IO>
    class ELGL{
        private:
            ThreadPool* pool;
            lbcrypto::KeyPair<lbcrypto::DCRTPoly> kp;
    }
}