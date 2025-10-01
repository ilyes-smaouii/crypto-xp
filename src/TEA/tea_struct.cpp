// #include <stdlib>

// #include <cstdint>
// #include <stdexcept>

// #include "cpp-common/misc.hpp"
#include "crypto_helpers.hpp"

#include "tea_struct.hpp"

TEABlockAlgo::TEABlockAlgo(const key_t &other_key) : _key(other_key) {}

const TEABlockAlgo::key_t &TEABlockAlgo::getKey() const { return _key; }

void TEABlockAlgo::setKey(const key_t &other_key) { _key = other_key; }

void TEABlockAlgo::encryptBlockRaw(byte_t* buf_data) {
  encryptBlockRaw(buf_data, _key);
}

void TEABlockAlgo::decryptBlockRaw(byte_t* buf_data) {
  decryptBlockRaw(buf_data, _key);
}