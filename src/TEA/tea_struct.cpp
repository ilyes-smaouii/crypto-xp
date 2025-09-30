// #include <stdlib>

#include <cstdint>
#include <stdexcept>

#include "cpp-common/misc.hpp"

// #include "crypto_helpers.hpp"
#include "tea_struct.hpp"

TEABlockAlgo::TEABlockAlgo(const key_t &other_key) : _key(other_key) {}

TEABlockAlgo::key_t TEABlockAlgo::getKey() const { return _key; }

void TEABlockAlgo::setKey(const key_t &other_key) { _key = other_key; }

void TEABlockAlgo::encryptBlockRaw(HLP::Misc::my_shared_buffer buffer) {
  encryptBlockRaw(buffer, _key);
}