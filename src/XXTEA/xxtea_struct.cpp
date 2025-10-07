// #include <stdlib>

// #include <cstdint>
// #include <stdexcept>

// #include "cpp-common/misc.hpp"
#include "crypto_helpers.hpp"

#include "xxtea_struct.hpp"

XXTEABlockAlgo::XXTEABlockAlgo(const key_t &other_key) : _key(other_key) {}

const XXTEABlockAlgo::key_t &XXTEABlockAlgo::getKey() const { return _key; }

void XXTEABlockAlgo::setKey(const key_t &other_key) { _key = other_key; }

void XXTEABlockAlgo::encryptBlockRaw(byte_t* buf_data) {
  encryptBlockRaw(buf_data, _key);
}

void XXTEABlockAlgo::decryptBlockRaw(byte_t* buf_data) {
  decryptBlockRaw(buf_data, _key);
}