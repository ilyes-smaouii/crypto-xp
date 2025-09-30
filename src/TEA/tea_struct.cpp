// #include <stdlib>

#include <cstdint>
#include <stdexcept>

#include "cpp-common/misc.hpp"

// #include "crypto_helpers.hpp"
#include "tea_struct.hpp"

TEABlockAlgo::TEABlockAlgo(const key_t &other_key) : _key(other_key) {}

TEABlockAlgo::key_t TEABlockAlgo::getKey() const { return _key; }

void TEABlockAlgo::setKey(const key_t &other_key) { _key = other_key; }

void TEABlockAlgo::encryptBlockRaw(HLP::Misc::my_shared_buffer buffer,
                                   const key_t &key) {
  auto buf_len = buffer.getSize();
  if (buf_len != 4 /* i.e. getBlockSize() / 8 */) {
    throw std::runtime_error("");
  }
  auto v = buffer.dataAs<std::uint32_t *>();
  auto v0 = *(buffer.getNthBytePtrAs<std::uint32_t *>(0));
  auto v1 = *(buffer.getNthBytePtrAs<std::uint32_t *>(4));
  std::uint32_t delta = 0x9E3779B9;
  auto k = key.dataAs<const std::uint32_t *>();
  std::uint32_t k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];
  std::uint32_t sum = 0, i;
  for (std::size_t i = 0; i < 32; i++) { /* basic cycle start */
    sum += delta;
    v0 += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
    v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
  } /* end cycle */
  v[0] = v0;
  v[1] = v1;
}