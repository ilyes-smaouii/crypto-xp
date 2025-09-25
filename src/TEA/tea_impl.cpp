#include "tea_impl.hpp"
#include "../crypto_helpers.hpp"
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iterator>
#include <stdint.h>
#include <string>

// Code below copied from Wikipedia article, will update it later :
// https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm
// (as of 2025-09-12, 21:24 GMT+2)
// update : nvm, I don't think there's much to change here

void encryptBlockTEA_raw(uint32_t v[2], const uint32_t k[4]) {
  uint32_t v0 = v[0], v1 = v[1], sum = 0, i; /* set up */
  uint32_t delta = 0x9E3779B9;               /* a key schedule constant */
  uint32_t k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3]; /* cache key */
  for (i = 0; i < 32; i++) {                           /* basic cycle start */
    sum += delta;
    v0 += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
    v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
  } /* end cycle */
  v[0] = v0;
  v[1] = v1;
}

void encryptBlockTEA(EncryptionBlock<64> &block,
                     const EncryptionKey<128> &key) {
  auto v = reinterpret_cast<std::uint32_t *>(block.data());
  auto k = reinterpret_cast<const std::uint32_t *>(key.data());
  encryptBlockTEA_raw(v, k);
}

void decryptBlockTEA_raw(uint32_t v[2], const uint32_t k[4]) {
  uint32_t v0 = v[0], v1 = v[1], sum = 0xC6EF3720,
           i;                  /* set up; sum is (delta << 5) & 0xFFFFFFFF */
  uint32_t delta = 0x9E3779B9; /* a key schedule constant */
  uint32_t k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3]; /* cache key */
  for (i = 0; i < 32; i++) {                           /* basic cycle start */
    v1 -= ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
    v0 -= ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
    sum -= delta;
  } /* end cycle */
  v[0] = v0;
  v[1] = v1;
}

void decryptBlockTEA(EncryptionBlock<64> &block,
                     const EncryptionKey<128> &key) {
  auto v = reinterpret_cast<std::uint32_t *>(block.data());
  auto k = reinterpret_cast<const std::uint32_t *>(key.data());
  decryptBlockTEA_raw(v, k);
}

void encryptBufferTEA(byte_t *buffer, const std::size_t buffer_sz,
                      EncryptionKey<128> ec_key) {
  std::size_t curr_byte;
  auto curr_block_ptr = reinterpret_cast<std::uint32_t *>(buffer);
  for (; (byte_t *)(curr_block_ptr + 2) - buffer <= buffer_sz;
       curr_block_ptr += 2) {
    encryptBlockTEA_raw(reinterpret_cast<std::uint32_t *>(curr_block_ptr),
                        reinterpret_cast<std::uint32_t *>((ec_key.data())));
  }
  curr_byte = (byte_t *)(curr_block_ptr)-buffer;
  if (curr_byte < buffer_sz) {
    EncryptionBlock<64> end_with_padding{};
    end_with_padding.set_to_zero();
    std::memcpy(end_with_padding.data(), curr_block_ptr, buffer_sz - curr_byte);
    encryptBlockTEA(end_with_padding, ec_key);
    // encryptBlockTEA_raw(end_with_padding.dataAs<std::uint32_t*>(),
    // ec_key.dataAs<std::uint32_t*>()); TO-DO ? (copy the other way around)
    std::memcpy(curr_block_ptr, end_with_padding.data(), buffer_sz - curr_byte);
  }
}

void decryptBufferTEA(byte_t *buffer, std::size_t buffer_sz,
                      EncryptionKey<128> ec_key) {
  std::size_t curr_byte;
  auto curr_block_ptr = reinterpret_cast<std::uint32_t *>(buffer);
  for (; (byte_t *)(curr_block_ptr + 2) - buffer <= buffer_sz;
       curr_block_ptr += 2) {
    decryptBlockTEA_raw(reinterpret_cast<std::uint32_t *>(curr_block_ptr),
                        reinterpret_cast<std::uint32_t *>((ec_key.data())));
  }
  curr_byte = (byte_t *)(curr_block_ptr)-buffer;
  if (curr_byte < buffer_sz) {
    EncryptionBlock<64> end_with_padding{};
    end_with_padding.set_to_zero();
    std::memcpy(end_with_padding.data(), curr_block_ptr, buffer_sz - curr_byte);
    decryptBlockTEA(end_with_padding, ec_key);
    // encryptBlockTEA_raw(end_with_padding.dataAs<std::uint32_t*>(),
    // ec_key.dataAs<std::uint32_t*>()); TO-DO ? (copy the other way around)
    std::memcpy(curr_block_ptr, end_with_padding.data(), buffer_sz - curr_byte);
  }
}

std::string encryptStringTEA(const std::string &some_string,
                             const EncryptionKey<128> &my_key) {
  const std::size_t buf_sz =
      get_string_size_in_memory(some_string) + 1; // one byte for 0-termination
  // [alt 1]
  auto buf = reinterpret_cast<byte_t *>(std::calloc(buf_sz, 1));
  std::memcpy(buf, some_string.c_str(), buf_sz - 1);
  // std::memset(reinterpret_cast<byte_t *>(buf) + buf_sz - 1, 0, 1);
  // []
  // [alt 2]
  // auto modifiable_c_str = const_cast<byte_t*>(reinterpret_cast<const
  // byte_t*>(some_string.c_str()));
  encryptBufferTEA(buf, buf_sz - 1, my_key);
  // []
  return std::string{reinterpret_cast<char *>(buf)};
}

std::string decryptStringTEA(const std::string &some_string,
                             const EncryptionKey<128> &my_key) {
  const std::size_t buf_sz =
      get_string_size_in_memory(some_string) + 1; // one byte for 0-termination
  // [alt 1]
  auto buf = reinterpret_cast<byte_t *>(std::calloc(buf_sz, 1));
  std::memcpy(buf, some_string.c_str(), buf_sz - 1);
  // std::memset(reinterpret_cast<byte_t *>(buf) + buf_sz - 1, 0, 1);
  // []
  // [alt 2]
  // auto modifiable_c_str = const_cast<byte_t*>(reinterpret_cast<const
  // byte_t*>(some_string.c_str()));
  decryptBufferTEA(buf, buf_sz - 1, my_key);
  // []
  return std::string{reinterpret_cast<char *>(buf)};
}