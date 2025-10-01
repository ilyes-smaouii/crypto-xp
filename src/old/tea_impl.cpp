#include "tea_impl.hpp"
#include "../crypto_helpers.hpp"
// #include <array>
// #include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
// #include <iterator>
#include <stdexcept>
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
  auto v = block.dataAs<std::uint32_t *>();
  auto k = key.dataAs<const std::uint32_t *>();
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
  auto v = block.dataAs<std::uint32_t *>();
  auto k = key.dataAs<const std::uint32_t *>();
  decryptBlockTEA_raw(v, k);
}

void encryptBufferTEA(byte_t *buffer, const std::size_t buffer_sz,
                      EncryptionKey<128> ec_key) {
  std::size_t curr_byte{0};

  constexpr std::size_t BLOCK_SIZE_TEA_BYTES = 8;
  if (buffer_sz % BLOCK_SIZE_TEA_BYTES) {
    throw std::runtime_error(
        "Algorithm can only work on buffer of sizes that are multiple of 8 !");
  }

  // auto curr_block_ptr = reinterpret_cast<std::uint32_t *>(buffer);
  for (; (byte_t *)(buffer + curr_byte + 8) - buffer <= buffer_sz;
       curr_byte += 8) {
    encryptBlockTEA_raw(reinterpret_cast<std::uint32_t *>(buffer + curr_byte),
                        reinterpret_cast<std::uint32_t *>((ec_key.data())));
  }
  // curr_byte = (buffer + curr_byte) - buffer;
  /* if (curr_byte < buffer_sz) {
    throw std::runtime_error("Algorithm can only work on buffer of sizes that
  are multiple of 8 !"); EncryptionBlock<64> end_with_padding{};
    end_with_padding.set_to_zero();
    std::memcpy(end_with_padding.data(), buffer + curr_byte,
                buffer_sz - curr_byte);
    // encryptBlockTEA(end_with_padding, ec_key);
    encryptBlockTEA_raw(end_with_padding.dataAs<std::uint32_t *>(),
                        ec_key.dataAs<std::uint32_t *>()); // TO-DO ? (copy the
                                                           // other way around)
    std::memcpy(buffer + curr_byte, end_with_padding.data(),
                8);
  } */
}

void decryptBufferTEA(byte_t *buffer, std::size_t buffer_sz,
                      EncryptionKey<128> ec_key) {
  std::size_t curr_byte{0};
  constexpr std::size_t BLOCK_SIZE_TEA_BYTES = 8;

  if (buffer_sz % BLOCK_SIZE_TEA_BYTES) {
    throw std::runtime_error(
        "Algorithm can only work on buffer of sizes that are multiple of 8 !");
  }

  // auto curr_block_ptr = reinterpret_cast<std::uint32_t *>(buffer);
  for (; (byte_t *)(buffer + curr_byte + 8) - buffer <= buffer_sz;
       curr_byte += 8) {
    decryptBlockTEA_raw(reinterpret_cast<std::uint32_t *>(buffer + curr_byte),
                        reinterpret_cast<std::uint32_t *>((ec_key.data())));
  }
  // curr_byte = (buffer + curr_byte) - buffer;
  /* if (curr_byte < buffer_sz) {
    EncryptionBlock<64> end_with_padding{};
    end_with_padding.set_to_zero();
    std::memcpy(end_with_padding.data(), buffer + curr_byte,
                buffer_sz - curr_byte);
    // decryptBlockTEA(end_with_padding, ec_key);
    decryptBlockTEA_raw(
        end_with_padding.dataAs<std::uint32_t *>(),
        ec_key.dataAs<std::uint32_t *>()); // TO-DO ? (copy the other way
                                           // around)
    std::memcpy(buffer + curr_byte, end_with_padding.data(),
                8);
  } */
}

std::string encryptStringTEA(const std::string &some_string,
                             const EncryptionKey<128> &my_key) {

  constexpr std::size_t BLOCK_SIZE_TEA_BYTES = 8;

  const std::size_t buf_sz =
      BLOCK_SIZE_TEA_BYTES *
      ((get_string_size_in_memory(some_string) + BLOCK_SIZE_TEA_BYTES - 1) /
       BLOCK_SIZE_TEA_BYTES); // one byte for 0-termination
  // [alt 1]
  // auto buf = reinterpret_cast<byte_t *>(std::calloc(buf_sz, 1));
  auto buf = HLP::Misc::my_shared_buffer{buf_sz + 1};
  std::memcpy(buf.data(), some_string.c_str(), buf_sz);
  encryptBufferTEA(buf.data(), buf_sz, my_key);
  // []
  auto res = std::string{buf.dataAs<char *>()};
  return res;
}

std::string decryptStringTEA(const std::string &some_string,
                             const EncryptionKey<128> &my_key) {
  constexpr std::size_t BLOCK_SIZE_TEA_BYTES = 8;

  const std::size_t buf_sz =
      BLOCK_SIZE_TEA_BYTES *
      ((get_string_size_in_memory(some_string) + BLOCK_SIZE_TEA_BYTES - 1) /
       BLOCK_SIZE_TEA_BYTES); // one byte for 0-termination
  // [alt 1]
  // auto buf = reinterpret_cast<byte_t *>(std::calloc(buf_sz, 1));
  auto buf = HLP::Misc::my_shared_buffer{buf_sz + 1};
  std::memcpy(buf.data(), some_string.c_str(), buf_sz);
  decryptBufferTEA(buf.data(), buf_sz, my_key);
  // []
  auto res = std::string{buf.dataAs<char *>()};
  return res;
}

// TO-DO : use crypto_helpers' generic functions once they're implemented