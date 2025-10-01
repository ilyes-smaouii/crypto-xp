#pragma once

#include <cstddef>
// #include <format>

// Dependencies from other projects
// #include "cpp-common/misc.hpp"

#include "../crypto_helpers.hpp"

struct TEABlockAlgo {
  using key_t = EncryptionKey<128>;

private:
  static constexpr std::uint32_t DELTA = 0x9E3779B9;
  static constexpr std::uint32_t INITIAL_SUM_DECRYPTION = 0xC6EF3720;

public:
  key_t _key{};

  TEABlockAlgo() = default;
  TEABlockAlgo(const key_t &ec_key);

  static constexpr std::size_t getBlockSize() { return 64; };
  static constexpr std::size_t getKeySize() { return 128; };

  const key_t &getKey() const;
  void setKey(const key_t &ec_key);

  static void encryptBlockRaw(byte_t *buf_data, const key_t &key) {
    std::uint32_t *v = reinterpret_cast<std::uint32_t *>(buf_data);
    std::uint32_t v0 = *(reinterpret_cast<std::uint32_t *>(buf_data));
    std::uint32_t v1 = *(reinterpret_cast<std::uint32_t *>(buf_data + 4));
    auto k = key.dataAs<const std::uint32_t *>();
    std::uint32_t k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];
    std::uint32_t sum = 0, i;
    for (std::size_t i = 0; i < 32; i++) { /* basic cycle start */
      sum += DELTA;
      v0 += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
      v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
    } /* end cycle */
    v[0] = v0;
    v[1] = v1;
  }

  void encryptBlockRaw(byte_t *buf_data);

  static void decryptBlockRaw(byte_t *buf_data, const key_t &key) {
    std::uint32_t *v = reinterpret_cast<std::uint32_t *>(buf_data);
    std::uint32_t v0 = *(reinterpret_cast<std::uint32_t *>(buf_data));
    std::uint32_t v1 = *(reinterpret_cast<std::uint32_t *>(buf_data + 4));
    auto k = key.dataAs<const std::uint32_t *>();
    std::uint32_t k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];
    std::uint32_t sum = INITIAL_SUM_DECRYPTION, i;
    for (std::size_t i = 0; i < 32; i++) { /* basic cycle start */
      v1 -= ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
      v0 -= ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
      sum -= DELTA;
    } /* end cycle */
    v[0] = v0;
    v[1] = v1;
  }

  void decryptBlockRaw(byte_t *buf_data);
};