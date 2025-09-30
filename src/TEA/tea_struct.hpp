#pragma once

#include <cstddef>

// Dependencies from other projects
#include "cpp-common/misc.hpp"

#include "../crypto_helpers.hpp"


struct TEABlockAlgo {
  using key_t = EncryptionKey<128>;

  key_t _key{};

  TEABlockAlgo(const key_t &ec_key);

  static constexpr std::size_t getBlockSize() { return 64; };
  static constexpr std::size_t getKeySize() { return 128; };

  key_t getKey() const;
  void setKey(const key_t &ec_key);

  void encryptBlockRaw(HLP::Misc::my_shared_buffer buf, const key_t& ec_key);
};