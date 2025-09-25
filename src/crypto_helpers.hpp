#pragma once

#include "../../cpp-common/misc.hpp"

#include <array>
#include <climits>
// #include <cstddef>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>

// #include <sys/stat.h>
// #include <time.h>
#include <stdexcept>
#include <string>

using byte_t = std::uint8_t;

// Not entirely sure about these static_assert's
// IIRC, standard requires CHAR_BIT to be *at least* 8, and if it does happen to
// be > 8, I'm not really sure it would really break anything, so the assert
// might be irrelevant
constexpr std::size_t BITS_PER_BYTE = 8;
static_assert(CHAR_BIT == BITS_PER_BYTE, "Error : expected CHAR_BIT to be equal to 8 !");
// Same for the other two below
static_assert(sizeof(byte_t) == 1, "Error : byte_t should have a size of 1 !");
static_assert(sizeof(byte_t) == sizeof(unsigned char),
              "Error : byte_t should have same size as unsigned char !");

template<typename N>
concept SameAsSelf = std::same_as<N, N>;

template <std::size_t BUFFER_SIZE>
struct FIXED_SIZE_BUFFER {
  static_assert(BUFFER_SIZE % BITS_PER_BYTE == 0, "FIXED_SIZE_BUFFER static assert error : size should be multiple of BITS_PER_BYTE !");
  std::array<byte_t, (BUFFER_SIZE / BITS_PER_BYTE)> _data{};

  // TO-DO : add relevant methods
  void set_to_zero() { _data.fill(0); }
  constexpr static std::size_t get_buffer_size() { return BUFFER_SIZE; }
  byte_t *data() { return _data.data(); }
  template<typename DT>
  DT dataAs() { return reinterpret_cast<DT>(_data.data()); }
  const byte_t *data() const { return _data.data(); }
};

/*
  Type used to represent keys, where KEY_SIZE represents the
  key's size, in bytes
*/
template <size_t KEY_SIZE>
struct EncryptionKey : public FIXED_SIZE_BUFFER<KEY_SIZE> {
  EncryptionKey(std::uint64_t val) {
    // TO-DO : figure out how memory representation is gonna work here
    std::size_t bit_count = HLP::Misc::count_bits(val);
    if (bit_count > KEY_SIZE) {
      std::string msg{
          "EncryptionKey::EncryptionKey(int) error : value too high !"};
      msg += "\n(KEY_SIZE in bytes = " + std::to_string(KEY_SIZE) +
             ", value = " + std::to_string(val) + ")";
      throw std::runtime_error(msg);
    } else {
      std::size_t byte_count = (val + BITS_PER_BYTE - 1) / BITS_PER_BYTE;
      // std::size_t byte_count = (val + 7) >> 3; // faster in theory, but less
      // clear in intention, and I'm assuming the compiler will figure out this
      // optimization anyway
      std::memcpy(this->_data.data(), &val, byte_count);
    }
  }

  constexpr static std::size_t get_key_size() {
    return FIXED_SIZE_BUFFER<KEY_SIZE>::get_buffer_size();
  }
  // TO-DO : add relevant methods
};

/*
  Type used to represent blocks, where BLOCK_SIZE represents the
  block's size, in bytes
*/
template <size_t BLOCK_SIZE>
struct EncryptionBlock : public FIXED_SIZE_BUFFER<BLOCK_SIZE> {
  // TO-DO : add relevant methods
  constexpr static std::size_t get_block_size() {
    return FIXED_SIZE_BUFFER<BLOCK_SIZE>::get_buffer_size();
  }
};

std::size_t get_string_size_in_memory(const std::string &some_str);

// TO-DO : add generic functions for encryption/decryption ?