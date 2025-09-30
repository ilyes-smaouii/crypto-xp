#pragma once

#include "cpp-common/misc.hpp"

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
// #include <type_traits>

using byte_t = std::uint8_t;

// Not entirely sure about these static_assert's
// IIRC, standard requires CHAR_BIT to be *at least* 8, and if it does happen to
// be > 8, I'm not really sure it would really break anything, so the assert
// might be irrelevant
constexpr std::size_t BITS_PER_BYTE = 8;
static_assert(CHAR_BIT == BITS_PER_BYTE,
              "Error : expected CHAR_BIT to be equal to 8 !");
// Same for the other two below
static_assert(sizeof(byte_t) == 1, "Error : byte_t should have a size of 1 !");
static_assert(sizeof(byte_t) == sizeof(unsigned char),
              "Error : byte_t should have same size as unsigned char !");

template <std::size_t BUFFER_SIZE>
struct FIXED_SIZE_DATASPAN {
  static_assert(BUFFER_SIZE % BITS_PER_BYTE == 0,
                "FIXED_SIZE_BUFFER static assert error : size should be "
                "multiple of BITS_PER_BYTE !");
  static constexpr std::size_t BYTE_COUNT = BUFFER_SIZE / BITS_PER_BYTE;

  std::array<byte_t, BYTE_COUNT> _data{};

  // TO-DO : add relevant methods
  void set_to_zero() { _data.fill(0); }
  constexpr static std::size_t get_buffer_size() { return BUFFER_SIZE; }
  byte_t *data() { return _data.data(); }
  template <typename DT>
  DT dataAs() {
    return reinterpret_cast<DT>(_data.data());
  }
  template <typename DT>
  DT dataAs() const {
    return reinterpret_cast<DT>(_data.data());
  }
  const byte_t *data() const { return _data.data(); }
};

/*
  Type used to represent keys, where KEY_SIZE represents the
  key's size, in bytes
*/
template <size_t KEY_SIZE>
struct EncryptionKey : public FIXED_SIZE_DATASPAN<KEY_SIZE> {
  using FIXED_SIZE_DATASPAN<KEY_SIZE>::BYTE_COUNT;
  using parent_t = FIXED_SIZE_DATASPAN<KEY_SIZE>;
  

  EncryptionKey(const EncryptionKey<KEY_SIZE>& other_key) = default;

  EncryptionKey() {
    this->set_to_zero();
  }
  
  EncryptionKey(const std::array<byte_t, BYTE_COUNT> &val_array) {
    this->_data = val_array;
  }
  EncryptionKey(std::uint64_t val) {
    this->_data.fill(0);
    // TO-DO : figure out how memory representation is gonna work here
    std::size_t bit_count = HLP::Misc::count_bits(val);
    std::size_t byte_count = (val + BITS_PER_BYTE - 1) / BITS_PER_BYTE;
    if (byte_count > BYTE_COUNT) {
      std::string msg{
          "EncryptionKey::EncryptionKey(int) error : value too high !"};
      msg += "\n(KEY_SIZE in bytes = " + std::to_string(BYTE_COUNT) +
             ", value = " + std::to_string(val) + ")";
      throw std::runtime_error(msg);
    } else {
      // std::size_t byte_count = (val + 7) >> 3; // faster in theory, but less
      // clear in intention, and I'm assuming the compiler will figure out this
      // optimization anyway
      std::memcpy(this->_data.data(), &val, byte_count);
    }
  }

  constexpr static std::size_t get_key_size() {
    return FIXED_SIZE_DATASPAN<KEY_SIZE>::get_buffer_size();
  }
  // TO-DO : add relevant methods
};

/*
  Type used to represent blocks, where BLOCK_SIZE represents the
  block's size, in bytes
*/
template <size_t BLOCK_SIZE>
struct EncryptionBlock : public FIXED_SIZE_DATASPAN<BLOCK_SIZE> {
  using FIXED_SIZE_DATASPAN<BLOCK_SIZE>::BYTE_COUNT;
  // TO-DO : add relevant methods
  constexpr static std::size_t get_block_size() {
    return FIXED_SIZE_DATASPAN<BLOCK_SIZE>::get_buffer_size();
  }
};

/*
 * Concept for ciphering algorithms that can work on fixed-size blocks and keys,
 * and where each block is encrypyed/decrypted independently from the others
 */
template <typename CryptoAlgo>
concept UsableAsBlockAlgo =
    requires(CryptoAlgo algo,
             //  EncryptionBlock<CryptoAlgo::getBlockSize()> &data_block,
             HLP::Misc::my_shared_buffer shared_buf,
             const EncryptionKey<CryptoAlgo::getKeySize()> &ec_key,
             byte_t *ec_key_raw) {
      algo = CryptoAlgo{ec_key};
      {
        // returns block size in bits
        CryptoAlgo::getBlockSize()
      } -> std::same_as<std::size_t>;
      {
        // returns key size in bits
        CryptoAlgo::getKeySize()
      } -> std::same_as<std::size_t>;
      algo.setKey(ec_key);
      {
        algo.getKey()
      } -> std::same_as<EncryptionKey<CryptoAlgo::getKeySize()>>;
      /*
       * Encrypts block using given key
       */
      CryptoAlgo::encryptBlockRaw(shared_buf, ec_key);
      /*
       * State-less alternative
       */
      algo.encryptBlockRaw(shared_buf);
    };

/*
 * Returns size in bytes needed to represent a given string (exluding null
 * termination character)
 */
std::size_t get_string_size_in_memory(const std::string &some_str);

// TO-DO : add generic functions for encryption/decryption ?
template <typename CryptoAlgo, std::size_t KEY_SIZE>
void encryptBuffer(CryptoAlgo my_algo, byte_t *buf_data, std::size_t buf_len,
                   const EncryptionKey<KEY_SIZE> &my_key)
  requires UsableAsBlockAlgo<CryptoAlgo>
{

  constexpr std::size_t BLOCK_SIZE_BYTES = CryptoAlgo::getBlockSize() / 8;
  if (buf_len % BLOCK_SIZE_BYTES) {
    throw std::runtime_error(
        "Algorithm can only work on buffer of sizes that are multiple of 8 !");
  }

  std::size_t curr_byte{0};
  for (; curr_byte + BLOCK_SIZE_BYTES <= buf_len;
       curr_byte += BLOCK_SIZE_BYTES) {
    my_algo.encryptBlockRaw(buf_data + curr_byte, my_key.data());
  }
}

template <typename CryptoAlgo, std::size_t KEY_SIZE>
std::string getEncryptedString(CryptoAlgo my_algo,
                               const std::string &some_string,
                               const EncryptionKey<KEY_SIZE> &my_key)
  requires UsableAsBlockAlgo<CryptoAlgo>
{
  constexpr std::size_t BLOCK_SIZE_BYTES = CryptoAlgo::getBlockSize() / 8;

  const std::size_t buf_sz =
      BLOCK_SIZE_BYTES *
      ((get_string_size_in_memory(some_string) + BLOCK_SIZE_BYTES - 1) /
       BLOCK_SIZE_BYTES); // one byte for 0-termination
  // auto buf = reinterpret_cast<byte_t *>(std::calloc(buf_sz, 1));
  auto buf = HLP::Misc::my_shared_buffer{buf_sz + 1};
  std::memcpy(buf.data(), some_string.c_str(), buf_sz);
  encryptBuffer(my_algo, buf.data(), buf_sz, my_key);
  auto res = std::string{buf.dataAs<char *>()};
  return res;
}
