#include "../TEA/tea_impl.hpp"
// #include "../crypto_helpers.hpp"

#include <array>
#include <iostream>

int main(int argc, char *argv[]) {
  std::string some_str{argv[1]};
  EncryptionKey<128> some_key{33};
  std::array<byte_t, 16> key_arr{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  // EncryptionKey<128> some_key_2{key_arr};
  std::cout << encryptStringTEA(some_str, some_key) << std::endl;
}