#include "../TEA/tea_impl.hpp"
// #include "../crypto_helpers.hpp"

#include <array>
#include <iostream>
#include <format>

int main(int argc, char *argv[]) {
  std::string some_str{argv[1]};
  std::array<byte_t, 16> key_arr{0x21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  EncryptionKey<128> some_key{key_arr};
  // EncryptionKey<128> some_key_2{key_arr};
  auto encrypted_str = encryptStringTEA(some_str, some_key);
  auto decrypted_str = decryptStringTEA(encrypted_str, some_key);
  std::cout << std::format("{} (length {})", encrypted_str, encrypted_str.length()) << std::endl;
  std::cout << std::format("{} (length {})", decrypted_str, decrypted_str.length()) << std::endl;
}