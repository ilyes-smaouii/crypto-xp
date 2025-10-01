#include "../TEA/tea_struct.hpp"
#include "../crypto_helpers.hpp"

#include <array>
#include <format>
#include <iostream>

int main(int argc, char *argv[]) {
  std::string some_str{argv[1]};
  std::array<byte_t, 16> key_arr{0x21, 0, 0, 0, 0, 0, 0, 0,
                                 0,    0, 0, 0, 0, 0, 0, 0x3c};
  EncryptionKey<128> some_key{key_arr};

  TEABlockAlgo my_tea_algo{some_key};

  // EncryptionKey<128> some_key_2{key_arr};
  auto encrypted_str = getEncryptedString(my_tea_algo, some_str);
  auto decrypted_str = getDecryptedString(my_tea_algo, encrypted_str);
  std::cout << std::format("encrypted_str : {} (length {})", encrypted_str,
                           encrypted_str.length())
            << std::endl;
  std::cout << std::format("decrypted_str : {} (length {})", decrypted_str,
                           decrypted_str.length())
            << std::endl;

  // auto encrypted_str_2 = getEncryptedString<TEABlockAlgo>(some_str, some_key);
  // auto decrypted_str_2 =
  //     getDecryptedString<TEABlockAlgo>(encrypted_str_2, some_key);
  // std::cout << std::format("encrypted_str_2 : {} (length {})", encrypted_str_2,
  //                          encrypted_str_2.length())
  //           << std::endl;
  // std::cout << std::format("decrypted_str_2 : {} (length {})", decrypted_str_2,
  //                          decrypted_str_2.length())
  //           << std::endl;
}