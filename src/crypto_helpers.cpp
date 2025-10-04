#include "crypto_helpers.hpp"
#include <string>

std::size_t get_string_size_in_memory(const std::string &some_str) {
  constexpr std::size_t CHAR_SIZE = sizeof(std::string::traits_type::char_type);
  return CHAR_SIZE * some_str.length();
}