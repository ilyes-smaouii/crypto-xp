#include <climits>

using byte_t = unsigned char;

static_assert(CHAR_BIT == 8, "Error : expected CHAR_BIT to be equal to 8 !");
static_assert(sizeof(byte_t) == 1, "Error : byte_t should have a size of 1 !");

/* 
Type used to represent keys, where KEY_SIZE represents the
key's size, in bytes
*/
template<size_t KEY_SIZE>
struct MyKeyType {
  byte_t _data[KEY_SIZE]{};

  // TO-DO : add relevant methods
};