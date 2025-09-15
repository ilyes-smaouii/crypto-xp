#pragma once

#include "../crypto_helpers.hpp"
#include <stdint.h>
#include <string>

// Code below copied from Wikipedia article, will update it later :
// https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm
// (as of 2025-09-12, 21:24 GMT+2)
// update : nvm, I don't think there's much to change here

/*
  Arguments : 64-bit block "v" to encrypt, 128-bit key "k"
  Effect : encrypts "v" using TEA, with "k"
*/
void encryptBlockTEA_raw(uint32_t v[2], const uint32_t k[4]);

void encryptBlockTEA(EncryptionBlock<64> block, const EncryptionKey<128> key);

/*
  Arguments : 64-bit block "v" to decrypt, 128-bit key "k"
  Effect : decrypts "v" using TEA, with "k"
*/
void decryptBlockTEA_raw(uint32_t v[2], const uint32_t k[4]);

void decryptBlockTEA(EncryptionBlock<64> block, const EncryptionKey<128> key);

void encryptBufferTEA(byte_t *buffer, const std::size_t buffer_sz,
                      EncryptionKey<128> ec_key);

void decryptBufferTEA(byte_t *buffer, const std::size_t buffer_sz,
                      EncryptionKey<128> ec_key);

std::string encryptString(const std::string& some_string);