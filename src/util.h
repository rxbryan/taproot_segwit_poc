#ifndef __UTIL_H__
#define __UTIL_H__

#include "../crypto/bip32.h"
#include "../crypto/memzero.h"

void print_byte_array(uint8_t *arr, size_t size, const char * array_name);

size_t hex2bytes(uint8_t *dest, size_t count, const char *src);

bool parse_bip32_path(
                      const char* bip32_path,
                      uint32_t * out,
                      uint32_t out_len,
                      uint32_t * depth_out);

uint8_t btc_sig_to_script_sig(const uint8_t *sig,
                              const uint8_t *pub_key,
                              uint8_t *script_sig);
#endif

