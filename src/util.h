#ifndef __UTIL_H__
#define __UTIL_H__

#include "../crypto/bip32.h"


size_t hex2bytes(uint8_t *dest, size_t count, const char *src);

bool parse_bip32_path(
                      const char* bip32_path,
                      uint32_t * out,
                      uint32_t out_len,
                      uint32_t * depth_out);
#endif

