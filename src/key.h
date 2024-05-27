#ifndef __KEY_H__
#define __KEY_H__

#include <stdbool.h>

#include "../crypto/bip32.h"

#define XPUB_SIZE 113

#define P2TR 0x80000056
#define P2WPKH_IN_P2SH 0x80000031

bool generate_xpub(const uint32_t *path,
                       size_t path_length,
                       const char *curve,
                       const uint8_t *seed,
                       char *str);


#endif