#ifndef __ADDRESS_H__
#define __ADDRESS_H__

#include "../crypto/bip32.h"

#define SEGWIT_P2SH_PATH 0x80000031
#define TAPROOT_PATH 0x80000056

#define MAINNET 0x05
#define TESTNET 0xc4

void get_address(const uint8_t *seed,
                              const uint32_t *path,
                              uint32_t path_length,
                              uint8_t *public_key,
                              char *address);


#endif