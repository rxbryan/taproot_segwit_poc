#include <assert.h>
#include <string.h>

#include "address.h"
#include "util.h"
#include "../crypto/ecdsa.h"
#include "../crypto/curves.h"

void get_address(const uint8_t *seed,
                              const uint32_t *path,
                              uint32_t path_length,
                              uint8_t *public_key,
                              char *address){
  HDNode node = {0};
  char addr[50] = "";
  size_t address_length = 0;
  bool status = true;
  uint32_t fingerprint = 0x0;


  hdnode_from_seed(seed, 512 / 8, SECP256K1_NAME, &node);

  for (size_t i = 0; i < path_length; i++) {
    if (0 == hdnode_private_ckd(&node, path[i])) {
      // hdnode_private_ckd returns 1 when the derivation succeeds

      return;
    }
  }
  hdnode_fill_public_key(&node);

  switch (path[0]) {
    case SEGWIT_P2SH_PATH:
      // ignoring the return status and handling by size of address
      printf("in segwit path, \n");
      ecdsa_get_address_segwit_p2sh(node.public_key, TESTNET, node.curve->hasher_pubkey, node.curve->hasher_base58, addr, 36);
      break;
    case TAPROOT_PATH:
      break;
    // TODO add support for taproot and segwit
    default:
      break;
  }

  address_length = strnlen(addr, sizeof(addr));

  assert(address_length > 0);

  /*
  if (NULL != public_key) {
    ecdsa_uncompress_pubkey(
        get_curve_by_name(SECP256K1_NAME)->params, node.public_key, public_key);
  }*/
  if (NULL != public_key) {
    memcpy(public_key, node.public_key, 33);
  }
  
  if (NULL != address) {
    memcpy(address, addr, address_length);
  }
  

  memzero(&node, sizeof(HDNode));
  return;
}

