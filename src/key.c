#include <stdbool.h>

#include "util.h"
#include "key.h"
#include "../crypto/curves.h"

const int P2WPKH_P2SH_TESTNET_VERSION_BYTES = 0x044a5262;
const int P2WPKH_P2SH_MAINNET_VERSION_BYTES = 0x049d7cb2;

bool generate_xpub(const uint32_t *path,
                       size_t path_length,
                       const char *curve,
                       const uint8_t *seed,
                       char *str)
{
  if (!curve)
  {
    curve = SECP256K1_NAME;
  }
  uint32_t fingerprint = 0x0;
  HDNode node = {0};
  bool status = true;

  hdnode_from_seed(seed, 512 / 8, curve, &node);

  for (size_t i = 0; i < path_length; i++) {
    if (0 == hdnode_private_ckd(&node, path[i])) {
      // hdnode_private_ckd returns 1 when the derivation succeeds

      return false;
    }
  }
  hdnode_fill_public_key(&node);

  fingerprint = hdnode_fingerprint(&node);

  if (0 ==
      hdnode_serialize_public(&node, fingerprint, P2WPKH_P2SH_TESTNET_VERSION_BYTES, str, XPUB_SIZE)) {
    status &= false;
  }
  memzero(&node, sizeof(HDNode));
  return status;

}


