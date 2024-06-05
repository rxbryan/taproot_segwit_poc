#include <assert.h>
#include <string.h>
#include <stdio.h>

#include "address.h"
#include "util.h"
#include "../crypto/ecdsa.h"
#include "../crypto/curves.h"
#include "../crypto/segwit_addr.h"
#include "../crypto/zkp_context.h"
#include "../crypto/zkp_bip340.h"
#include "../secp256k1/include/secp256k1.h"
#include "../secp256k1/include/secp256k1_extrakeys.h"

void generate_taproot_address(uint8_t * , char *);

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
      ecdsa_get_address_segwit_p2sh(node.public_key, TESTNET, node.curve->hasher_pubkey, node.curve->hasher_base58, addr, 36);
      break;
    case TAPROOT_PATH:
    generate_taproot_address(node.public_key, address);
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

void generate_taproot_address(uint8_t * public_key, char * address_out) {
  if (!zkp_context_is_initialized()) {
    // init context
    zkp_context_init();
  }

  // acquire writable
  secp256k1_context * context = zkp_context_acquire_writable();
  secp256k1_pubkey pubkey = {0};

  int status = secp256k1_ec_pubkey_parse(context, &pubkey, public_key, 33);
  assert(status == 1);


  // TODO: use "secp256k1_xonly_pubkey_from_pubkey"
  // Check if y-coordinate is odd
  if (SECP256K1_TAG_PUBKEY_ODD == public_key[0]) {
    // negate public key
    status = secp256k1_ec_pubkey_negate(context, &pubkey);
    
  }

  secp256k1_xonly_pubkey xonly_in_pubkey = {0};
  if (secp256k1_xonly_pubkey_from_pubkey(context,
                                           &xonly_in_pubkey, NULL,
                                           &pubkey) != 1) {
      assert(1);
  } 

  uint8_t xonly_in[32] = {0};
  if (secp256k1_xonly_pubkey_serialize(context, xonly_in,
                                         &xonly_in_pubkey) != 1) {
      assert(1);
  }

  //tweak public key
  uint8_t output_public_key[32] = {0};

  status = zkp_bip340_tweak_public_key(xonly_in,
                                NULL,
                                output_public_key);
  
  assert(status != 0);

  print_byte_array(public_key, 33, "public key");
  print_byte_array(output_public_key, 32, "output public key");

  // hash public key
  uint8_t h[HASHER_DIGEST_LENGTH] = {0};
  //hasher_Raw(HASHER_SHA2_RIPEMD, output_public_key, 32, h);

  //uint8_t address_raw[22] = {0};
  //address_raw[0] = 0x51;
  //memcpy(address_raw+1, h, 20);

  // encode address

  //bech32_encode(address_out, "bc", address_raw, 21, BECH32_ENCODING_BECH32M);
  segwit_addr_encode(address_out,"bc", 1, output_public_key, 32);
  //print_byte_array(address_raw, 21, "address_raw");

  print_byte_array (address_out, 33, "address out");

  printf("address out: %s", address_out);
  //uint8_t ser_pubkey[33] = {0};
  //secp256k1_ec_pubkey_serialize(context, &ser_pubkey, 33, &pubkey, SECP256K1_EC_COMPRESSED);

  zkp_context_release_writable();
}