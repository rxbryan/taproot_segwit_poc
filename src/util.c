#include <string.h>
#include <stdio.h>
#include "../crypto/ecdsa.h"
#include "util.h"

void print_byte_array(uint8_t *arr, size_t size, const char * array_name) {
  printf("%s: ", array_name);
    for (int i = 0; i < size; i++) {
      printf("%02x", arr[i]);
    }
    printf("\n");
}

size_t hex2bytes(uint8_t *dest, size_t count, const char *src) {
  size_t i = 0;
  int value;
  for (i = 0; i < count && sscanf(src + i * 2, "%2x", &value) == 1; i++) {
      dest[i] = value;
  }
  return i;
}

bool parse_bip32_path(
                      const char* bip32_path,
                      uint32_t * out,
                      uint32_t out_len,
                      uint32_t * depth_out
                      ) {
  if (!bip32_path || !out) {
    return false;
  }

  char* copy = strdup(bip32_path);
  if (!copy) {
    return false;
  }

  char* components = strtok(copy, "/");
  if (!components || strcmp(components, "m") != 0) {
    free(copy);
    return false;
  }

 uint32_t depth = 0;

  while (((components = strtok(NULL, "/")) != NULL)) {
    if (depth == out_len)
      return false;

    int hardened = 0;
    size_t len = strlen(components);
    if (components[len - 1] == '\'') {
      components[len - 1] = '\0';
      hardened = 1;
    } else {
      hardened = 0;
    }

    if (hardened) {
      out[depth] = 2147483648 + strtol(components, NULL, 10);
    }
    else {
      out[depth] = strtol(components, NULL, 10);
    }

    depth++;
  }
  *depth_out = depth;
  return true;
}

uint8_t btc_sig_to_script_sig(const uint8_t *sig,
                              const uint8_t *pub_key,
                              uint8_t *script_sig) {
  uint8_t script_sig_len = 0;
  if (NULL == sig || NULL == pub_key || NULL == script_sig) {
    return script_sig_len;
  }

  uint8_t script[128] = {0};
  memzero(script, sizeof(script));
  uint8_t der_sig_len = ecdsa_sig_to_der(sig, &script[1]);

  // PUSHDATA Opcode(1) + der_sig_len + SigHash Code(1) + PUSHDATA Opcode(1) +
  // Public Key(33)
  script_sig_len = 1 + der_sig_len + 2 + 33;
  script[0] = der_sig_len + 1;
  script[1 + der_sig_len] = 1;         // sighash code: 1
  script[1 + der_sig_len + 1] = 33;    // push data opcode: 33
  memcpy(&script[1 + der_sig_len + 1 + 1], pub_key, 33);
  memcpy(script_sig, script, 128);
  return script_sig_len;
}
