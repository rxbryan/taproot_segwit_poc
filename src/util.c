#include <string.h>

#include "util.h"

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
