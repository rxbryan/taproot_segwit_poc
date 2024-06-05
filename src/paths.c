#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <math.h>

#include "paths.h"

bool parse_bip32_path(const char* bip32_path, uint32_t * out, uint32_t out_len, uint32_t * depth_out) {
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
    printf("%s\n", components);
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
    printf("depth: %d\n", depth);
  }
  *depth_out = depth;
  return true;
}


int main() {
  const char* path =  "m/49'/0'/0'/0/5";
  uint32_t out [MAX_DEPTH];
  uint32_t depth = 0;
  bool status = parse_bip32_path(path, out, MAX_DEPTH, &depth);

int i = 0;
  while (i < depth) {
    printf("m/%x\n", out[i]);
    i++;
  }
  return 0;
}

