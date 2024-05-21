
static bool one_shot_xpub_generate(const btc_get_xpub_derivation_path_t *paths,
                                   const uint8_t *seed,
                                   char xpubs[][XPUB_SIZE],
                                   pb_size_t count) {
  for (pb_size_t index = 0; index < count; index++) {
    const btc_get_xpub_derivation_path_t *path = &paths[index];
    uint32_t xpub_ver = 0;
    if (!btc_get_version(path->path[0], &xpub_ver) ||
        !btc_generate_xpub(path->path,
                           path->path_count,
                           SECP256K1_NAME,
                           seed,
                           xpub_ver,
                           xpubs[index])) {
      return false;
    }
  }
  return true;
}

