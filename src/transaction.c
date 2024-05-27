#include <string.h>
#include <stdio.h>
#include <assert.h>

#include "transaction.h"
#include "util.h"
#include "../crypto/sha2.h"
#include "../crypto/secp256k1.h"
#include "../crypto/ecdsa.h"
#include "../crypto/curves.h"

bool calculate_p2wpkh_in_p2sh_digest(
                                    uint32_t version,
                                    uint8_t* hash_prevouts,
                                    uint8_t* hash_sequence,
                                    uint8_t* hash_outputs,
                                    uint8_t* outpoint,
                                    uint8_t *scriptpubkey,
                                    uint64_t amount,
                                    uint32_t nsequence,
                                    uint32_t n_locktime,
                                    uint32_t n_hashtype,
                                    uint8_t *digest) {
  uint8_t buffer[100] = {0};
  uint8_t buffer_2[2000] = {0};
  uint32_t len = 0;
  SHA256_CTX sha_256_ctx = {0};
  //input_index

  memzero(&sha_256_ctx, sizeof(sha_256_ctx));
  sha256_Init(&sha_256_ctx);

  // digest version
  write_le(buffer, version);
  write_le(buffer_2, version);
  len +=4;
  sha256_Update(&sha_256_ctx, buffer, 4);

  memcpy(buffer_2+len,hash_prevouts, 32);
  sha256_Update(&sha_256_ctx, hash_prevouts, 32);
  len +=32;
  memcpy(buffer_2+len,hash_sequence, 32);
  sha256_Update(&sha_256_ctx, hash_sequence, 32);
  len +=32;
  // outpoint
  sha256_Update(&sha_256_ctx, outpoint, 36);

  memcpy(buffer_2+len,outpoint, 36);
  len +=36;

  /* Scriptcode */
  // Leading size bytes
  buffer[0] = 0x19;
  buffer[1] = 0x76;
  sha256_Update(&sha_256_ctx, buffer, 2);
memcpy(buffer_2+len,buffer, 2);
  len +=2;

  sha256_Update(&sha_256_ctx, scriptpubkey, 22);
  memcpy(buffer_2+len,scriptpubkey, 22);
  len +=22;
  buffer[0] = 0x88;
  buffer[1] = 0xac;
  sha256_Update(&sha_256_ctx, buffer, 2);
  memcpy(buffer_2+len,buffer, 2);
  len +=2;

  // digest the 64-bit value (little-endian)
  sha256_Update(&sha_256_ctx, (uint8_t *)&amount, 8);
  memcpy(buffer_2+len,(uint8_t *)&amount, 8);
  len +=8;

  write_le(buffer, nsequence);
  memcpy(buffer_2+len,buffer, 4);
  len +=4;
  sha256_Update(&sha_256_ctx, buffer, 4);
  sha256_Update(&sha_256_ctx, hash_outputs, 32);
    memcpy(buffer_2+len, hash_outputs, 32);
  len +=32;

  // digest locktime and sighash
  write_le(buffer, n_locktime);
  write_le(buffer + 4, n_hashtype);
    memcpy(buffer_2+len,buffer, 8);
  len +=8;
  sha256_Update(&sha_256_ctx, buffer, 8);

  print_byte_array(buffer_2, len, "hash preimage");
  // double hash
  sha256_Final(&sha_256_ctx, digest);
  sha256_Raw(digest, 32, digest);
  memzero(&sha_256_ctx, sizeof(sha_256_ctx));
  return true;
}

void sign_input_transaction(
                            txnInput *input_Data,
                            txnOutput *output_data,
                            txnMetadata *data,
                            uint8_t *private_key,
                            uint8_t** signatures)
{
  uint8_t buffer[500] = {0};
  for (uint32_t txindex = 0; txindex < data->input_count; txindex++ ) {
    uint8_t digest[32];

    uint8_t hash_prevouts[32];
    uint8_t hash_sequence[32];
    uint8_t hash_outputs[32];
    uint8_t outpoint[36];

    // hash previous output
    uint32_t len = 0;
    for (uint32_t i = 0; i < data->input_count; i++) {
      memcpy(buffer+len, input_Data[i].prev_txn_hash, 32);
      len += 32;
      write_le(buffer+len, input_Data[i].prev_output_index);
      len +=4;
    }
    // double hash
    sha256_Raw(buffer, 36, hash_prevouts);
    sha256_Raw(hash_prevouts, 32, hash_prevouts);

    // hash sequence
    write_le(buffer, input_Data[txindex].sequence);
    sha256_Raw(buffer, 4, hash_sequence);
    sha256_Raw(hash_sequence, 32, hash_sequence);
    
    // hash outputs
    len = 0;
    for (uint32_t i = 0; i < data->output_count; i++) {
      memcpy(buffer+len, (uint8_t *)&output_data[i].value, 8);
      len += 8;
      memcpy(buffer+len, output_data[i].script_pub_key, 26);
      len +=26;
    }
    // double hash
    sha256_Raw(buffer, len, hash_outputs);
    sha256_Raw(hash_outputs, 32, hash_outputs);

    print_byte_array(hash_prevouts, 32, "hash_prevouts");
    print_byte_array(hash_sequence, 32, "hash_sequence");
    print_byte_array(hash_outputs, 32, "hash_outputs");

    //outpoint
    memcpy(outpoint, input_Data[txindex].prev_txn_hash, 32);
    write_le(outpoint+32, input_Data[txindex].prev_output_index);

    print_byte_array(outpoint, 36, "outpoint");

    calculate_p2wpkh_in_p2sh_digest(
      data->version,
      hash_prevouts,
      hash_sequence,
      hash_outputs,
      outpoint,
      input_Data[txindex].script_pub_key,
      input_Data[txindex].value,
      input_Data[txindex].sequence,
      data->locktime,
      data->sighash,
      digest
    );

    print_byte_array(digest, 32, "digest");

    const ecdsa_curve *curve = &secp256k1;
    ecdsa_sign_digest(curve, private_key, digest, signatures[txindex], NULL, NULL);

    uint8_t public_key[33] = {0};
    ecdsa_get_public_key33(curve, private_key, public_key);
    

    uint32_t size = btc_sig_to_script_sig(signatures[txindex], public_key, signatures[txindex]);
    assert(size > 0);
    signatures[txindex][71] = 0x01; 
    
    print_byte_array(signatures[txindex], 72, "btc_sig");
  }
}
