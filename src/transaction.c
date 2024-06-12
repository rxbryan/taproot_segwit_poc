#include <string.h>
#include <stdio.h>
#include <assert.h>

#include "transaction.h"
#include "util.h"
#include "../crypto/sha2.h"
#include "../crypto/secp256k1.h"
#include "../crypto/ecdsa.h"
#include "../crypto/curves.h"

#include "../crypto/zkp_bip340.h"

const uint8_t TAP_SIG_HASH[] = {
    244, 10, 72, 223, 75, 42, 112, 200, 180, 146, 75, 242, 101, 70, 97, 237, 61,
    149, 253, 102, 163, 19, 235, 135, 35, 117, 151, 198, 40, 228, 160, 49, 244,
    10, 72, 223, 75, 42, 112, 200, 180, 146, 75, 242, 101, 70, 97, 237, 61, 149,
    253, 102, 163, 19, 235, 135, 35, 117, 151, 198, 40, 228, 160, 49,
  };

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
    sha256_Raw(buffer, len, hash_prevouts);
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

void sign_taproot_tx(
                      txnInput *input_Data,
                      txnOutput *output_data,
                      txnMetadata *data,
                      uint8_t *private_key,
                      uint8_t** signatures,
                      uint8_t ** digest_out) {


  // Calculate relevant hashes based on hash_type
  uint8_t sha_prevouts[32] = {0};
  uint8_t sha_amounts[32] = {0};
  uint8_t sha_scriptpubkeys[32] = {0};
  uint8_t sha_sequences[32] = {0};
  uint8_t sha_outputs[32] = {0};
  uint8_t sha_annex[32] = {0};
  uint8_t sha_single_output[32] = {0};

  for (uint32_t txindex = 0; txindex < data->input_count; txindex++){
    uint8_t buffer[206] = {0};
    uint8_t digest[32] = {0};
    uint32_t len = 0;
    
    bool annex = !(!data->annex);

    uint8_t output_type = (data->sighash == SIGHASH_DEFAULT) ? SIGHASH_ALL : data->sighash & SIGHASH_OUTPUT_MASK;
    uint8_t input_type = data->sighash & SIGHASH_INPUT_MASK;
    bool is_anyone_can_pay = (input_type == SIGHASH_ANYONECANPAY);
    bool is_none = (output_type == SIGHASH_NONE);
    bool is_single = (output_type == SIGHASH_SINGLE);

    uint8_t prefix = 0x00;
    memcpy(buffer, (uint8_t *)&prefix, 1);
    len += 1;

    memcpy(buffer+len, (uint8_t *)&data->sighash, 1);
    len += 1;
    
    write_le(buffer+len, data->version);
    len += 4;

    print_byte_array(buffer, len, "initial buffer");
    write_le(buffer+len, data->locktime);
    len += 4;

    if (!is_anyone_can_pay) {
      // Calculate sha_prevouts, sha_amounts, sha_scriptpubkeys, sha_sequences
      {
        //sha_prevouts
        uint8_t * prevouts_buf = malloc(36*data->input_count);
        memzero(prevouts_buf, 36*data->input_count);

        for (uint32_t i = 0, l = 0; i < data->input_count; i++) {
          memcpy(prevouts_buf+l, input_Data[i].prev_txn_hash, 32);
          l +=32;
          memcpy(prevouts_buf+l, (uint8_t*)&input_Data[i].prev_output_index, 4);
          l+4;
        }
      
        sha256_Raw(prevouts_buf, 36*data->input_count, sha_prevouts);
        print_byte_array(prevouts_buf, 36*data->input_count, "prevouts");

        print_byte_array(sha_prevouts, 32, "sha_prevouts");
      }

    print_byte_array(buffer, len, "initial buffer");
      memcpy(buffer+len, sha_prevouts, 32);
      len += 32;

    print_byte_array(buffer, len, "initial buffer");
      {
        //sha_amounts
        SHA256_CTX sha_256_ctx = {0};
        memzero(&sha_256_ctx, sizeof(sha_256_ctx));

        sha256_Init(&sha_256_ctx);

        for (uint32_t i = 0; i < data->input_count; i++) {
          sha256_Update(&sha_256_ctx, (uint8_t*)&input_Data[i].value, 8);
        }
      
        sha256_Final(&sha_256_ctx, sha_amounts);      
        memcpy(buffer+len, sha_amounts, 32);
        len += 32;

        print_byte_array(sha_amounts, 32, "sha_amounts");
      }

      {
        //sha_scriptpubkeys
        uint8_t * script_buf = malloc(35*data->input_count);
        memzero(script_buf, 35*data->input_count);

        for (uint32_t i = 0, l = 0; i < data->input_count; i++) {
          memcpy(script_buf + l, input_Data[i].script_pub_key, input_Data[i].script_pub_key_len);
          l += input_Data[i].script_pub_key_len;
        }

        print_byte_array(script_buf, 35*data->input_count, "script_buf");
      
        sha256_Raw(script_buf, 35*data->input_count,sha_scriptpubkeys);
        memcpy(buffer+len, sha_scriptpubkeys, 32);
        len += 32;

        print_byte_array(sha_scriptpubkeys, 32, "sha_scriptpubkeys");
      }

      {
        //sha_sequences
        SHA256_CTX sha_256_ctx = {0};
        memzero(&sha_256_ctx, sizeof(sha_256_ctx));

        sha256_Init(&sha_256_ctx);

        for (uint32_t i = 0; i < data->input_count; i++) {
          sha256_Update(&sha_256_ctx, (uint8_t*)&input_Data[i].sequence, 4);
        }
      
        sha256_Final(&sha_256_ctx, sha_sequences);
        memcpy(buffer+len, sha_sequences, 32);
        len += 32;

        print_byte_array(sha_sequences, 32, "sha_sequences");
      }

    }

    if (!(is_none || is_single)) {
        //sha_outputs

        // calculate capacity
        uint32_t capacity = 0;
        uint32_t size = 0;
        while (size < data->output_count)
        {
          printf("count_1: %u", size);
          capacity +=8;
          capacity += output_data[size].script_pub_key_len;
          size++;
        }
        
        uint8_t * output_buf = malloc(capacity);
        memzero(output_buf, capacity);

        for (uint32_t i = 0, l = 0; i < data->output_count; i++) {
          printf("count: %u", i);
          memcpy( output_buf+l, (uint8_t*)&output_data[i].value, 8);
          l += 8;
          memcpy( output_buf+l, output_data[i].script_pub_key, output_data[i].script_pub_key_len);
          l += output_data[i].script_pub_key_len;
        }
        print_byte_array(output_buf, capacity, "out_buf");
      
        sha256_Raw(output_buf, capacity, sha_outputs);
        memcpy(buffer+len, sha_outputs, 32);
        len += 32;
      print_byte_array(sha_outputs, 32, "sha_outputs");
    }

    // spend_flag = (ext_flag*2)+annex_present
    //ext_flag = 0, should compute annex_present
    uint8_t spendbit = 0;
    memcpy(buffer+len, &spendbit,1);
    len += 1;

    if (is_anyone_can_pay) {
      memcpy(buffer+len, input_Data[txindex].prev_txn_hash, 32);
      len +=32;
      memcpy(buffer+len, (uint8_t*)&input_Data[txindex].prev_output_index, 4);
      len += 4;

      memcpy(buffer+len, input_Data[txindex].script_pub_key, input_Data[txindex].script_pub_key_len);
      len += 35;

      memcpy(buffer+len, (uint8_t*)&input_Data[txindex].sequence, 4);
      len += 4;
    }
    else {

      memcpy(buffer+len, (uint8_t*)&input_Data[txindex].prev_output_index, 4);
      len += 4;
    }

    if (annex) {
      // todo: implement support for annex
      assert(0);
    }

    if ((data->sighash & 3) == SIGHASH_SINGLE) {
            //sha_outputs
        SHA256_CTX sha_256_ctx = {0};
        memzero(&sha_256_ctx, sizeof(sha_256_ctx));

        sha256_Init(&sha_256_ctx);
        sha256_Update(&sha_256_ctx, (uint8_t*)&output_data[txindex].value, 8);
        sha256_Update(&sha_256_ctx,  output_data[txindex].script_pub_key, output_data[txindex].script_pub_key_len);
      
        sha256_Final(&sha_256_ctx, sha_single_output);
        
        memcpy(buffer+len, sha_outputs, 32);
        len += 32;
    }

    // TODO: BIP342 extension
    /*
    Length calculation from:
    https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#cite_note-14
    With extension from:
    https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki#signature-validation
    doesn't seem important
    uint8_t sig_msg_size =
      174 -
      (isAnyoneCanPay ? 49 : 0) -
      (isNone ? 32 : 0) +
      (annex ? 32 : 0) +
      (leafHash ? 37 : 0);
    */

    assert(len <= 207);
    print_byte_array(buffer, len, "msb buffer");
    //sha256_Raw(buffer, len, digest);

    //compute message hash
    uint8_t temp[272] = {0};
    memcpy(temp, TAP_SIG_HASH, sizeof(TAP_SIG_HASH)/sizeof(TAP_SIG_HASH[0]));
    memcpy(temp+(sizeof(TAP_SIG_HASH)/sizeof(TAP_SIG_HASH[0])), buffer, len);


    sha256_Raw(temp, len+(sizeof(TAP_SIG_HASH)/sizeof(TAP_SIG_HASH[0])), digest);

    print_byte_array(digest, 32, "digest");
    zkp_bip340_sign_digest(private_key, digest, signatures[txindex], NULL);
    print_byte_array(signatures[txindex], 64, "schnoor signature");

    memcpy(digest_out[txindex], digest, 32);
  }



}

