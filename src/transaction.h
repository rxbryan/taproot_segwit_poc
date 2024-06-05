#ifndef __TRANSACTION_H__
#define __TRANSACTION_H__

#include <stdint.h>
#include <stdbool.h>


#define SIGHASH_ALL 0x01
#define SIGHASH_NONE 0x02
#define SIGHASH_SINGLE 0x03
#define SIGHASH_ANYONECANPAY 0x80

typedef uint8_t* bytes;

typedef struct txnInput {
  bytes prev_txn;
  bytes prev_txn_hash;

  uint32_t prev_output_index;
  uint64_t value;
  bytes script_pub_key;
  uint32_t script_pub_key_len;
  uint32_t sequence;

  uint32_t change_index;
  uint32_t address_index;
} txnInput;

typedef struct txnOutput {
  int64_t value;
  bytes script_pub_key;
  uint32_t script_pub_key_len;

  bool is_change;
  uint32_t changes_index;
} txnOutput;

typedef struct txnMetadata {
  // transaction output UTXO fields
  uint32_t version;
  uint32_t input_count;
  uint32_t output_count;
  uint32_t locktime;
  uint32_t sighash;
  uint8_t * annex;
}txnMetadata;

void sign_input_transaction(
                            txnInput *input_Data,
                            txnOutput *output_data,
                            txnMetadata *data,
                            uint8_t *private_key,
                            uint8_t** signatures);

void sign_taproot_tx(
                      txnInput *input_Data,
                      txnOutput *output_data,
                      txnMetadata *data,
                      uint8_t *private_key,
                      uint8_t** signatures,
                      uint32_t txindex);

#endif
