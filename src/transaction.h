#ifndef __TRANSACTION_H__
#define __TRANSACTION_H__

#include <stdint.h>
#include <stdbool.h>

typedef uint8_t* bytes;

typedef struct txnInput {
  bytes prev_txn;
  bytes prev_txn_hash;

  uint32_t prev_output_index;
  uint64_t value;
  bytes script_pub_key;
  uint32_t sequence;

  uint32_t change_index;
  uint32_t address_index;
} txnInput;

typedef struct txnOutput {
  int64_t value;
  bytes script_pub_key;

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
}txnMetadata;

void sign_input_transaction(
                            txnInput *input_Data,
                            txnOutput *output_data,
                            txnMetadata *data,
                            uint8_t *private_key,
                            uint8_t** signatures);

#endif
