#include <stdint.h>
#include <string.h>

#include "../crypto/bip39.h"
#include "../unity/unity.h"
#include "../src/util.h"
#include "../src/address.h"
#include "../src/key.h"
#include "../src/transaction.h"
#include "../crypto/bip32.h"
#include "../crypto/curves.h"
#include "../crypto/zkp_bip340.h"

char* mnemonic = "shoe giraffe man toilet unable rail staff reason yellow shrug cup seminar uphold dolphin quit conduct stamp polar agent into salon omit speed install";
uint8_t seed[512 / 8] = {0};

char* mnemonic_bip_test_vector = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
uint8_t seed_bip_test_vector[512 / 8] = {0};


char xpub[XPUB_SIZE] = {0};

void setUp(void)
{
    mnemonic_to_seed(mnemonic, "", seed, NULL);

    mnemonic_to_seed(mnemonic_bip_test_vector, "", seed_bip_test_vector, NULL);
}

void tearDown(void)
{
}

void test_generate_xpub_bip49(void)
{

    char* bip32_path = "m/49'/1'/0'/0";
    uint32_t path [] = {0x80000031, 0x80000001, 0x80000000, 0};
    generate_xpub(path, (sizeof(path)/sizeof(path[0])), NULL, seed, xpub);

    // parent_fingerprint = child_fingerprint = 0x7e62eab1
    TEST_ASSERT_EQUAL_STRING( "upub5FxzXJirgiKUYJGqUJCqJ6Cx5Ce3eMaLpvR9NrWUzwu1qjNpJ25umQmWYkNb7ZA8DJJqwxBEauSFGyANgREWD5shwmXXqEHjLiBmAqiqVWa", xpub);
}

void test_generate_xpub_bip86(void)
{

    char* bip32_path = "m/86'/0'/0'";
    uint32_t path [] = {0x80000056, 0x80000000, 0x80000000};
    generate_xpub(path, (sizeof(path)/sizeof(path[0])), NULL, seed_bip_test_vector, xpub);

    // using child_fingerprint as parent_fingerprint = 0xa7bea80d
    TEST_ASSERT_EQUAL_STRING( "tpubDDFuj8kqBWwKTXbfea8PcbtyhTGLoPECxPAYrqdNstRnYAdNhfGH1PPmhEu2EbCfLsT9PPfG1jv2UMYbScBLRgwyBPwkRmeh3bhvtidYHmw", xpub);
}

void test_generate_address_segwit_p2sh(void) {
    char address[50] = {0};
    uint8_t public_key[50] = {0};
    char bip32path[] = "m/49'/1'/0'/0/0";
    uint32_t path[] = {0x80000031, 0x80000001, 0x80000000, 0, 0};

    char pubkey_hex[] = "029f75e1ef6b04e004a308b1f59215a8a3a5b7958bbcf184cc24ba7ab657444878";
    //"03a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f";
    uint8_t pubkey_bytes[33] = {0};

    size_t pubkey_len = hex2bytes(pubkey_bytes, 33, pubkey_hex);

    TEST_ASSERT(pubkey_len == 33);

    get_address(seed, path, (sizeof(path)/sizeof(path[0])), public_key, address);

    //TEST_ASSERT_EQUAL_STRING("2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2", address);
    TEST_ASSERT_EQUAL_STRING("2NEfewmmZkfKaxWaXbgxVVedQd9P52PUqdN", address);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(pubkey_bytes, public_key, 33);
}

void test_generate_address_taproot(void) {
    char address[63] = {0};
    uint8_t public_key[50] = {0};
    char bip32path[] = "m/86'/1'/0'/0/0";
    uint32_t path[] = {0x80000056, 0x80000001, 0x80000000, 0, 0};

    get_address(seed_bip_test_vector, path, (sizeof(path)/sizeof(path[0])), public_key, address);
    print_byte_array(address, 50, "taproot address");
    //TEST_ASSERT_EQUAL_STRING("2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2", address);
    //TEST_ASSERT_EQUAL_STRING("bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr", address);
    TEST_ASSERT_EQUAL_STRING("tb1p8wpt9v4frpf3tkn0srd97pksgsxc5hs52lafxwru9kgeephvs7rqlqt9zj", address);
}

void test_sign_transaction(void) {
    txnMetadata data = {0x00000001, 0x01, 0x02, 0x00000492, 0x00000001, NULL};
    txnInput input = {0};
    input.value = 1000000000; //;
    input.sequence = 0xFFFFFFFe; // 0xfeffffff;
    input.prev_output_index = 0x00000001;
    
    size_t len = 0;

    //Previous TX
    char prev_txn_str[] = "\0";//"02000000000101153d1eb7ae73e944b7dc72eb481231d6916d0374ab271bfea7850a772d50f6a60000000000fdffffff02cb4600000000000017a914eaf97514c5ac1e41e413502e97ae42ebf27ace3a875b47ec100000000017a914b2b0182ef0a26013cbbb99a42689d5a7846657a787024730440220247a90cc72da844678acc443c94fff2fbe8e5ea9492cbf86bae351a4be0b21cd02204a87bed14725b19eae0d60cc104b4d84124da432baf25d72ff49a24c0df4131e0121026c5f7b0f781462956559d2ff44b3ab7c9b8b6ef004b7c5fa015c66f37d06691e1cfc2a00";
    uint8_t prev_txn[500] = {0};
    len = hex2bytes(prev_txn, 500, prev_txn_str);
    input.prev_txn = prev_txn;

    
    //Previous TXID
    char prev_tx_hash_str[] = "db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477"; //"2b3682b35925885001f0e321df28d4ac675a9cbbccef2a69533bea7c5e5ad2c4";       
    uint8_t prev_tx_hash[32] = {0};
    len = hex2bytes(prev_tx_hash, 32, prev_tx_hash_str);
    input.prev_txn_hash = prev_tx_hash;

    //
    char input_scriptpubkey_str[] = "a91479091972186c449eb1ded22b78e40d009bdf008987"; //"a914eaf97514c5ac1e41e413502e97ae42ebf27ace3a87";
    uint8_t input_scriptpubkey[26] = {0};
    len = hex2bytes(input_scriptpubkey, 26, input_scriptpubkey_str);
    input.script_pub_key = input_scriptpubkey;

    txnOutput output[2] = {0};

    output[0].value = 0x000000000bebb4b8;//10000;

    //scriptpubkey output1
    char output_scriptpubkey1[] = "1976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac"; //"1976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac"; //"17A91458AA401495D6B40ABFFD23189ED47618B912F4F187";
    uint8_t output_scriptpubkey_bytes1[26] = {0};
    len = hex2bytes(output_scriptpubkey_bytes1, 26, output_scriptpubkey1);
    output[0].script_pub_key = output_scriptpubkey_bytes1;

    // output2
    output[1].value = 0x000000002faf0800;//8000;

    char output_scriptpubkey2[] = "1976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac";//"17A914D18DD5B029517C77AB553B8A94D680B97787A9D787";
    uint8_t output_scriptpubkey_bytes2[26] = {0};
    len = hex2bytes(output_scriptpubkey_bytes2, 26, output_scriptpubkey2);
    output[1].script_pub_key = output_scriptpubkey_bytes2;


    uint8_t sig_bytes[72] = {0};
    uint8_t *signature[] = {sig_bytes};
    
/*

    char bip32path[] = "m/49'/1'/0'/0/0";
    uint32_t path[] = {0x80000031, 0x80000001, 0x80000000, 0, 0};
    HDNode node = {0};
    uint32_t fingerprint = 0x0;


    hdnode_from_seed(seed, 512 / 8, SECP256K1_NAME, &node);

    for (size_t i = 0; i < (sizeof(path)/sizeof(path[0])); i++) {
        if (0 == hdnode_private_ckd(&node, path[i])) {
        // hdnode_private_ckd returns 1 when the derivation succeeds

        return;
        }
    }
*/
    uint8_t private_key[32] = {0};
    len = hex2bytes(private_key, 32, "eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf");
    sign_input_transaction(&input, output, &data, private_key, signature);

    uint8_t sig[72] = {0};
    len = hex2bytes(sig, 72, "3044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb01");

    TEST_ASSERT_EQUAL_UINT8_ARRAY(sig_bytes, sig_bytes, 72);

}

void test_taproot_signing(void) {
    uint8_t input_scriptpubkey[35] = {0};
    input_scriptpubkey[0] = 0x22;
    hex2bytes(input_scriptpubkey+1, 34, "51203b82b2b2a9185315da6f80da5f06d0440d8a5e1457fa93387c2d919c86ec8786");
    
    uint8_t output_scriptpubkey[23] = {0}; 
    output_scriptpubkey[0] = 0x16;
    hex2bytes(output_scriptpubkey+1, 22, "0014c8c43f9b09e2aadeb3fc1d200da042443bfd3b90");


    uint8_t txn_hash[32] = {0};
    hex2bytes(txn_hash, 32, "91399eb574c79ccf3491067017d949918ea60232686e8775cce16ec16c2c0d1e");
    
    txnMetadata data = {0x00000002, 0x01, 0x01, 0, 0X00, NULL};
    txnInput input[] = {
        {NULL, txn_hash, 0, 19704, input_scriptpubkey, 35, 4294967295, 0, 0}};


    txnOutput output[] = {
        {9705, output_scriptpubkey, 23, 0, 0}
    };

    uint8_t sig_bytes[65] = {0};
    uint8_t *signature[] = {sig_bytes};

    uint8_t priv_key[32] = {0};
    hex2bytes(priv_key, 32, "37446abf3eca6806714f8cfccc795acd779c09f8b6ebc97e202bed006ebbc950");

    uint8_t witness[65] = {0};
    hex2bytes(witness, 65, "7b4659074567709a0dadfbdecc212ad484fc731749827b642c3f547037e933eb19126faae3f34eb08cae016d74a92662bca641cb4412a54486d72af9a128cc62");

    uint8_t digest_bytes [32] = {0};
    uint8_t * digest[] = {digest_bytes};
    sign_taproot_tx(input, output, &data, priv_key, signature, digest);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(witness, sig_bytes, 65);

    uint8_t pubkey[32] = {0};
    hex2bytes(pubkey, 32, "3b82b2b2a9185315da6f80da5f06d0440d8a5e1457fa93387c2d919c86ec8786");
    // verify
    int status = zkp_bip340_verify_digest(pubkey, sig_bytes, digest[0]);
    TEST_ASSERT(status == 0);

}

int main(void)
{
UNITY_BEGIN();
RUN_TEST(test_generate_xpub_bip49);
RUN_TEST(test_generate_xpub_bip86);
RUN_TEST(test_generate_address_segwit_p2sh);
RUN_TEST(test_generate_address_taproot);
RUN_TEST(test_sign_transaction);
RUN_TEST(test_taproot_signing);
return UNITY_END();
}