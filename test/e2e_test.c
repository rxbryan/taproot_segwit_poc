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
    char address[50] = {0};
    uint8_t public_key[50] = {0};
    char bip32path[] = "m/86'/0'/0'/0/0";
    uint32_t path[] = {0x80000056, 0x80000000, 0x80000000, 0, 0};

    get_address(seed_bip_test_vector, path, (sizeof(path)/sizeof(path[0])), public_key, address);

    //TEST_ASSERT_EQUAL_STRING("2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2", address);
    TEST_ASSERT_EQUAL_STRING("bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr", address);
}

void test_sign_transaction(void) {
    txnMetadata data = {0x00000001, 0x01, 0x02, 0x00000492/*0x00000000*/, 0x00000001, NULL};
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
    uint8_t spk1[35] = {0};
    spk1[0] = 0x22;
    hex2bytes(spk1+1, 34, "512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343");
    uint8_t spk2[35] = {0};
    spk2[0] = 0x22;
    hex2bytes(spk2+1, 34, "5120147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3");
    uint8_t spk3[26] = {0};
    spk3[0] = 0x19;
    hex2bytes(spk3+1, 25, "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac");
    uint8_t spk4[35] = {0};
    spk4[0] = 0x22;
    hex2bytes(spk4+1, 34,"5120e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e");
    uint8_t spk5[35] = {0};
    spk5[0] = 0x22;
    hex2bytes(spk5+1, 34, "512091b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc21783605");
    uint8_t spk6[23] = {0};
    spk6[0] = 0x16;
    hex2bytes(spk6+1, 22, "00147dd65592d0ab2fe0d0257d571abf032cd9db93dc");
    uint8_t spk7[35] = {0};
    spk7[0] = 0x22;
    hex2bytes(spk7+1, 34, "512075169f4001aa68f15bbed28b218df1d0a62cbbcf1188c6665110c293c907b831");
    uint8_t spk8[35] = {0};
    spk8[0] = 0x22;
    hex2bytes(spk8+1, 34, "5120712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b17df5");
    uint8_t spk9[35] = {0};
    spk9[0] = 0x22;
    hex2bytes(spk9+1, 34, "512077e30a5522dd9f894c3f8b8bd4c4b2cf82ca7da8a3ea6a239655c39c050ab220");

    uint8_t out_spk1[26] = {0};
    out_spk1[0] = 0x19;
    hex2bytes(out_spk1+1, 25, "76a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac");

    uint8_t out_spk2[33] = {0};
    out_spk2[0] = 0x20;
    hex2bytes(out_spk2+1, 32, "ac9a87f5594be208f8532db38cff670c450ed2fea8fcdefcc9a663f78bab962b");


    uint8_t txn_hash1[32] = {0};
    hex2bytes(txn_hash1, 32, "d72ec0fb6f68ad385a94182d9bab3b85f6c47a4ef8755f5b953611f5b333e4c9");
    uint8_t txn_hash2[32] = {0};
    hex2bytes(txn_hash2, 32, "7d7bac5bb73139ca2e0d464f4d2abca86fed6f21371e7215d74457b9d6fadd99");
    uint8_t txn_hash3[32] = {0};
    hex2bytes(txn_hash3, 32, "8f1e5f388334338629825c2de8ca3163b60e28cd754471069d757245914a8124");
    uint8_t txn_hash4[32] = {0};
    hex2bytes(txn_hash4, 32,"0f861908aa363bc01b267ac3d6a2837beeada238ce7e3401df0a48a36d4058b3");
    uint8_t txn_hash5[32] = {0};
    hex2bytes(txn_hash5, 32, "aa2520db6f8dcc2deef02020fabb7b64d129462ae5b5dfc3a525ee21930eabc6");
    uint8_t txn_hash6[32] = {0};
    hex2bytes(txn_hash6, 32, "591694db6cf6aa69e82bebd2f2aa9217a8bcef93141285392a3a44d623ca0d05");
    uint8_t txn_hash7[32] = {0};
    hex2bytes(txn_hash7, 32, "6e469b77b3880cc923bc072a3a4eadc0de367babb3228f8435b1bbd1d5f5c449");
    uint8_t txn_hash8[32] = {0};
    hex2bytes(txn_hash8, 32, "9eaab6e8c6d96e67916e3a29a42e6569bbb796b46b776a237ae47faefd4daefb");
    uint8_t txn_hash9[32] = {0};
    hex2bytes(txn_hash9, 32, "7a87bea662d30c0964c41d524c665b9a697627b0c111408638d150a81a8ba21f");


    txnMetadata data = {0x00000002, 0x09, 0x02, 500000000, 3, NULL};
    txnInput input[9] = {
        {NULL, txn_hash1, 1, 420000000, spk1, 35, 0, 0, 0},
        {NULL, txn_hash2, 0, 462000000, spk2, 35, 4294967295, 0, 0},
        {NULL, txn_hash3, 0, 294000000, spk3, 26, 4294967295, 0, 0},
        {NULL, txn_hash4, 1, 504000000, spk4, 35, 4294967294, 0, 0},
        {NULL, txn_hash5, 0, 630000000, spk5, 35, 4294967294, 0, 0},
        {NULL, txn_hash6, 0, 378000000, spk6, 22, 0, 0, 0},
        {NULL, txn_hash7, 1, 672000000, spk7, 35, 0, 0, 0},
        {NULL, txn_hash8, 0, 546000000, spk8, 35, 4294967295, 0, 0},
        {NULL, txn_hash9, 1, 588000000, spk9, 35, 4294967295, 0, 0}};


    txnOutput output[2] = {
        {1000000000, out_spk1, 26, 0, 0},
        {3410000000, out_spk2, 33, 0, 0}
    };

    uint8_t sig_bytes[65] = {0};
    uint8_t *signature[] = {sig_bytes};

    uint8_t priv_key[32] = {0};
    hex2bytes(priv_key, 32, "2405b971772ad26915c8dcdf10f238753a9b837e5f8e6a86fd7c0cce5b7296d9");

    uint8_t witness[32] = {0};
    hex2bytes(witness, 65, "ed7c1647cb97379e76892be0cacff57ec4a7102aa24296ca39af7541246d8ff14d38958d4cc1e2e478e4d4a764bbfd835b16d4e314b72937b29833060b87276c03");

    sign_taproot_tx(input, output, &data, priv_key, signature, 0);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(witness, sig_bytes, 65);

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