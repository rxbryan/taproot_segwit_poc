#include <stdint.h>
#include <string.h>

#include "../crypto/bip39.h"
#include "../unity/unity.h"
#include "../src/util.h"
#include "../src/address.h"
#include "../src/key.h"

#include "../crypto/curves.h"

char* mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
uint8_t seed[512 / 8] = {0};
char xpub[XPUB_SIZE] = {0};

void setUp(void)
{
    mnemonic_to_seed(mnemonic, "", seed, NULL);
}

void tearDown(void)
{
}

void test_generate_xpub(void)
{

    char* bip32_path = "m/49'/1'/0'";
    uint32_t path [] = {0x80000031, 0x80000001, 0x80000000};
    generate_xpub(path, (sizeof(path)/sizeof(path[0])), NULL, seed, xpub);

    TEST_ASSERT_EQUAL_STRING( "upub5DEPBmf18ejTHKYVb1ZZhE8j5Auc3ksVUMtQQS2o25dpDKyH6YAYjpmrYMPmuxEuXNsvAynGWPJQux6uivnyi7ZF9UbQXx3B4j27bmg37v9", xpub);
}

void test_generate_address_segwit_p2sh(void) {
    char address[50] = {0};
    uint8_t public_key[50] = {0};
    char bip32path[] = "m/49'/1'/0'/0/0";
    uint32_t path[] = {0x80000031, 0x80000001, 0x80000000, 0, 0};

    char pubkey_hex[] = "03a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f";
    uint8_t pubkey_bytes[33] = {0};

    size_t pubkey_len = hex2bytes(pubkey_bytes, 33, pubkey_hex);

    TEST_ASSERT(pubkey_len == 33);

    get_address(seed, path, (sizeof(path)/sizeof(path[0])), public_key, address);

    TEST_ASSERT_EQUAL_STRING("2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2", address);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(pubkey_bytes, public_key, 33);
}

int main(void)
{
UNITY_BEGIN();
RUN_TEST(test_generate_xpub);
RUN_TEST(test_generate_address_segwit_p2sh);
return UNITY_END();
}