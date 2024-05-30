cmake_minimum_required(VERSION 3.10)  # Minimum required CMake version
project(crypto C)                  # Project name and language

# Set compiler flags (optional)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -g")

# Include header directories (optional)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})  # Assuming header files are in the "include" directory

# Define build options based on the Makefile settings
set(USE_VALGRIND  ${VALGRIND})
set(USE_ETHEREUM 0)
set(USE_GRAPHENE 0)
set(USE_KECCAK    1)
set(USE_MONERO    0)
set(USE_NEM       1)
set(USE_CARDANO  0)

# Find OpenSSL library (if needed)
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIRS})

# Define source files
set(SRCS
    bignum.c
    ecdsa.c
    curves.c
    secp256k1.c
    nist256p1.c
    rand.c
    hmac.c
    bip32.c
    bip39.c
    bip39_english.c
    pbkdf2.c
    base58.c
    base32.c
    address.c
    script.c
    ripemd160.c
    sha2.c
    sha3.c
    hasher.c
    aes/aescrypt.c
    aes/aeskey.c
    aes/aestab.c
    aes/aes_modes.c
    ed25519-donna/curve25519-donna-32bit.c
    ed25519-donna/curve25519-donna-helpers.c
    ed25519-donna/modm-donna-32bit.c
    ed25519-donna/ed25519-donna-basepoint-table.c
    ed25519-donna/ed25519-donna-32bit-tables.c
    ed25519-donna/ed25519-donna-impl-base.c
    ed25519-donna/ed25519.c
    ed25519-donna/curve25519-donna-scalarmult-base.c
    ed25519-donna/ed25519-sha3.c
    ed25519-donna/ed25519-keccak.c
    blake256.c
    blake2b.c
    blake2s.c
    groestl.c
    nem.c
    segwit_addr.c
    memzero.c
    hmac_drbg.c
    rfc6979.c
    zkp_bip340.c
    zkp_context.c
    
)


# Add source files
add_library(crypto SHARED ${SRCS})
target_compile_definitions( crypto PUBLIC USE_INSECURE_PRNG)
target_link_libraries(crypto secp256k1)

# Set target build options
target_compile_definitions(crypto PRIVATE
    USE_VALGRIND=${USE_VALGRIND}
    USE_ETHEREUM=${USE_ETHEREUM}
    USE_GRAPHENE=${USE_GRAPHENE}
    USE_KECCAK=${USE_KECCAK}
    USE_MONERO=${USE_MONERO}
    USE_NEM=${USE_NEM}
    USE_CARDANO=${USE_CARDANO}
)

# Link with OpenSSL library (if needed)
#target_link_libraries(crypto PRIVATE OpenSSL::OpenSSL)

#export(TARGETS my_library  FILE ${PROJECT_BINARY_DIR}/cmake/my_library/my_library-export.cmake)


# Set position-independent code (-fPIC) for shared library
set_target_properties(crypto PROPERTIES POSITION_INDEPENDENT_CODE ON)

# Clean rule (optional)
#add_custom_target(clean COMMAND rm -f *.o aes/*.o ed25519-donna/*.o crypto.so)

