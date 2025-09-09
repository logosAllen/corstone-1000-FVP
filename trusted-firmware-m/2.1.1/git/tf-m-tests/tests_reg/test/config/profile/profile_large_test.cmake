#-------------------------------------------------------------------------------
# Copyright (c) 2021-2022, Arm Limited. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

################################## Tests #######################################

set(TFM_CRYPTO_TEST_ALG_CBC                     ON      CACHE BOOL      "Test CBC cryptography mode")
set(TFM_CRYPTO_TEST_ALG_CFB                     OFF     CACHE BOOL      "Test CFB cryptography mode")
set(TFM_CRYPTO_TEST_ALG_ECB                     OFF     CACHE BOOL      "Test ECB cryptography mode")
set(TFM_CRYPTO_TEST_ALG_CTR                     ON      CACHE BOOL      "Test CTR cryptography mode")
set(TFM_CRYPTO_TEST_ALG_OFB                     OFF     CACHE BOOL      "Test OFB cryptography mode")
set(TFM_CRYPTO_TEST_ALG_GCM                     ON      CACHE BOOL      "Test GCM cryptography mode")
set(TFM_CRYPTO_TEST_ALG_SHA_224                 OFF     CACHE BOOL      "Test SHA-224 cryptography algorithm")
set(TFM_CRYPTO_TEST_ALG_SHA_384                 OFF     CACHE BOOL      "Test SHA-384 cryptography algorithm")
if (NOT ${CC312_LEGACY_DRIVER_API_ENABLED})
    set(TFM_CRYPTO_TEST_ALG_SHA_512             OFF     CACHE BOOL      "Test SHA-512 cryptography algorithm")
else()
    set(TFM_CRYPTO_TEST_ALG_SHA_512             ON      CACHE BOOL      "Test SHA-512 cryptography algorithm")
endif()
set(TFM_CRYPTO_TEST_HKDF                        ON      CACHE BOOL      "Test the HKDF key derivation algorithm")
set(TFM_CRYPTO_TEST_ECDH                        ON      CACHE BOOL      "Test the ECDH key agreement algorithm")
set(TFM_CRYPTO_TEST_CHACHA20                    OFF     CACHE BOOL      "Test the ChaCha20 stream cipher")
set(TFM_CRYPTO_TEST_ALG_CHACHA20_POLY1305       OFF     CACHE BOOL      "Test ChaCha20-Poly1305 AEAD algorithm")
set(TFM_CRYPTO_TEST_ALG_RSASSA_PSS_VERIFICATION OFF     CACHE BOOL      "Test RSASSA-PSS signature verification algorithm")
set(TFM_CRYPTO_TEST_UNSUPPORTED_ALG             ON      CACHE BOOL      "Test unsupported algorithm in hash, MAC")
set(TFM_CRYPTO_TEST_ALG_DETERMINISTIC_ECDSA     ON      CACHE BOOL      "Test Deterministic ECDSA signing/verification algorithm")
set(TFM_CRYPTO_TEST_ALG_ECDSA                   ON      CACHE BOOL      "Test ECDSA signing/verification algorithm")
