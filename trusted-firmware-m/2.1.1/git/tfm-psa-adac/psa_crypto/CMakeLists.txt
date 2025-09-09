#-------------------------------------------------------------------------------
# Copyright (c) 2020-2023, Arm Limited. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

add_library(psa_adac_psa_crypto STATIC)

target_sources(psa_adac_psa_crypto
    PRIVATE
        adac_crypto_psa.c
        adac_crypto_psa_hash.c
        adac_crypto_psa_mac.c
        adac_crypto_psa_pk.c
)

target_link_libraries(psa_adac_psa_crypto
    PRIVATE
        psa_adac_config
        tfm_sprt
)

target_link_libraries(trusted-firmware-m-psa-adac
    PRIVATE
        psa_adac_psa_crypto
)
