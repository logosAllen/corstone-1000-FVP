/*
 * Copyright (c) 2023-2024, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __DPE_CERTIFICATE_H__
#define __DPE_CERTIFICATE_H__

#include <stddef.h>
#include <stdint.h>
#include "dpe_certificate_common.h"
#include "dpe_context_mngr.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DICE_MAX_ENCODED_PUBLIC_KEY_SIZE         (DPE_ATTEST_PUB_KEY_SIZE + 32)

/**
 * \brief Encodes and signs the certificate for a layer
 *
 * \param[in]  layer_ctx         Pointer to certificate layer context.
 * \param[out] cert_buf          Pointer to the output cert buffer.
 * \param[in]  cert_buf_size     Size of the output cert buffer.
 * \param[out] cert_actual_size  Actual size of the final certificate.
 * *
 * \return Returns error code of type dpe_error_t
 */
dpe_error_t encode_layer_certificate(const struct layer_context_t *layer_ctx,
                                     uint8_t *cert_buf,
                                     size_t cert_buf_size,
                                     size_t *cert_actual_size);

/**
 * \brief Stores signed certificate for a layer
 *
 * \param[in] layer_ctx  Pointer to current layer context.
 *
 * \return Returns error code of type dpe_error_t
 */
dpe_error_t store_layer_certificate(const struct layer_context_t *layer_ctx);

/**
 * \brief Returns the encoded certificate chain from leaf layer to the RoT layer.
 *
 * \param[in]  layer_ctx               Pointer to the current leaf layer context.
 * \param[out] cert_chain_buf          Pointer to certificate chain buffer.
 * \param[in]  cert_chain_buf_size     Size of certificate chain buffer.
 * \param[out] cert_chain_actual_size  Actual size of the chain.
 *
 * \return Returns error code of type dpe_error_t
 */
dpe_error_t get_certificate_chain(const struct layer_context_t *layer_ctx,
                                  uint8_t *cert_chain_buf,
                                  size_t cert_chain_buf_size,
                                  size_t *cert_chain_actual_size);

/**
 * \brief Returns the encoded CDI from raw value.
 *
 * \param[in]  cdi_attest_buf            Buffer holds the  attestation CDI data.
 * \param[in]  cdi_seal_buf              Buffer holds the  sealing CDI data.
 * \param[out] encoded_cdi_buf           Pointer to the output encoded CDI buffer.
 * \param[in]  encoded_cdi_buf_size      Size of the encoded CDI buffer.
 * \param[out] exported_cdi_actual_size  Actual size of the encoded CDI.
 *
 * \return Returns error code of type dpe_error_t
 */
dpe_error_t encode_cdi(const uint8_t cdi_attest_buf[DICE_CDI_SIZE],
                       const uint8_t cdi_seal_buf[DICE_CDI_SIZE],
                       uint8_t *encoded_cdi_buf,
                       size_t encoded_cdi_buf_size,
                       size_t *encoded_cdi_actual_size);

#ifdef __cplusplus
}
#endif

#endif /* __DPE_CERTIFICATE_H__ */
