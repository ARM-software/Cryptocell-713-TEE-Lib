/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


#ifndef _BSV_SBRT_CRYPTO_INT_API_H
#define _BSV_SBRT_CRYPTO_INT_API_H

#ifdef __cplusplus
extern "C"
{
#endif

/*!
@file
@brief This file contains internal cryptographic ROM APIs of the Boot Services.

@defgroup cc_sbrt_crypto_api CryptoCell Boot Services cryptographic ROM APIs
@{
@ingroup cc_sbrt
*/


#include "cc_pal_types.h"
#include "cc_sec_defs.h"
#include "cc_sbrt_crypto_int_defs.h"
#include "cc_address_defs.h"
#include "dma_buffer.h"
#include "cc_boot_defs.h"

/* Life cycle state definitions. */
#define CC_RT_CHIP_MANUFACTURE_LCS        0x0 /*!< The CM life-cycle state (LCS) value. */
#define CC_RT_DEVICE_MANUFACTURE_LCS      0x1 /*!< The DM life-cycle state (LCS) value. */
#define CC_RT_SECURE_LCS                  0x5 /*!< The Secure life-cycle state (LCS) value. */
#define CC_RT_RMA_LCS                     0x7 /*!< The RMA life-cycle state (LCS) value. */

#define CC_BSV_CHIP_MANUFACTURE_LCS       CC_RT_CHIP_MANUFACTURE_LCS
#define CC_BSV_DEVICE_MANUFACTURE_LCS     CC_RT_DEVICE_MANUFACTURE_LCS
#define CC_BSV_SECURE_LCS                 CC_RT_SECURE_LCS
#define CC_BSV_RMA_LCS                    CC_RT_RMA_LCS

/*----------------------------
      PUBLIC FUNCTIONS
-----------------------------------*/

/*!
 @brief This function initializes the AES and HASH HW engines to calculate SHA256 digest of an image with decryption base on AES-CTR.
 It sets setup descriptors, and returns after HW sequence completion is received.
 @return \c CC_OK on success.
 @return A non-zero value from bsv_error.h on failure.
 */
CCError_t SbrtCryptoImageInit(unsigned long hwBaseAddress,
                              CCSbrtFlow_t flow,
                              CCBsvKeyType_t keyType,
                              uint8_t *pNonce);

/*!
 @brief This function processes the AES and HASH HW engines to calculate SHA256 digest of an image with decryption base on AES-CTR.
 It sets flow descriptor, and can return without waiting to HW completion.
 @return \c CC_OK on success.
 @return A non-zero value from bsv_error.h on failure.
 */
CCError_t SbrtCryptoImageProcess(CCSbrtFlow_t flow,
                                 CCSbrtCompletionMode_t completionMode,
                                 DmaBuffer_s *pDataIn,
                                 DmaBuffer_s *pDataOut);

/*!
 @brief This function Locks the symmetric cryptography mutex
 */
void SbrtCryptoImageLock(void);

/*!
 @brief This function Unlocks the symmetric cryptography mutex
 */
void SbrtCryptoImageUnlock(void);

/*!
 @brief This function finilizes the HASH HW engine after calculate SHA256 digest of an image with decryption base on AES-CTR.
 It sets finilize descriptors, and returns after HW sequence completion is received.
 @return \c CC_OK on success.
 @return A non-zero value from bsv_error.h on failure.
 */
CCError_t SbrtCryptoImageFinish(CCHashResult_t hashResult);

CCError_t SbrtSHA256(unsigned long hwBaseAddress,
                     uint8_t *pDataIn,
                     size_t dataSize,
                     CCHashResult_t hashBuff);

CCError_t SbrtRsaPssVerify(unsigned long hwBaseAddress,
                           uint32_t *NBuff,
                           uint32_t *NpBuff,
                           uint32_t *signature,
                           CCHashResult_t hashedData,
                           uint32_t *pWorkSpace,
                           size_t workspaceSize);

#ifdef __cplusplus
}
#endif

#endif /* _BSV_SBRT_CRYPTO_INT_API_H */

/**
@}
 */

