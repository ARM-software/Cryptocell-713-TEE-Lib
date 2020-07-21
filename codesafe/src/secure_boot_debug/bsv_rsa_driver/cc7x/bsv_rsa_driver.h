/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


#ifndef _BSV_RSA_DRIVER_H
#define _BSV_RSA_DRIVER_H

#ifdef __cplusplus
extern "C"
{
#endif

    /*!
@file
@brief This file contains the cryptographic ROM APIs of the Boot Services.

@defgroup cc_bsv_crypto_api CryptoCell Boot Services cryptographic ROM APIs
@{
@ingroup cc_bsv
     */

#include "cc_pal_types.h"
#include "cc_certificate_defs.h"
#include "rsa_bsv.h"



/*! Defines the buffer size to be masked with signature for PSS verify. */
#define  MASKED_DB_SIZE (BSV_CERT_RSA_KEY_SIZE_IN_BYTES - HASH_RESULT_SIZE_IN_BYTES - 1)

/*!
@brief This function Calculates the Np buffer of a given N

    The function supports 2k and 3K bit size of modulus, based on compile time define.


@return \c CC_OK on success.
@return A non-zero value from bsv_error.h on failure.
 */
uint32_t BsvRsaCalcNp(unsigned long hwBaseAddress, /*!< [in] The base address of the CryptoCell HW registers. */
                      uint32_t *pN,  /*!< [in] The modulus buffer LITTLE endian format. */
                      uint32_t *pNp);  /*!< [out] The barret tag buffer LITTLE endian format. */


/*!
@brief This function performs the exponent and modulus operation.
    Res_ptr = (Base_ptr ^ Exp) mod N_ptr. ( Exp = 0x10001 )

    The function supports 2k and 3K bit size of modulus, based on compile time define.
    There are no restriction on pInBuff location, however its size must be equal to BSV_RSA_KEY_SIZE_IN_BYTES and its
    value must be smaller than the modulus,


@return \c CC_OK on success.
@return A non-zero value from bsv_error.h on failure.
 */
uint32_t BsvRsaCalcExponent( unsigned long hwBaseAddress,/*!< [in] The base address of the CryptoCell HW registers. */
                             uint32_t *Base_ptr,  /*!< [in] The DataIn buffer to be calc expMod LITTLE endian format. */
                             uint32_t *N_ptr,  /*!< [in] The modulus buffer LITTLE endian format. */
                             uint32_t *Np_ptr, /*!< [in] The barret tag buffer LITTLE endian format. */
                             uint32_t *Res_ptr);  /*!< [in] The the result buffer LITTLE endian format. */


/*!
@brief This function performs PSS decode algorithm(PKCS#1 v2.1).
      The input data <pEncodedMsg> is placed as BE bytes arrays into 32-bit word buffers
      for alignment goal. Order of bytes in arrays is BE.

    The function supports 2k and 3K bit size of modulus, based on compile time define.

@return \c CC_OK on success.
@return A non-zero value from bsv_error.h on failure.
 */
CCError_t BsvRsaPssDecode(unsigned long hwBaseAddress,  /*!< [in] The base address of the CryptoCell HW registers. */
                          CCHashResult_t mHash,         /* [in] SHA256 hash of the message (32 bytes). */
                          uint8_t *pEncodedMsg,         /* [in] Pointer to PSS encoded message (EM). BE format
                                                          assumed Size is modulus size. */
                          int32_t *pVerifyStat,          /* [out] Pointer to validation status value, equalled to:
                                                            1 - if valid, 0 - if not valid. */
                          BsvPssDecodeWorkspace_t  *pWorkspace);        /*!< [in] Pointer to user allocated buffer for internal use. */


/*!
@brief This function performs PSS verify algorithm(PKCS#1 v2.1).
      NBuff, NpBuff and signature are assumed to be allocated on workspace (LE format)
      since we do not want to use lots of stack size.
      this function is used only internally for certificate verification

@return \c CC_OK on success.
@return A non-zero value from bsv_error.h on failure.
 */
CCError_t BsvRsaPssVerify(unsigned long hwBaseAddress,/*!< [in] The base address of the CryptoCell HW registers. */
                          uint32_t *NBuff,       /*!< [in] The modulus buffer LITTLE endian format. */
                          uint32_t *NpBuff,     /*!< [in] The barret tag buffer LITTLE endian format. */
                          uint32_t *signature, /* [in] Pointer to PSS signature to be verified. */
                          CCHashResult_t hashedData,/* [in] SHA256 hash of the message (32 bytes). */
                          uint32_t *pWorkSpace,     /*!< [in] Pointer to user allocated buffer for internal use. */
                          size_t workspaceSize);    /*!< [in] size of workspace buffer in Bytes, must be at-least
                                                       sizeof(BsvPssVerifyIntWorkspace_t). */


#ifdef __cplusplus
}
#endif

#endif  /* _BSV_RSA_DRIVER_H */

/**
@}
 */

