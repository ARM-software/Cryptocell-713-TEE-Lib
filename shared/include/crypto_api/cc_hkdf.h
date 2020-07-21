/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _CC_HKDF_H
#define _CC_HKDF_H


#include "cc_pal_types.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*!
@file
@brief This file defines the API that supports HMAC Key derivation function as
       defined by RFC5869.
 */
 /*!
 @addtogroup cc_hkdf
 @{
*/

/************************ Defines ******************************/
/*! HKDF maximal key size in words. */
#define CC_HKDF_MAX_HASH_KEY_SIZE_IN_BYTES        512

/*! HKDF maximal HASH digest size in bytes. */
#define CC_HKDF_MAX_HASH_DIGEST_SIZE_IN_BYTES     \
                                            CC_HASH_SHA512_DIGEST_SIZE_IN_BYTES
/*! HKDF maximal HASH digest size in words. */
#define CC_HKDF_MAX_HASH_DIGEST_SIZE_IN_WORDS     \
                          CC_HKDF_MAX_HASH_DIGEST_SIZE_IN_BYTES/sizeof(uint32_t)


/************************ Enums ********************************/
/*! Enum defining HKDF HASH available modes. */
typedef enum
{
    /*! SHA1 mode. */
    CC_HKDF_HASH_SHA1_mode    = 0,
    /*! SHA224 mode. */
    CC_HKDF_HASH_SHA224_mode  = 1,
    /*! SHA256 mode. */
    CC_HKDF_HASH_SHA256_mode  = 2,
    /*! SHA384 mode. */
    CC_HKDF_HASH_SHA384_mode  = 3,
    /*! SHA512 mode. */
    CC_HKDF_HASH_SHA512_mode  = 4,
    /*! Maximal number of HASH modes. */
    CC_HKDF_HASH_NumOfModes,
    /*! Reserved */
    CC_HKDF_HASH_OpModeLast    = 0x7FFFFFFF,
}CCHkdfHashOpMode_t;


/**
 * @brief CC_HkdfKeyDerivFunc performs the HMAC-based key derivation,
 *        according to RFC5869

@return \c CC_OK on success.
@return A non-zero value on failure as defined cc_kdf_error.h,
        cc_hash_error or cc_hmac_error.h
*/
CEXPORT_C CCError_t  CC_HkdfKeyDerivFunc(
                        CCHkdfHashOpMode_t      hkdf_hash_mode,/*!< [in]   The HKDF identifier of hash function to be used. */
                        uint8_t*                salt_ptr,      /*!< [in]   A pointer to a non secret random value. can be NULL. */
                        size_t	                saltLen,       /*!< [in]   The size of the salt_ptr. */
                        uint8_t*                ikm_ptr,       /*!< [in]   A pointer to a input key message. */
                        size_t                  ikm_len,       /*!< [in]   The size of the input key message */
                        uint8_t*                info_ptr,      /*!< [in]   A pointer to an optional context and application specific information. can be NULL */
                        size_t                  info_len,      /*!< [in]   The size of the information. */
                        uint8_t*                okm,           /*!< [out]  A pointer to a output key material. */
                        size_t                  okm_len,       /*!< [in]   The size of the output key material. */
                        CCBool                  is_strong_key  /*!< [in]   if TRUE , then no need to perform the extraction phase. */
                        );

#ifdef __cplusplus
}
#endif
/*!
 @}
*/
#endif

