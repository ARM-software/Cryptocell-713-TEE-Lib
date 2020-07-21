/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _CC_FIPS_H_
#define _CC_FIPS_H_

#include "cc_pal_types.h"

/*!
@file
@brief This file contains definitions and APIs that are used in the CryptoCell FIPS module.
*/

/*!
 @addtogroup cc_fips
 @{
 */
/*! FIPS state definition. */
typedef uint32_t CCFipsState_t;

/*! Definition of FIPS not supported state.*/
#define CC_FIPS_STATE_NOT_SUPPORTED     0x0
/*! Definition of FIPS error state.*/
#define CC_FIPS_STATE_ERROR             0x1
/*! Definition of FIPS supported state.*/
#define CC_FIPS_STATE_SUPPORTED         0x2
/*! Definition of FIPS suspended state.*/
#define CC_FIPS_STATE_SUSPENDED         0x4
/*! Definition of FIPS approved state.*/
#define CC_FIPS_STATE_CRYPTO_APPROVED   0x8

/*! FIPS error messages*/
typedef enum {
	/*! Success.*/
        CC_TEE_FIPS_ERROR_OK = 0,
	/*! FIPS general error. */
        CC_TEE_FIPS_ERROR_GENERAL,
	/*! FIPS error returned from REE. */
        CC_TEE_FIPS_ERROR_FROM_REE,
	/*! Aes ecb power up tests returned error. */
        CC_TEE_FIPS_ERROR_AES_ECB_PUT,
	/*! Aes cbc power up tests returned error. */
        CC_TEE_FIPS_ERROR_AES_CBC_PUT,
	/*! Aes ofb power up tests returned error. */
        CC_TEE_FIPS_ERROR_AES_OFB_PUT,
	/*! Aes ctr power up tests returned error. */
        CC_TEE_FIPS_ERROR_AES_CTR_PUT,
	/*! Aes cbc cts power up tests returned error. */
        CC_TEE_FIPS_ERROR_AES_CBC_CTS_PUT,
	/*! Aes cbc mac power up tests returned error. */
        CC_TEE_FIPS_ERROR_AES_CBC_MAC_PUT,
	/*! Aes cmac power up tests returned error. */
        CC_TEE_FIPS_ERROR_AES_CMAC_PUT,
	/*! Aes ccm power up tests returned error. */
        CC_TEE_FIPS_ERROR_AESCCM_PUT,
	/*! Aes xts power up tests returned error. */
        CC_TEE_FIPS_ERROR_AES_XTS_PUT,
	/*! Des ecb power up tests returned error. */
        CC_TEE_FIPS_ERROR_DES_ECB_PUT,
	/*! Des cbc power up tests returned error. */
        CC_TEE_FIPS_ERROR_DES_CBC_PUT,
	/*! Hash sha1 power up tests returned error. */
        CC_TEE_FIPS_ERROR_SHA1_PUT,
	/*! Hash sha256 power up tests returned error. */
        CC_TEE_FIPS_ERROR_SHA256_PUT,
	/*! Hash sha512 power up tests returned error. */
        CC_TEE_FIPS_ERROR_SHA512_PUT,
	/*! Hmac sha256 power up tests returned error. */
        CC_TEE_FIPS_ERROR_HMAC_SHA256_PUT,
	/*! Rsa encrypt power up tests returned error. */
        CC_TEE_FIPS_ERROR_RSA_ENC_PUT,
	/*! Rsa decrypt power up tests returned error. */
        CC_TEE_FIPS_ERROR_RSA_DEC_PUT,
	/*! Rsa sign power up tests returned error. */
        CC_TEE_FIPS_ERROR_RSA_SIGN_PUT,
	/*! Rsa verify power up tests returned error. */
        CC_TEE_FIPS_ERROR_RSA_VERIFY_PUT,
	/*! Ecc sign power up tests returned error. */
        CC_TEE_FIPS_ERROR_ECDSA_SIGN_PUT,
	/*! Ecc verify power up tests returned error. */
        CC_TEE_FIPS_ERROR_ECDSA_VERIFY_PUT,
	/*! Dh power up tests returned error. */
        CC_TEE_FIPS_ERROR_DH_PUT,
	/*! Ecdh power up tests returned error. */
        CC_TEE_FIPS_ERROR_ECDH_PUT,
	/*! Prng power up tests returned error. */
        CC_TEE_FIPS_ERROR_PRNG_PUT,
	/*! Rsa encrypt conditional tests returned error. */
        CC_TEE_FIPS_ERROR_RSA_ENC_COND,
	/*! Rsa decrypt conditional tests returned error. */
        CC_TEE_FIPS_ERROR_RSA_DEC_COND,
	/*! Ecc sign conditional tests returned error. */
        CC_TEE_FIPS_ERROR_ECDSA_SIGN_COND,
	/*! Ecc verify conditional tests returned error. */
        CC_TEE_FIPS_ERROR_ECDSA_VERIFY_COND,
	/*! Prng continuous tests returned error. */
        CC_TEE_FIPS_ERROR_PRNG_CONT,
	/*! Aes gcm power up tests returned error. */
        CC_TEE_FIPS_ERROR_AESGCM_PUT,
	/*! Reserved. */
        CC_TEE_FIPS_ERROR_RESERVE32B = INT32_MAX
} CCFipsError_t;

/*! FIPS TEE status */
typedef enum {
        /*! FIPS REE status is OK. */
        CC_TEE_FIPS_REE_STATUS_OK = 0,
        /*! FIPS REE status is error. */
        CC_TEE_FIPS_REE_STATUS_ERROR,
        /*! Reserved. */
        CC_TEE_FIPS_REE_STATUS_RESERVE32B = INT32_MAX
} CCFipsReeStatus_t;

/*! FIPS cryptographic usage status */
typedef enum {
        /*! FIPS TEE state is not approved. */
        CC_TEE_FIPS_CRYPTO_USAGE_STATE_NON_APPROVED = 0,
        /*! FIPS TEE state is approved. */
        CC_TEE_FIPS_CRYPTO_USAGE_STATE_APPROVED,
        /*! Reserved. */
        CC_TEE_FIPS_CRYPTO_USAGE_STATE_RESERVE32B = INT32_MAX
} CCFipsCryptoUsageState_t;

/*! Set FIPS state to 'approved' state. */
#define CC_FIPS_CRYPTO_USAGE_SET_APPROVED() \
        CC_FipsCryptoUsageStateSet(CC_TEE_FIPS_CRYPTO_USAGE_STATE_APPROVED)
/*! Set FIPS state to 'non approved' state. */
#define CC_FIPS_CRYPTO_USAGE_SET_NON_APPROVED() \
        CC_FipsCryptoUsageStateSet(CC_TEE_FIPS_CRYPTO_USAGE_STATE_NON_APPROVED)

/*!
@brief This function is used to get the current FIPS error of the Arm CryptoCell TEE library.

@return \c CC_OK on success.
@return A non-zero value from cc_fips_error.h on failure.
*/
CCError_t CC_FipsErrorGet(
                CCFipsError_t *pFipsError  /*!< [out] The current FIPS error of the library. */
);


/*!
@brief This function is used to get the current FIPS state (FIPS certification state set to \c ON or \c OFF) and zeroization state
of the Arm CryptoCell TEE library.

@return \c CC_OK on success.
@return A non-zero value from cc_fips_error.h on failure.
*/
CCError_t CC_FipsStateGet(CCFipsState_t  *pFipsState, /*!< [out] The FIPS state of the library. */
			  bool  *pIsDeviceZeroized     /*!< [out] Is device was zeroized. */); /* Should this be "This device was zeroized?"*/

/*!
@brief Sets the permission (approved/non-approved) of the cryptographic operations in the suspended state
of the Arm CryptoCell TEE library.

@return \c CC_OK on success.
@return A non-zero value from cc_fips_error.h on failure.
*/
CCError_t CC_FipsCryptoUsageStateSet(
                CCFipsCryptoUsageState_t state  /*!< [in]  The state of the cryptographic operations. */
);

/*!
@brief This function is used to handle the interrupt that is issued when the CryptoCell-713 REE is updating its FIPS status.

\note This function should be integrated into the Interrupt Handler Routine of the operating system of the user.
      In the example implementation, this function is called through a - \ref CC_InterruptHandler.

@return \c CC_OK on success,
@return A non-zero value from cc_fips_error.h on failure.
*/
CCError_t CC_FipsIrqHandle(void);
/*!
 @}
 */
#endif  // _CC_FIPS_H_
