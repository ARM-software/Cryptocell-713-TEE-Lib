/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _CC_CH_CERT_H_
#define _CC_CH_CERT_H_

#include "cc_pal_types.h"

/*!
@file
@brief This file contains definitions and APIs that are used in the CryptoCell Chinese certification module.
*/

/*!
 @addtogroup ch_cert_defs
 @{
*/


/*! Definition of Chinese certification state. */
typedef uint32_t CCChCertState_t;
/*! Chinese certification is unsupported. */
#define CC_CH_CERT_STATE_NOT_SUPPORTED     0x0
/*! State definition of Chinese certification - error. */
#define CC_CH_CERT_STATE_ERROR             0x1
/*! Chinese certification is supported. */
#define CC_CH_CERT_STATE_SUPPORTED         0x2
/*! Chinese certification is approved. */
#define CC_CH_CERT_STATE_CRYPTO_APPROVED   0x4


 /*! Error messages for Chinese cipher tests */
typedef enum {
	/*! A success indication. */
        CC_TEE_CH_CERT_ERROR_OK = 0,
	/*! A general error. */
        CC_TEE_CH_CERT_ERROR_GENERAL,
	/*! SM4 ECB tests failure. */
        CC_TEE_CH_CERT_ERROR_SM4_ECB_PUT,
	/*! SM4 CBC tests failure. */
        CC_TEE_CH_CERT_ERROR_SM4_CBC_PUT,
	/*! SM4 CTR tests failure. */
        CC_TEE_CH_CERT_ERROR_SM4_CTR_PUT,
	/*! SM3 tests failure. */
        CC_TEE_CH_CERT_ERROR_SM3_PUT,
	/*! SM2 Sign/Verify tests failure. */
        CC_TEE_CH_CERT_ERROR_SM2_SIGN_PUT,
	/*! SM2 conditional tests failure. */
        CC_TEE_CH_CERT_ERROR_SM2_KEY_GEN_COND,
	/*! Reserved error code. */
        CC_TEE_CH_CERT_ERROR_RESERVE32B = INT32_MAX
}CCChCertError_t;

/*! Error messages for Chinese certification tests*/
typedef enum {
	/*! Identifies the system as failed the Chinese certifications tests.  */
        CC_TEE_CH_CERT_CRYPTO_USAGE_STATE_NON_APPROVED = 0,
	/*! Identifies the system as passed the Chinese certifications tests.  */
        CC_TEE_CH_CERT_CRYPTO_USAGE_STATE_APPROVED,
	/*! Reserved error code. */
        CC_TEE_CH_CERT_CRYPTO_USAGE_STATE_RESERVE32B = INT32_MAX
}CCChCertCryptoUsageState_t;



/*! Sets the Chinese certification state to approved. */
#define CC_CH_CERT_CRYPTO_USAGE_SET_APPROVED() \
        CC_ChCertCryptoUsageStateSet(CC_TEE_CH_CERT_CRYPTO_USAGE_STATE_APPROVED)
/*! Sets the Chinese certification state to not approved. */
#define CC_CH_CERT_CRYPTO_USAGE_SET_NON_APPROVED() \
        CC_ChCertCryptoUsageStateSet(CC_TEE_CH_CERT_CRYPTO_USAGE_STATE_NON_APPROVED)

/*!
@brief This function is used to get the current Chinese certification error of the Arm CryptoCell TEE library.

@return \c CC_OK on success,
@return A non-zero value from cc_chinese_cert_error.h on failure.
*/
CCError_t CC_ChCertErrorGet(
    /*! [out] The current Chinese certification error of the library. */
    CCChCertError_t *pChCertError
);


/*!
@brief This function is used to get the current state of the Chinese certification state (Chinese certification state set to ON or OFF) and zeroization state
of the Arm CryptoCell TEE library.

@return \c CC_OK on success,
@return A non-zero value from cc_chinese_cert_error.h on failure.
*/
CCError_t CC_ChCertStateGet(
    /*! [out] The Chinese certification State of the library (in accordance with the certification state definitions.)  */
    CCChCertState_t  *pChCertState
);

/*!
@brief This function is used to set the permission (approved/non-approved) of the crypto operations in the suspended state
of the Arm CryptoCell TEE library.

@return \c CC_OK on success,
@return A non-zero value from cc_chinese_cert_error.h on failure.
*/
CCError_t CC_ChCertCryptoUsageStateSet(
    /*! [in]  The state of the cryptographic operations. */
    CCChCertCryptoUsageState_t state
);
/*!
 @}
 */
#endif  // _CC_CH_CERT_H_
