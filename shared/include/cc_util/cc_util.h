/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef  _CC_UTIL_H
#define  _CC_UTIL_H


/*!
@file
@brief This file contains CryptoCell utility functions and definitions.
*/

/*!
@addtogroup cc_util_functions
@{
    */

#ifdef __cplusplus
extern "C"
{
#endif

#include "cc_util_defs.h"
#include "cc_util_error.h"
#include "cc_pal_types.h"
#include "cc_rnd_common.h"
#include "cc_ecpki_types.h"
#include "cc_cert_ctx.h"
/******************************************************************************
*                        	DEFINITIONS
******************************************************************************/


/*****************************************/
/* Endorsement key derivation definitions*/
/*****************************************/
/*! Endorsement key domain ID. */
typedef enum {
	CC_UTIL_EK_DomainID_secp256k1 = 1, /*!< secp256k1 domain definition. */
	CC_UTIL_EK_DomainID_secp256r1 = 2, /*!< secp256r1 domain definition. */
	CC_UTIL_EK_DomainID_Max, /*!< Reserved. */
	CC_UTIL_EK_DomainID_Last      = 0x7FFFFFFF, /*!< Reserved. */
}CCUtilEkDomainID_t;


/*! Endorsement key maximal modulus length. */
#define CC_UTIL_EK_BUFF_MAX_LENGTH 32  // 256 bit modulus and order sizes

/*! Endorsement key buffer definition. */
typedef  uint8_t  CCUtilEkBuf_t[CC_UTIL_EK_BUFF_MAX_LENGTH];

/*! Endorsement key private key definition.*/
typedef  struct {
    CCUtilEkBuf_t  PrivKey; /*!< Private key. */
} CCUtilEkPrivkey_t;

/*! Endorsement key public key definition. */
typedef  struct {
    CCUtilEkBuf_t  PublKeyX; /*!< X Public key. */
    CCUtilEkBuf_t  PublKeyY; /*!< Y Public key. */
} CCUtilEkPubkey_t;

/*! FIPS context definition, which is required for FIPS certification. */
typedef CCEcpkiKgCertContext_t CCUtilEkFipsContext_t;


/*! Temporary buffer Definitions. */
typedef  struct CCUtilEkTempData_t{
        CCEcpkiUserPrivKey_t  privKeyBuf; /*!< Private key.*/
        CCEcpkiUserPublKey_t  publKeyBuf; /*!< Public key.*/
        CCEcpkiKgTempData_t   ecpkiKgTempData; /*!< Temporary data.*/
} CCUtilEkTempData_t;

/*!
 * @brief This function computes the device unique endorsement key, as an ECC256 key pair, derived from the device root key (HUK).
 *
 * @return \c CC_UTIL_OK on success.
 * @return A non-zero value on failure as defined cc_util_error.h.
 *
 * Prior to using this ECC key pair with CryptoCell ECC APIs, translate the domain ID that was used to create it, to a CryptoCell
 *	  domain ID:
 *	  <ul><li> \c CC_UTIL_EK_DomainID_secp256r1 - \c CC_ECPKI_DomainID_secp256r1.</li>
 *	  <li> \c CC_UTIL_EK_DomainID_secp256k1 - \c CC_ECPKI_DomainID_secp256k1.</li></ul>
 */
CCUtilError_t CC_UtilDeriveEndorsementKey(
			CCUtilEkDomainID_t  domainID, 	/*!< [in] Selection of domain ID for the key. The following domain IDs are supported:
									<ul><li> \c CC_UTIL_EK_DomainID_secp256r1 (compliant with Trusted Board Boot Requirements CLIENT (TBBR-CLIENT) Armv8-A).</li>
									<li> \c CC_UTIL_EK_DomainID_secp256k1. </li></ul>*/
			CCUtilEkPrivkey_t   *pPrivKey_ptr, /*!< [out] Pointer to the derived private key. To use this private key with CryptoCell ECC,
									use ::CC_EcpkiPrivKeyBuild (CryptoCell domainID, pPrivKey_ptr, sizeof(*pPrivKey_ptr),
									UserPrivKey_ptr) to convert to CryptoCell ECC private key format. */
			CCUtilEkPubkey_t    *pPublKey_ptr,  /*!< [out] Pointer to the derived public key, in [X||Y] format (X and Y being the point
									coordinates). To use this public key with CryptoCell ECC:
									<ul><li> Concatenate a single byte with value 0x04 (indicating uncompressed
										format) with pPublKey_ptr in the following order [0x04||X||Y].</li>
									<li> Call ::CC_EcpkiPubKeyBuild (CryptoCell domainID, [PC || pPublKey_ptr],
										1+sizeof(*pPublKey_ptr), UserPublKey_ptr) to convert to CC_ECC public key
										format.</li></ul>*/
		      CCUtilEkTempData_t     *pTempDataBuf,  /*!< [in] Temporary buffers for internal use. */
		      CCRndGenerateVectWorkFunc_t f_rng,     /*!< [in] - Pointer to DRBG function*/
		      void                        *p_rng,    /*!< [in/out]  - Pointer to the RND context buffer used in case FIPS certification if required
                                    (may be NULL for all other cases). */
		      CCUtilEkFipsContext_t  *pEkFipsCtx     /*!< [in]  Pointer to temporary buffer used in case FIPS certification if required
									(may be \c NULL for all other cases). */
	);



/*****************************************/
/*   SESSION key settings definitions    */
/*****************************************/

/*!
 * @brief This function builds a random session key (KSESS), and sets it to the session key registers.
 *        It must be used as early as possible during the boot sequence, but only after the RNG is initialized.
 *
 * \note If this function is called more than once, each subsequent call invalidates any prior session-key-based authentication.
 *       These prior authentications have to be authenticated again. \par
 * \note Whenever the device reconfigures memory buffers previously used for Secure content, to become accessible from Non-secure context,
 *	 ::CC_UtilSetSessionKey must be invoked to set a new session key, and thus invalidate any existing secure key packages.
 *
 * @return \c CC_UTIL_OK on success.
 * @return A non-zero value on failure as defined cc_util_error.h.
 */
CCUtilError_t CC_UtilSetSessionKey(CCRndGenerateVectWorkFunc_t f_rng, /*!< [in] - Pointer to DRBG function*/
                                   void *p_rng                       /*!< [in/out]  - Pointer to the random context - the input to f_rng. */
);

#ifdef __cplusplus
}
#endif
/*!
@}
*/

#endif /*_CC_UTIL_H*/
