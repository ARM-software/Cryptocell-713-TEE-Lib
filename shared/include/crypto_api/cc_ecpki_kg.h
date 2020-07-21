/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


#ifndef _CC_ECPKI_KG_H
#define _CC_ECPKI_KG_H

/*!
@file
@brief This file defines the API for generation of ECC private and public keys.
*/

/*!
 @addtogroup cc_ecpki_kg
 @{
 */



#include "cc_error.h"
#include "cc_rnd_common.h"
#include "cc_ecpki_types.h"
#include "cc_cert_ctx.h"
#ifdef __cplusplus
extern "C"
{
#endif

/*****************  CC_EcpkiKeyPairGenerate function   **********************/
/*!
@brief Generates a pair of private and public keys in internal representation
according to <em>ANSI X9.62-2005: Public Key Cryptography for the
Financial Services Industry, The Elliptic Curve Digital Signature Algorithm
(ECDSA) standard</em>.

@return \c CC_OK on success.
@return A non-zero value on failure as defined cc_ecpki_error.h or cc_rnd_error.h
*/
CIMPORT_C CCError_t CC_EcpkiKeyPairGenerate(
                        /*! [in] Pointer to DRBG function. */
                        CCRndGenerateVectWorkFunc_t f_rng,
                        /*! [in/out]  Pointer to the random context - the input
                        to f_rng. */
                        void *p_rng,
                        /*! [in]  Pointer to EC (elliptic curve) domain (curve). */
                        const CCEcpkiDomain_t  *pDomain,
                        /*! [out] Pointer to the private key structure. This
                        structure is used as input to the ECPKI cryptographic
                        primitives. */
                        CCEcpkiUserPrivKey_t   *pUserPrivKey,
                        /*! [out] Pointer to the public key structure. This
                        structure is used as input to the ECPKI cryptographic
                        primitives. */
                        CCEcpkiUserPublKey_t   *pUserPublKey,
                        /*! [in] Temporary buffers for internal use. */
                        CCEcpkiKgTempData_t   *pTempData,
                        /*! [in] Pointer to temporary buffer used in case FIPS
                        certification if required (may be NULL for all other
                        cases). */
                        CCEcpkiKgCertContext_t  *pFipsCtx
);




#ifdef __cplusplus
}
#endif
/*!
@}
 */
#endif




