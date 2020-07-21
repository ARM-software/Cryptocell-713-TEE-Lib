/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


#ifndef CC_ECPKI_DOMAIN_H
#define CC_ECPKI_DOMAIN_H


/*!
@file
@brief This file defines the ECPKI build domain API.
*/
 /*!
 @addtogroup cc_ecpki_domain
 @{
  */

#include "cc_error.h"
#include "cc_ecpki_types.h"

#ifdef __cplusplus
extern "C"
{
#endif



/**********************************************************************************
 *      	      CC_EcpkiBuildEcDomain function 			  *
 **********************************************************************************/
/*!
@brief The function builds (imports) the ECC Domain structure from EC parameters given
by the user in big-endian order of bytes in arrays.

Call this function first when you operate the ECC cryptographic operations.
The function performs the following operations:
<ul><li>Checks pointers and sizes of incoming parameters.</li>
<li> Converts parameters from big-endian bytes arrays into little endian words arrays, where
the left word is the last significant.</li></ul>
\note Domain parameters should be validated by the user, prior to calling this function.

@return \c CC_OK on success.
@return A non-zero value on failure as defined cc_ecpki_error.h.
 */
CIMPORT_C CCError_t CC_EcpkiBuildEcDomain(
			uint8_t   *pMod,                    /*!< [in]  A pointer to EC modulus. */
			uint8_t   *pA,                      /*!< [in]  A pointer to parameter A of elliptic curve.
                                                            The size of the buffer must be the same as EC modulus. */
			uint8_t   *pB,                      /*!< [in]  A pointer to parameter B of elliptic curve.
                                                            The size of the buffer must be the same as EC modulus. */
			uint8_t   *pOrd,                    /*!< [in]  A pointer to order of generator (point G). */
			uint8_t   *pGx,                     /*!< [in]  A pointer to coordinate X of generator G.
                                                            The size of the buffer must be the same as EC modulus. */
			uint8_t   *pGy,                     /*!< [in]  A pointer to coordinate Y of generator G.
                                                            The size of the buffer must be the same as EC modulus. */
			uint8_t   *pCof,                    /*!< [in]  A pointer to EC cofactor - optional. If the pointer
                                                            and the size are set to null, the given curve has
                                                            cofactor = 1 or cofactor should not be included in the calculations. */
			uint32_t   modSizeBytes,            /*!< [in]  A size of the EC modulus buffer in bytes.
                                                            \note The sizes of the buffers: pA, pB, pGx, pGx are equal to pMod size. */
			uint32_t   ordSizeBytes,            /*!< [in]  A size of the generator order in bytes. */
			uint32_t   cofSizeBytes,            /*!< [in]  A size of cofactor buffer in bytes. According to our
                                                            implementation cofactorSizeBytes must be not great, than 4 bytes.
                                                            If cofactor = 1, then, the size and the pointer may be set to null. */
			uint32_t   securityStrengthBits,    /*!< [in]  Optional security strength level S in bits:
     	                                                     see section A.3.1.4 of ANSI X9.62-2005: Public Key Cryptography for the Financial
							     Services Industry, The Elliptic Curve Digital Signature Algorithm (ECDSA).
							     If this parameter is equal to 0, then it is ignored, else the function checks
							     the EC order size. If the order is less than max(S-1, 192), then the function
							     returns an error. */
			CCEcpkiDomain_t  *pDomain       /*!< [out] A pointer to EC domain structure. */
);



/**********************************************************************************
 *      	      CC_EcpkiGetEcDomain function 			  	  *
 **********************************************************************************/

/*!
 * @brief  The function returns a pointer to an ECDSA saved domain (one of the supported domains).
 *
 * @return Domain pointer on success.
 * @return NULL on failure.
 */

const CCEcpkiDomain_t *CC_EcpkiGetEcDomain(CCEcpkiDomainID_t domainId /*!< [in] Index of one of the domain ID (must be one of the supported domains). */);

#ifdef __cplusplus
}
#endif

 /*!
 @}
 */
#endif
