/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _CC_ECPKI_ECIES_H
#define _CC_ECPKI_ECIES_H

/*!
@file
@brief This file defines the APIs that support ECIES - EC Integrated Encryption Scheme.
*/

/*!
 @addtogroup cc_ecies_apis
 @{
  */

#include "cc_ecpki_types.h"
#include "cc_rnd_common.h"
#include "cc_kdf.h"
#include "cc_cert_ctx.h"

#ifdef __cplusplus
extern "C"
{
#endif


/***********************************************************************
 *	                      EciesKemEncrypt                        *
 ***********************************************************************/
/**
 @brief The function creates and encrypts (encapsulate) a Secret Key of
	 required size according to the ISO/IEC 18033-2 standard [1],
	 sec. 10.2.3 - ECIES-KEM Encryption. To call this function the macro ::CC_EciesKemEncrypt
	 should be used.

	 The function does the following:
	 <ul><li> Generates random ephemeral EC key pair</li>
	 <li> Converts the ephemeral public key to ciphertext</li>
	 <li> Calculates the shared secret value SV</li>
	 <li> Calculates the Secret Keying data using the secret value SV.</li></ul>
 \note The term "sender" indicates an entity, who creates and performs encapsulation of the Secret Key using
       this function. The term "recipient" indicates another entity which receives and decrypts the Secret Key.\par
 \note All used public and private keys must be related to the same EC Domain.\par
 \note The public key of the recipient must be a legal public key - on elliptic curve.\par
 \note The function may also be used in Key Transport Schemes and partially, in Integrated Encryption Scheme
        (section 5.8 - ECIES without optional SharedData of ANSI X9.63-2011: Public Key Cryptography for the Financial Services
	 Industry - Key Agreement and Key Transport Using Elliptic Curve Cryptography).
 \note If external ephemeral keys are used, the caller must verify that these keys are valid.
 @return \c CC_OK on success.
 @return A non-zero value on failure as defined cc_ecpki_error.h.
*/
CEXPORT_C CCError_t EciesKemEncrypt(
			  CCEcpkiUserPublKey_t    *pRecipUzPublKey,	     /*!< [in] A pointer to the public key of the recipient. */
			  CCKdfDerivFuncMode_t     kdfDerivMode,	     /*!< [in] An enumerator variable, defining which KDF function mode
										       is used KDF1 or KDF2 (as defined in cc_kdf.h).*/
			  CCKdfHashOpMode_t       kdfHashMode,	     /*!< [in] An enumerator variable, defining the used HASH function */
			  uint32_t                     isSingleHashMode,     /*!< [in] Specific ECIES mode definition 0,1 according to
										       ISO/IEC 18033-2 - sec.10.2. */
			  CCEcpkiUserPrivKey_t    *pExtEphUzPrivKey,     /*!< [in] A pointer to external ephemeral private key - used only for testing. */
			  CCEcpkiUserPublKey_t    *pExtEphUzPublKey,     /*!< [in] A pointer to external ephemeral public key - used only for testing. */
			  uint8_t                   *pSecrKey,		     /*!< [out] Pointer to the generated Secret Key. */
			  size_t                     secrKeySize,	     /*!< [in] The size of the pSecrKey buffer in bytes. */
			  uint8_t                   *pCipherData,	     /*!< [out] A pointer to the encrypted ciphertext. */
			  size_t                    *pCipherDataSize,	     /*!< [in/out] A pointer to the size of the output cipher data (in)
											   and its actual size in bytes (out).*/
			  CCEciesTempData_t       *pTempBuff,	     /*!< [in] Temporary buffer for internal usage.*/
			  CCRndGenerateVectWorkFunc_t f_rng,         /*!< [in] - Pointer to DRBG function*/
			  void                        *p_rng,        /*!< [in/out]  - Pointer to the random context - the input to f_rng. */
			  CCEcpkiKgCertContext_t    *pFipsCtx	     /*!< [in] Pointer to temporary buffer used in case FIPS or Chinese
										       certification if required (may be NULL for all other cases). */
			  );


/***********************************************************************
 *	               CC_EciesKemEncrypt macros                        *
 ***********************************************************************/
/**
 @brief A macro for creation and encryption of secret key. For a description of the parameters see ::EciesKemEncrypt.
*/
#define  CC_EciesKemEncrypt(pRecipPublKey,kdfDerivMode,kdfHashMode,isSingleHashMode,pSecrKey,secrKeySize,pCipherData,pCipherDataSize,pTempBuff,f_rng,p_rng,pFipsCtx) \
	 EciesKemEncrypt((pRecipPublKey),(kdfDerivMode),(kdfHashMode),(isSingleHashMode),NULL,NULL,(pSecrKey),(secrKeySize),(pCipherData),(pCipherDataSize),(pTempBuff),(f_rng),(p_rng),(pFipsCtx))


/***********************************************************************
 *	                      CC_EciesKemDecrypt                       *
 ***********************************************************************/
/**
@brief The function decrypts the encapsulated Secret Key passed by the sender according to the ISO/IEC 18033-2 standard [1],
       sec. 10.2.4 - ECIES-KEM Decryption.

       The function does the following
	 <ul><li> Checks that the ephemeral public key of the sender relates to used EC Domain and initializes the Key structure.</li>
	 <li> Calculates the shared secret value SV.</li>
	 <li> Calculates the Secret Keying data using the secret value SV.</li></ul>

 \note The term "sender" indicates an entity, who creates and performs encapsulation of the Secret Key using
		this function. The term "recipient" indicates an other entity which receives and decrypts the Secret Key. \par
 \note All used public and private keys must be related to the same EC Domain. \par
 \note The function may also be used in Key Transport Schemes and partially, in Integrated Encryption Scheme
        (section 5.8 - ECIES without optional SharedData of ANSI X9.63-2011: Public Key Cryptography for the Financial
	Services Industry - Key Agreement and Key Transport Using Elliptic Curve Cryptography).


 @return \c CC_OK on success.
 @return A non-zero value on failure as defined cc_ecpki_error.h.
*/
CIMPORT_C CCError_t CC_EciesKemDecrypt(
			   CCEcpkiUserPrivKey_t    *pRecipPrivKey,		 /*!< [in] A pointer to the recipient's private key. */
			   CCKdfDerivFuncMode_t     kdfDerivMode,		 /*!< [in] An enumerator variable, defining which KDF function mode
										       is used KDF1 or KDF2 (as defined in cc_kdf.h).*/
			   CCKdfHashOpMode_t        kdfHashMode,		 	 /*!< [in] An enumerator variable, defining used HASH function. */
			   uint32_t                 isSingleHashMode,	 	 /*!< [in] Specific ECIES mode definition 0,1 according to
											   ISO/IEC 18033-2 - sec.10.2. */
			   uint8_t                  *pCipherData,		 /*!< [in] A pointer to the received encrypted cipher data. */
			   size_t                   cipherDataSize,		 /*!< [in] A size of the cipher data in bytes. */
			   uint8_t                  *pSecrKey,			 /*!< [out] Pointer to the generated Secret Key. */
			   size_t                   secrKeySize,		 /*!< [in] The size of the pSecrKey buffer in bytes. */
			   CCEciesTempData_t        *pTempBuff		 	 /*!< [in] Temporary buffer for internal usage. */);


#ifdef __cplusplus
}
#endif
/*!
 @}
 */
#endif
