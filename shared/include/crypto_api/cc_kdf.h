/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _CC_KDF_H
#define _CC_KDF_H



#ifdef __cplusplus
extern "C"
{
#endif

/*!
@file
@brief This file defines the API that supports Key derivation function in modes
       as defined in Public-Key Cryptography Standards (PKCS) #3: Diffie-Hellman Key Agreement Standard,
       ANSI X9.42-2003: Public Key Cryptography for the Financial Services Industry: Agreement of Symmetric Keys Using Discrete Logarithm Cryptography,
       and ANSI X9.63-2011: Public Key Cryptography for the Financial Services Industry - Key Agreement and Key Transport Using Elliptic Curve
       Cryptography.
 */

 /*!
 @addtogroup cc_kdf
@{
*/

#include "cc_hash_defs.h"
#include "cc_kdf_defs.h"

/*********************************************************************************************************/
/***************************************** Public Functions **********************************************/
/*********************************************************************************************************/
/*!
 @brief CC_KdfKeyDerivFunc performs key derivation according to one of the modes defined in standards:
	ANSI X9.42-2003: Public Key Cryptography for the Financial Services Industry: Agreement of Symmetric Keys Using Discrete Logarithm Cryptography,
	ANSI X9.63-2011: Public Key Cryptography for the Financial Services Industry - Key Agreement and Key Transport Using Elliptic Curve Cryptography,
	ISO/IEC 18033-2:2006: Information technology -- Security techniques -- Encryption algorithms -- Part 2: Asymmetric ciphers.

The present implementation of the function allows the following operation modes:
<ul><li> CC_KDF_ASN1_DerivMode - mode based on  ASN.1 DER encoding; </li>
<li> CC_KDF_ConcatDerivMode - mode based on concatenation;</li>
<li> CC_KDF_X963_DerivMode = CC_KDF_ConcatDerivMode;</li>
<li> CC_KDF_ISO18033_KDF1_DerivMode, CC_KDF_ISO18033_KDF2_DerivMode - specific modes according to
ISO/IEC 18033-2 standard.</li></ul>

The purpose of this function is to derive a keying data from the shared secret value and some
other optional shared information, included in OtherInfo (SharedInfo).

\note All buffers arguments are represented in big-endian format.

@return \c CC_OK on success.
@return A non-zero value on failure as defined cc_kdf_error.h or cc_hash_error.h.
*/
CCError_t  CC_KdfKeyDerivFunc(
                    uint8_t              *pZzSecret,            /*!< [in]  A pointer to shared secret value octet string. */
                    size_t                zzSecretSize,         /*!< [in]  The size of the shared secret value in bytes.
                                                                           The maximal size is defined as: ::CC_KDF_MAX_SIZE_OF_SHARED_SECRET_VALUE. */
                    CCKdfOtherInfo_t     *pOtherInfo,           /*!< [in]  A pointer to the structure, containing pointers to the data, shared by
									   two entities of agreement, depending on KDF mode:
                                                                           <ul><li> In KDF ASN1 mode OtherInfo includes ASN1 DER encoding of AlgorithmID (mandatory),
                                                                             and some optional data entries as described in section 7.7.1 of the ANSI X9.42-2003:
									     Public Key Cryptography for the Financial Services Industry: Agreement of Symmetric Keys Using
									     Discrete Logarithm Cryptography standard.</li>
                                                                           <li> In both ISO/IEC 18033-2:2006: Information technology -- Security techniques -- Encryption algorithms -- Part 2:
										Asymmetric ciphers standard: KDF1 and KDF2 modes this parameter is ignored and may be set to NULL. </li>
                                                                           <li> In other modes it is optional and may be set to NULL. </li></ul>*/
                    CCKdfHashOpMode_t     kdfHashMode,          /*!< [in]  The KDF identifier of hash function to be used. The hash function output
									   must be at least 160 bits. */
                    CCKdfDerivFuncMode_t  derivMode,            /*!< [in]  The enum value, specifies one of above described derivation modes. */
                    uint8_t              *pKeyingData,          /*!< [out] A pointer to the buffer for derived keying data. */
                    size_t                keyingDataSize        /*!< [in]  The size in bytes of the keying data to be derived.
                                                                           The maximal size is defined as :: CC_KDF_MAX_SIZE_OF_KEYING_DATA. */ );


/*********************************************************************************************************/
/*!
 CC_KdfAsn1KeyDerivFunc performs key derivation according to ASN1 DER encoding method defined
 in section 7.2.1 of ANSI X9.42-2003: Public Key Cryptography for the Financial Services Industry: Agreement of Symmetric Keys Using Discrete Logarithm Cryptography standard.
 For a description of the parameters see ::CC_KdfKeyDerivFunc.
*/
#define CC_KdfAsn1KeyDerivFunc(ZZSecret_ptr,ZZSecretSize,OtherInfo_ptr,kdfHashMode,KeyingData_ptr,KeyLenInBytes)\
		CC_KdfKeyDerivFunc((ZZSecret_ptr),(ZZSecretSize),(OtherInfo_ptr),(kdfHashMode),CC_KDF_ASN1_DerivMode,(KeyingData_ptr),(KeyLenInBytes))


/*********************************************************************************************************/
/*!
 CC_KdfConcatKeyDerivFunc performs key derivation according to concatenation mode defined
 in section 7.2.2 of ANSI X9.42-2003: Public Key Cryptography for the Financial Services Industry: Agreement of Symmetric Keys Using Discrete Logarithm Cryptography
 standard and also meets ANSI X9.63-2011: Public Key Cryptography for the Financial Services Industry - Key Agreement and Key Transport Using Elliptic Curve
 Cryptography standard. For a description of the parameters see ::CC_KdfKeyDerivFunc.
*/
#define CC_KdfConcatKeyDerivFunc(ZZSecret_ptr,ZZSecretSize,OtherInfo_ptr,kdfHashMode,KeyingData_ptr,KeyLenInBytes)\
		CC_KdfKeyDerivFunc((ZZSecret_ptr),(ZZSecretSize),(OtherInfo_ptr),(kdfHashMode),CC_KDF_ConcatDerivMode,(KeyingData_ptr),(KeyLenInBytes))


#ifdef __cplusplus
}
#endif
 /**
@}
 */
#endif //_CC_KDF_H

