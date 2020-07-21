/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


#ifndef _CC_RSA_SCHEMES_PRIV_ENC_H
#define _CC_RSA_SCHEMES_PRIV_ENC_H


#include "cc_error.h"
#include "cc_rsa_types.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*!
@file
@brief This file defines APIs that support [PKCS1_1.5] private encryption schemes.
*/

/**********************************************************************************************************/
/*!
@brief This function implements a private encrypt operation,
       by combining the RSA decryption primitive and the EMSA-PKCS1-v1_5 encoding method,
       to provide an RSA-based encryption method.

@return CC_OK on success.
@return A non-zero value from cc_rsa_error.h on failure.
*/
CEXPORT_C CCError_t CC_RsaPkcs1v15PrivateEncrypt(
			CCRsaUserPrivKey_t  *UserPrivKey_ptr, /*!< [in] Pointer to the private-key data structure of the User.*/
			CCRsaPrimeData_t  *PrimeData_ptr,     /*!< [in] Pointer to a temporary structure that is internally used as workspace
								      for the encryption operation.*/
			uint8_t           *DataIn_ptr,		 /*!< [in] Pointer to the data to encrypt.*/
			uint16_t           DataInSize,		 /*!< [in] The size (in bytes) of the data to encrypt. The data size must be:
                                                                           DataSize <= modulus size - 11. */
			uint8_t            *Output_ptr		 /*!< [out] Pointer to the encrypted data. The buffer must be at least modulus size
									    bytes long. */);

/**********************************************************************************************************/


#ifdef __cplusplus
}
#endif

#endif
