/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef  _CC_UTIL_CMAC_H
#define  _CC_UTIL_CMAC_H

#include "cc_util_error.h"
#include "cc_util_int_defs.h"
#include "cc_aes_defs.h"
#include "cc_util_defs.h"

/******************************************************************************
*                        	DEFINITIONS
******************************************************************************/

/*!
 * This function is used to construct the data required for key derivation.
 *
 * @param pLabel            the label to use
 * @param labelSize         the length of the label
 * @param pContextData      nonce
 * @param contextSize       nonce size
 * @param pDataOut          data buffer that will hold the result
 * @param pDataOutSize      a pointer to the size of the outputed buffer
 * @param derivedKeySize    the size of the key to derive
 *
 * @return                  CC_UTIL_OK on success.
 */
CCUtilError_t UtilCmacBuildDataForDerivation(const uint8_t *pLabel,
                                             size_t labelSize,
                                             const uint8_t *pContextData,
                                             size_t contextSize,
                                             uint8_t *pDataOut,
                                             size_t *pDataOutSize,
                                             size_t derivedKeySize);

/*!
 * This function is used to generate bytes stream for key derivation purposes.
 * The function gets an input data and can use use one of the following keys: KDR/Session/userKey.
 *
 * @param[in] aesKeyType 	- UTIL_USER_KEY / UTIL_ROOT_KEY / UTIL_SESSION_KEY.
 * @param[in] pUserKey		- A pointer to the user's key buffer (case of CC_UTIL_USER_KEY).
 * @param[in] pDataIn 		- A pointer to input buffer.
 * @param[in] dataInSize 	- Size of data in bytes.
 * @param[out] pCmacResult 	- A pointer to output buffer 16 bytes array.
 *
 * @return CC_UTIL_OK on success, otherwise failure
 *
 */
CCUtilError_t UtilCmacDeriveKey(UtilKeyType_t keyType,
                                CCAesUserKeyData_t *pUserKey,
                                uint8_t *pDataOut,
                                size_t dataInSize,
                                CCUtilAesCmacResult_t pCmacResult);


#endif /* _CC_UTIL_CMAC_H */
