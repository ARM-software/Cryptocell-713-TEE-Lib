/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef  _CC_UTIL_OEM_ASSET_H
#define  _CC_UTIL_OEM_ASSET_H

/*!
@file
@brief This file contains the functions and definitions for the OEM Asset provisioning.
*/

/*!
 @addtogroup oem_util
 @{
 */

#ifdef __cplusplus
extern "C"
{
#endif

#include "cc_util_defs.h"

/*! Defines the OEM key buffer. */
typedef CCUtilAesCmacResult_t CCUtilOemKey_t;


/*!
 * @brief This API provides a means of secure provisioning of OEM assets to devices using CryptoCell TEE.
 *        It takes an encrypted and authenticated asset package produced by the OEM Asset Packing offline utility
 *        (using AES-CCM with key derived from KOEM and the asset identifier), and authenticates and decrypts it.
 *        The decrypted asset data and optional user data parameter are returned to the caller.
 * \note  The device must be in SE LCS, otherwise an error is returned.
 *
 * @return \c CC_UTIL_OK on success.
 * @return A non-zero value on failure as defined in cc_util_error.h.
 */
CCUtilError_t CC_UtilOemAssetUnpack(
			CCUtilOemKey_t      	pOemKey, 	 /*!< [in] KOEM 16 bytes buffer, in big-endian order. KOEM was computed during
									  first stage boot, and stored in Secure SRAM.*/
			uint32_t 	  	assetId, 	 /*!< [in] 32-bit index identifying the asset, big-endian order. Must match the asset ID embedded
									  in the asset package. */
			uint8_t     		*pAssetPackage,	 /*!< [in] The encrypted and authenticated asset package. */
			size_t  		assetPackageLen, /*!< [in] Length of the asset package. */
			uint8_t     		*pAssetData, 	 /*!< [out] Buffer for retrieving the decrypted asset data. */
			size_t  		*pAssetDataLen,  /*!< [in, out] Input: Size of the available asset data buffer.
										Output: Pointer to actual length of the decrypted asset data.
										Maximal size is 512-bytes.*/
			uint32_t     		*pUserData	 /*!< [out] Pointer to 32-bit integer for retrieval of the user data that was optionally
									    embedded in the package. This may be \c NULL, in which case the user data is not returned.*/);


#ifdef __cplusplus
}
#endif
/*!
 @}
 */
#endif /*_CC_UTIL_OEM_ASSET_H*/
