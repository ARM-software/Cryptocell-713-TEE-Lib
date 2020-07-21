/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

/*!
 @file cc_asset_provisioning.h
 @brief This file contains CryptoCell runtime-library ICV, OEM asset-provisioning APIs, and definitions.
 */

 /*!
 @addtogroup icv_oem_provisioning_apis
 @{
     */

#ifndef _CC_ASSET_PROVISIONING_H_
#define _CC_ASSET_PROVISIONING_H_

/*! The maximal size of an asset package. Header + asset. */
#define CC_ASSET_PROV_MAX_ASSET_PKG_SIZE  4140

/*! Key used for asset provisioning.*/
 typedef enum {
    ASSET_PROV_KEY_TYPE_KCP, /*!< OEM: The Kcp key was used to pack the asset. */
    ASSET_PROV_KEY_TYPE_KPICV, /*!< ICV: The Kpicv key was used to pack the asset. */
    ASSET_PROV_KEY_TYPE_RESERVED = 0x7FFFFFFF, /*!< Reserved. */
} CCAssetProvKeyType_t;

/*!
 @brief This API securely provisions ICV or OEM assets to devices, using CryptoCell.

 This function takes an encrypted and authenticated asset package produced by the ICV or OEM asset-packaging offline utility
 (using AES-CCM with key derived from Kpicv or Kcp respectively, and the asset identifier), authenticates and decrypts it.
 The decrypted asset data is returned to the caller.

 @note  This function is valid in all LCS.
        However, an error is returned if the requested key is locked, invalid, or not used.

 @return \c CC_UTIL_OK on success.
 @return A non-zero value on failure, as defined in cc_util_error.h.
 */
CCError_t CC_UtilAssetProvisioningOpen(CCAssetProvKeyType_t keyType, /*!< type of key to use to decrypt the package */
                                       uint32_t *pAssetPkgBuff, /*!< pointer to the head of the package */
                                       size_t assetPackageLen, /*!< The length of the entire package. header + asset */
                                       uint32_t *pAssetData, /*!< A pointer to a buffer that will contain the decrypted asset.
                                                                  When pAssetData == pAssetPkgBuff the decryption will be performed in-place */
                                       size_t *pAssetDataLen /*!< The length of decrypted asset data */
                                       );
/*!
 @}
 */

#endif /* _CC_ASSET_PROVISIONING_H_ */
