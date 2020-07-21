/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


#include "cc_pal_log.h"
#include "cc_pal_types.h"
#include "cc_pal_mem.h"

#include "cc_util_error.h"
#include "cc_util_int_defs.h"
#include "cc_util_defs.h"
#include "cc_util_cmac.h"
#include "cc_util_key_derivation.h"

#include "cc_aesccm.h"
#include "cc_aes_defs.h"
#include "cc_asset_prov.h"
#include "cc_asset_provisioning.h"

#define CC_ASSET_PROV_CONST_PKG_SIZE        (CC_ASSET_PROV_ADATA_SIZE + CC_ASSET_PROV_NONCE_SIZE + CC_ASSET_PROV_TAG_SIZE)
#define CC_ASSET_PROV_MIN_PKG_SIZE          (CC_ASSET_PROV_CONST_PKG_SIZE + CC_ASSET_PROV_BLOCK_SIZE)

static CCError_t UtilAssetProvValidate(CCAssetProvKeyType_t keyType,
                                       uint32_t *pAssetPkgBuff,
                                       size_t assetPackageLen,
                                       uint32_t *pAssetData,
                                       size_t *pAssetDataLen)
{
    CCAssetProv_t *pAssetPackage = NULL;

    /* validate inputs */
    if (pAssetPkgBuff == NULL) {
        CC_PAL_LOG_ERR("pAssetPkgBuff == NULL\n");
        return CC_UTIL_ILLEGAL_PARAMS_ERROR;
    }

    if (pAssetData == NULL) {
        CC_PAL_LOG_ERR("pAssetData == NULL\n");
        return CC_UTIL_ILLEGAL_PARAMS_ERROR;
    }

    if (pAssetDataLen == NULL) {
        CC_PAL_LOG_ERR("pAssetDataLen == NULL\n");
        return CC_UTIL_ILLEGAL_PARAMS_ERROR;
    }

    if (assetPackageLen > CC_ASSET_PROV_MAX_ASSET_PKG_SIZE) {
        CC_PAL_LOG_ERR("assetPackageLen > CC_ASSET_PROV_MAX_ASSET_PKG_SIZE\n");
        return CC_UTIL_ILLEGAL_PARAMS_ERROR;
    }

    if (assetPackageLen < CC_ASSET_PROV_MIN_PKG_SIZE) {
        CC_PAL_LOG_ERR("assetPackageLen < minPkgSize\n");
        return CC_UTIL_ILLEGAL_PARAMS_ERROR;
    }

    if (((unsigned long) pAssetPkgBuff + assetPackageLen) < (unsigned long) pAssetPkgBuff) {
        CC_PAL_LOG_ERR("pAssetPkgBuff + assetPackageLen < pAssetPkgBuff\n");
        return CC_UTIL_ILLEGAL_PARAMS_ERROR;
    }

    if ((keyType != ASSET_PROV_KEY_TYPE_KPICV) && (keyType != ASSET_PROV_KEY_TYPE_KCP)) {
        CC_PAL_LOG_ERR("keyType is not KPICV nor KCP\n");
        return CC_UTIL_ILLEGAL_PARAMS_ERROR;
    }

    pAssetPackage = (CCAssetProv_t *) pAssetPkgBuff;

    /* Validate asset size max size */
    if (pAssetPackage->assetSize > CC_ASSET_PROV_MAX_ASSET_SIZE) {
        CC_PAL_LOG_ERR("Invalid asset size %u", pAssetPackage->assetSize);
        return CC_UTIL_ILLEGAL_PARAMS_ERROR;
    }

    /* Verify assetDataSize not 0 */
    if (pAssetPackage->assetSize == 0) {
        CC_PAL_LOG_ERR("Invalid asset size is 0\n");
        return CC_UTIL_ILLEGAL_PARAMS_ERROR;
    }

    /* Verify assetDataSize against assetPkgSize */
    if (assetPackageLen < (CC_ASSET_PROV_CONST_PKG_SIZE + pAssetPackage->assetSize)) {
        CC_PAL_LOG_ERR("Invalid asset size %u", pAssetPackage->assetSize);
        return CC_UTIL_ILLEGAL_PARAMS_ERROR;
    }

    if (*pAssetDataLen < pAssetPackage->assetSize) {
        CC_PAL_LOG_ERR("invalid AssetDataLen %u\n", *pAssetDataLen);
        return CC_UTIL_ILLEGAL_PARAMS_ERROR;
    }

    /* Verify package token */
    if (pAssetPackage->token != ASSET_PROV_TOKEN) {
        CC_PAL_LOG_ERR("invalid token\n");
        return CC_UTIL_ILLEGAL_PARAMS_ERROR;
    }

    /* Verify package version */
    if (pAssetPackage->version != ASSET_PROV_VERSION) {
        CC_PAL_LOG_ERR("Invalid version");
        return CC_UTIL_ILLEGAL_PARAMS_ERROR;
    }

    return CC_UTIL_OK;

}

static CCError_t UtilAssetProvAssetKeyToUtilKey(CCAssetProvKeyType_t assetKey, UtilKeyType_t *pUtilKey)
{
    if (pUtilKey == NULL) {
        CC_PAL_LOG_ERR("pUtilKey is NULL\n");
        return CC_UTIL_ILLEGAL_PARAMS_ERROR;
    }

    switch (assetKey) {
        case ASSET_PROV_KEY_TYPE_KCP:
            *pUtilKey = UTIL_KCP_KEY;
            break;
        case ASSET_PROV_KEY_TYPE_KPICV:
            *pUtilKey = UTIL_KPICV_KEY;
            break;
        default:
            *pUtilKey = UTIL_END_OF_KEY_TYPE;
            break;
    }

    return CC_UTIL_OK;
}

CCError_t CC_UtilAssetProvisioningOpen(CCAssetProvKeyType_t keyType,
                                       uint32_t *pAssetPkgBuff,
                                       size_t assetPackageLen,
                                       uint32_t *pAssetData,
                                       size_t *pAssetDataLen)
{
    CCError_t rc = CC_OK;

    const uint8_t provLabel = 'P';
    CCAssetProv_t *pAssetPackage = NULL;
    uint32_t assetDataSize = 0;
    uint32_t isSet = 0;
    UtilKeyType_t utilKey = UTIL_END_OF_KEY_TYPE;
    uint8_t *pMac = NULL;
    uint32_t lcs = CC_LCS_RMA_LCS;

    uint8_t dataIn[CC_UTIL_MAX_KDF_SIZE_IN_BYTES] = { 0 };
    size_t dataInSize = CC_UTIL_MAX_KDF_SIZE_IN_BYTES;
    uint8_t keyProv[CC_UTIL_AES_CMAC_RESULT_SIZE_IN_BYTES]  = { 0 };
    uint8_t *pCcmAddData = NULL;
    uint8_t *pCcmNonceData = NULL;

    CC_UTIL_IS_SECURE_DISABLE_FLAG_SET(isSet);
    if (isSet == SECURE_DISABLE_FLAG_SET) {
        CC_PAL_LOG_ERR("security disabled bit is asserted\n");
        return CC_UTIL_SD_IS_SET_ERROR;
    }

    /* check if fatal error bit is set to ON */
    CC_UTIL_IS_FATAL_ERROR_SET(isSet);
    if (isSet == FATAL_ERROR_FLAG_SET) {
        CC_PAL_LOG_ERR("Fatal Error bit is set to ON\n");
        return CC_UTIL_FATAL_ERR_IS_LOCKED_ERR;
    }

    /*
     * when in CM and DM life cycle, EKcst is not set.
     * skip "EKcst disbled" Test to allow testing CM and DM with shadow registeres.
     * in RMA the HW keys Kpicv and Kcp are '0'.
     */
    CC_UTIL_GET_LCS(lcs);
    if (lcs == CC_LCS_SECURE_LCS) {
        /* The function should return error in case is_kcst_disabled is not set */
        CC_UTIL_IS_KCUST_DISABLE(rc);
        if (rc == 0) {
            CC_PAL_LOG_ERR("Kcst should be disabled\n");
            return CC_UTIL_KCST_NOT_DISABLED_ERROR;
        }
    }

    /* convert key types certificae key type to driver key type */
    rc = UtilAssetProvAssetKeyToUtilKey(keyType, &utilKey);
    if (rc != CC_UTIL_OK) {
        CC_PAL_LOG_ERR("utilAssetProvAssetKeyToUtilKey failed with error 0x%08x\n", rc);
        return rc;
    }

    /* verify package integrity */
    rc = UtilAssetProvValidate(keyType, pAssetPkgBuff, assetPackageLen, pAssetData, pAssetDataLen);
    if (rc != CC_UTIL_OK) {
        CC_PAL_LOG_ERR("CC_UtilAssetProvValidate failed with error 0x%08x\n", rc);
        return rc;
    }

    pAssetPackage = (CCAssetProv_t *) pAssetPkgBuff;

    /* Generate dataIn buffer for CMAC: iteration || 'P' || 0x00 || asset Id || 0x80
       since derived key is 128 bits we have only 1 iteration */
    rc = UtilCmacBuildDataForDerivation(&provLabel,
                                        sizeof(provLabel),
                                        (uint8_t *) &pAssetPackage->assetId,
                                        sizeof(pAssetPackage->assetId),
                                        dataIn,
                                        &dataInSize,
                                        (size_t) CC_UTIL_AES_CMAC_RESULT_SIZE_IN_BYTES);
    if (rc != CC_UTIL_OK) {
        CC_PAL_LOG_ERR("UtilCmacBuildDataForDerivation failed with error 0x%08x\n", rc);
        return rc;
    }

    /* only one iteration of key derivation */
    dataIn[0] = 1;

    /* perform key derivation */
    rc = UtilCmacDeriveKey(utilKey, NULL, dataIn, dataInSize, keyProv);
    if (rc != 0) {
        CC_PalMemSetZero(keyProv, CC_UTIL_AES_CMAC_RESULT_SIZE_IN_BYTES);
        CC_PAL_LOG_ERR("UtilCmacDeriveKey failed with error 0x%08x", rc);
        return rc;
    }

    assetDataSize = pAssetPackage->assetSize;
    pCcmNonceData = pAssetPackage->nonce;
    pCcmAddData = (uint8_t *)pAssetPackage;
    pMac = pAssetPackage->encAsset + assetDataSize;

    /* Decrypt and authenticate the BLOB */
    rc = CC_AesCcm(CC_AES_DECRYPT,
                   keyProv, CC_AES_Key128BitSize,
                   pCcmNonceData, CC_ASSET_PROV_NONCE_SIZE,
                   pCcmAddData, CC_ASSET_PROV_ADATA_SIZE,
                   pAssetPackage->encAsset, assetDataSize,
                   (uint8_t*)pAssetData, CC_ASSET_PROV_TAG_SIZE, pMac,
                   CC_AES_MODE_CCM);
    if (rc != 0) {
        CC_PalMemSetZero(keyProv, CC_UTIL_AES_CMAC_RESULT_SIZE_IN_BYTES);
        CC_PalMemSetZero(pAssetData, *pAssetDataLen);
        CC_PAL_LOG_ERR("CC_AesCcm failed with error 0x%08x", rc);
        return rc;
    }

    /*  Set output data */
    *pAssetDataLen = assetDataSize;

    return rc;
}
