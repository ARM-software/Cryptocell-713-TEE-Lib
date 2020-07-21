/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include "common_util_log.h"
#include "common_crypto_asym.h"
#include "common_crypto_sym.h"
#include "common_rsa_keypair_util.h"
#include "common_util_files.h"
#include "cc_asset_prov.h"

#define KEY_SIZE                16
#define KPROV_KEY_SIZE          16
#define KPROV_DATA_IN_SIZE      8

static uint8_t isLibOpened = 0;

/**
 * @brief initialize openSSL library
 *
 * @param[in] None
 * @param[out] None
 *
 */
/*********************************************************/
static void InitOpenSsl(void)
{
    if (0 == isLibOpened) {
        OpenSSL_add_all_algorithms();
    }
    isLibOpened++;
}

/**
 * @brief terminates and cleanup openSSL library
 *
 * @param[in]  None
 * @param[out] None
 *
 */
/*********************************************************/
static void CloseOpenSsl(void)
{
    isLibOpened--;
    if (0 == isLibOpened) {
        EVP_cleanup();
    }
}

/**
 * @brief performs CMAC key derivation for Kprov using openSSL library
 *
 * @param[in]  pKey & keySize - Kpicv key and its size
 * 		lable & pContext & contextSize used to build the dataIn for derivation
 * @param[out] pOutKey - Kprov
 *
 */
/*********************************************************/
static int AesCmacKeyDerivation(uint8_t *pKey,
                                uint32_t keySize,
                                char lable,
                                uint8_t *pContext,
                                uint32_t contextSize,
                                char *pOutKey,
                                uint32_t outKeySize)
{
    int rc = 0;
    int i = 0;
    int8_t dataIn[KPROV_DATA_IN_SIZE] = { 0x0 };

    /* Create the input to the CMAC derivation */
    dataIn[i++] = 0x1;
    dataIn[i++] = lable;
    dataIn[i++] = 0x0;
    memcpy(&dataIn[i], pContext, contextSize);
    i += contextSize;
    dataIn[i] = outKeySize * CC_BITS_IN_BYTE;    // size of the key in bits

    rc = CC_CommonAesCmacEncrypt(dataIn, sizeof(dataIn), pKey, keySize, pOutKey);
    if (rc != 0) {
        UTIL_LOG_ERR("failed to CC_CommonAesCmacEncrypt(), rc %d\n", rc);
        return (-1);
    }

    return rc;
}

/**
 * @brief Build the ICV asset BLOB using openSSL library
 *
 * @param[in]  encKeyBuff & encKeyBuffSize & pKeyPwdFileName - the encryptes Kpicv key
 *       	assetId - Asset ID, used for Kprov derivation
 *       	asset & assetSize - The Asset to generate the BLOB for
 *       	pBlobFileName - OUT - the asset BLOB binary file name
 * @param[out] None
 *
 */
/*********************************************************/
int build_asset_blob(uint8_t *encKeyBuff,
                     uint32_t encKeyBuffSize,
                     char *pKeyPwdFileName,
                     uint32_t assetId,
                     uint8_t *asset,
                     uint32_t assetSize,
                     char *pBlobFileName)
{
    int rc = 0;
    uint8_t key[(KEY_SIZE + AES_BLOCK_SIZE)] = { 0 };
    uint8_t keyProv[KPROV_KEY_SIZE] = { 0 };
    uint8_t i = 0;
    CCAssetProv_t assetBlob = { 0 };
    uint32_t assetBlobSize;

    // Verify Inputs
    if (encKeyBuff == NULL) {
        UTIL_LOG_ERR("failed to encKeyBuff == NULL rc 0x%08x\n", rc);
        return (-1);
    }

    if (encKeyBuffSize != (KEY_SIZE + AES_BLOCK_SIZE)) {
        UTIL_LOG_ERR("failed to encKeyBuffSize != (KEY_SIZE + AES_BLOCK_SIZE) rc 0x%08x\n", rc);
        return (-1);
    }

    if (asset == NULL) {
        UTIL_LOG_ERR("failed to asset == NULL rc 0x%08x\n", rc);
        return (-1);
    }

    if (assetSize > CC_ASSET_PROV_MAX_ASSET_SIZE) {
        UTIL_LOG_ERR("failed to assetSize > CC_ASSET_PROV_MAX_ASSET_SIZE rc 0x%08x\n", rc);
        return (-1);
    }

    if (pBlobFileName == NULL) {
        UTIL_LOG_ERR("failed to pBlobFileName == NULL rc 0x%08x\n", rc);
        return (-1);
    }

    assetBlobSize = CC_ASSET_PROV_ADATA_SIZE + CC_ASSET_PROV_NONCE_SIZE + assetSize
                    + CC_ASSET_PROV_TAG_SIZE;

    InitOpenSsl();

    // Build the BLOB header
    assetBlob.token = ASSET_PROV_TOKEN;
    assetBlob.version = ASSET_PROV_VERSION;
    assetBlob.assetSize = assetSize;
    assetBlob.assetId = assetId;

    rc = CC_CommonRandBytes(CC_ASSET_PROV_NONCE_SIZE, (uint8_t *) assetBlob.nonce);
    if (rc != 0) {
        UTIL_LOG_ERR("failed to CC_CommonRandBytes() for nonce, rc %d\n", rc);
        rc = (-1);
        goto end_func;
    }

    // Decrypt Kpicv
    rc = CC_CommonAesCbcDecrypt(pKeyPwdFileName, encKeyBuff, encKeyBuffSize, key);
    if (rc != 0) {
        UTIL_LOG_ERR("failed to CC_CommonAesCbcDecrypt() for Kpicv, rc %d\n", rc);
        rc = (-1);
        goto end_func;
    }

    // Calculate Kprov = cmac(Kpicv, 0x01 || 0x50 || 0x00 || asset id || 0x80)
    rc = AesCmacKeyDerivation(key,
                              KEY_SIZE,
                              'P',
                              (uint8_t *) &assetBlob.assetId,
                              sizeof(assetBlob.assetId),
                              keyProv,
                              sizeof(keyProv));


    if (rc != 0) {
        UTIL_LOG_ERR("failed to AesCmacKeyDerivation() for Kprov, rc %d\n", rc);
        rc = (-1);
        goto end_func;
    }

    // Encrypt and authenticate the asset
    rc = CC_CommonAesCcmEncrypt(keyProv,
                                (uint8_t *) assetBlob.nonce,
                                CC_ASSET_PROV_NONCE_SIZE,
                                (uint8_t *) &assetBlob,
                                CC_ASSET_PROV_ADATA_SIZE,
                                asset,
                                assetSize,
                                (uint8_t *) assetBlob.encAsset,
                                ((uint8_t *) assetBlob.encAsset) + assetSize,
                                CC_ASSET_PROV_TAG_SIZE);
    if (rc != 0) {
        UTIL_LOG_ERR("failed to CC_CommonAesCmacEncrypt() for Kprov, rc %d\n", rc);
        rc = (-1);
        goto end_func;
    }

    // Writing the asset BLOB into bin file
    rc = CC_CommonUtilCopyBuffToBinFile(pBlobFileName, (uint8_t *) &assetBlob, assetBlobSize);
    if (rc != 0) {
        UTIL_LOG_ERR("failed to CC_CommonUtilCopyBuffToBinFile(), rc %d\n", rc);
        rc = (-1);
        goto end_func;
    }

    rc = 0;
end_func:
    CloseOpenSsl();
    return rc;
}
