/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include "secureboot_stage_defs.h"
#include "common_cert_verify.h"
#include "bootimagesverifier_def.h"
#include "secureboot_base_func.h"
#include "bootimagesverifier_def.h"
#include "bootimagesverifier_error.h"
#include "bootimagesverifier_parser.h"
#include "secboot_cert_defs.h"
#include "secdebug_defs.h"

const uint32_t certMagicNumber[CC_SB_MAX_CERT] = {
        /* No enum */			0,
        /*  CC_SB_KEY_CERT       */	CC_SB_KEY_CERT_MAGIC_NUMBER,
        /*  CC_SB_CONTENT_CERT   */	CC_SB_CONTENT_CERT_MAGIC_NUMBER,
        0,
        /*  CC_SB_ENABLER_CERT   */	CC_CERT_SEC_DEBUG_ENABLER_MAGIC,
        /*  CC_SB_DEVELOPER_CERT */	CC_CERT_SEC_DEBUG_DEVELOPER_MAGIC
};

const uint32_t certMainMaxSize[CC_SB_MAX_CERT] = {
        /* No enum */			      0,
        /*  CC_SB_KEY_CERT       */(CC_SB_MAX_KEY_CERT_SIZE_IN_BYTES - CC_SB_MAX_CERT_SIGN_SIZE_IN_BYTES),
        /*  CC_SB_CONTENT_CERT   */(CC_SB_MAX_CONTENT_CERT_SIZE_IN_BYTES - CC_SB_MAX_CERT_SIGN_SIZE_IN_BYTES),
        0,
        /*  CC_SB_ENABLER_CERT   */(CC_SB_MAX_ENABLER_CERT_SIZE_IN_BYTES - CC_SB_MAX_CERT_SIGN_SIZE_IN_BYTES),
        /*  CC_SB_DEVELOPER_CERT */(CC_SB_MAX_DEVELOPER_CERT_SIZE_IN_BYTES - CC_SB_MAX_CERT_SIGN_SIZE_IN_BYTES)
};


uint32_t hbkId2HashSizeWords[] = {
        /* CC_SB_HASH_BOOT_KEY_0_128B */  CC_BSV_128B_HASH_SIZE_IN_WORDS,
        /* CC_SB_HASH_BOOT_KEY_1_128B */  CC_BSV_128B_HASH_SIZE_IN_WORDS,
        /* CC_SB_HASH_BOOT_KEY_256B   */ CC_BSV_256B_HASH_SIZE_IN_WORDS,
};


static CCError_t readPubKeyHash(unsigned long hwBaseAddress, CCSbPubKeyIndexType_t keyIndex, CCHashResult_t PubKeyHASH, uint32_t hashSizeInWords)
{
    CCError_t error = CC_OK;
    uint32_t i;
    uint32_t lcs;

    /* Check input variables */
    if (PubKeyHASH == NULL)
        return CC_BOOT_IMG_VERIFIER_INV_INPUT_PARAM;

    /* Get LCS from register */
    error = CC_BsvLcsGet(hwBaseAddress, &lcs);
    if (error != CC_OK) {
        return error;
    }

    if ( (lcs == CC_BSV_CHIP_MANUFACTURE_LCS) ||
            (lcs == CC_BSV_RMA_LCS) ){
        return CC_BOOT_IMG_VERIFIER_SKIP_PUBLIC_KEY_VERIFY;
    }

    error = CC_BsvPubKeyHashGet(hwBaseAddress, keyIndex, PubKeyHASH, hashSizeInWords);
    /* Secure Boot should skip verification of the Certificate key against OTP memory when public key hash is not programmed yet (in CM or DM). */
    if (error == CC_BSV_HASH_NOT_PROGRAMMED_ERR){
        return CC_BOOT_IMG_VERIFIER_SKIP_PUBLIC_KEY_VERIFY;
    }

    if (error == CC_OK){
        /* All key and digest fields are stored in OTP in little-endian format */
        for (i=0; i < hashSizeInWords; i++) {
            PubKeyHASH[i] = UTIL_REVERT_UINT32_BYTES( PubKeyHASH[i] );
        }
    }

    return error;
}

static CCError_t verifyCertPubKeyAndSign(unsigned long hwBaseAddress,
                                         uint32_t    *pCert,
                                         size_t      certSize,
                                         CCSbCertInfo_t  *pSbCertInfo,
                                         BsvPssVerifyWorkspace_t  *pWorkspaceInt)
{
    CCError_t rc = CC_OK;
    uint32_t  expPubKeyHashSizeWords;
    CCHashResult_t    expPubKeyHash;

    if (pSbCertInfo->initDataFlag != CC_SB_FIRST_CERT_IN_CHAIN) { // not first certificate in chain
        expPubKeyHashSizeWords = sizeof(CCHashResult_t) / CC_32BIT_WORD_SIZE;
        UTIL_MemCopy((uint8_t *)expPubKeyHash, (uint8_t *)pSbCertInfo->pubKeyHash, expPubKeyHashSizeWords * CC_32BIT_WORD_SIZE);
    } else { // meaning this is first certificate in chain
        expPubKeyHashSizeWords = hbkId2HashSizeWords[pSbCertInfo->keyIndex];
        rc = readPubKeyHash(hwBaseAddress,
                            pSbCertInfo->keyIndex,
                            expPubKeyHash,
                            expPubKeyHashSizeWords);
        if (rc != CC_OK) {
            // if HBK not programed yet, skip HBK verify, but continue verifying the certificate
            if (rc == CC_BOOT_IMG_VERIFIER_SKIP_PUBLIC_KEY_VERIFY) {
                expPubKeyHashSizeWords = 0;
            } else {
                CC_PAL_LOG_ERR("Failed readPubKeyHash 0x%x", (unsigned int)rc);
                return rc;
            }
        }
    }

    /* Verify  public key hash only if expectedSize > 0 */
    if (expPubKeyHashSizeWords > 0) {
        rc = CCSbCalcPublicKeyHASHAndCompare(hwBaseAddress,
                                             (uint32_t *)&pWorkspaceInt->rsaExponentWs.pNparams,
                                             expPubKeyHash,
                                             expPubKeyHashSizeWords * CC_32BIT_WORD_SIZE);
        if (rc != CC_OK) {
            CC_PAL_LOG_ERR("CCSbCalcPublicKeyHASHAndCompare failed 0x%x\n", (unsigned int)rc);
            return rc;
        }
    }

    /* Verify the certificate signature */
    rc = CCSbVerifySignature(hwBaseAddress,
                             pCert,
                             (CCSbNParams_t *)(&pWorkspaceInt->rsaExponentWs.pNparams),
                             (CCSbSignature_t *)pWorkspaceInt->rsaExponentWs.pDataIn,
                             certSize,
                             RSA_PSS_3072,
                             (uint32_t *)(&pWorkspaceInt->pssVerWs),
                             sizeof(BsvPssVerifyIntWorkspace_t));
    if (rc != CC_OK) {
        CC_PAL_LOG_ERR("CCSbVerifySignature failed 0x%x\n", (unsigned int)rc);
        return rc;
    }

    return CC_OK;

}

/* The function validates the certificate header - Magic number , type and version. */
CCError_t CCCertValidateHeader(CCSbCertHeader_t *pCertHeader,
                                      CCSbCertTypes_t *pCertType)
{
    uint32_t expVersion;
    CCSbCertTypes_t certType = CC_SB_MAX_CERT;
    uint32_t i = 0;

    /* Verify Magic number, and get certificate type out of it */
    /*---------------------*/
    if (pCertHeader->magicNumber == 0) {
        CC_PAL_LOG_ERR("certificate magic number is incorrect \n");
        return CC_BOOT_IMG_VERIFIER_INCORRECT_CERT_TYPE;
    }

    for (i = CC_SB_MIN_CERT + 1; i < CC_SB_MAX_CERT; i++) {
        if (pCertHeader->magicNumber == certMagicNumber[i]) {
            certType = (CCSbCertTypes_t)i;
            break;
        }
    }

    if (certType == CC_SB_MAX_CERT) {
        CC_PAL_LOG_ERR("certificate type not found %d\n", certType);
        return CC_BOOT_IMG_VERIFIER_INCORRECT_CERT_TYPE;
    }

    if ((certType != *pCertType) &&
        ((*pCertType != CC_SB_KEY_OR_CONTENT_CERT) || ((certType != CC_SB_CONTENT_CERT) && (certType != CC_SB_KEY_CERT)))) {
        CC_PAL_LOG_ERR("certificate type is incorrect %d exp 0x%x\n", certType, *pCertType);
        return CC_BOOT_IMG_VERIFIER_INCORRECT_CERT_TYPE;
    }

    /* Verify certificate version */
    /*----------------------------*/
    expVersion = (CC_SB_CERT_VERSION_PROJ_PRD << CERT_VERSION_PROJ_PRD_BIT_SHIFT) | \
                 (CC_SB_CERT_VERSION_MAJOR << CERT_VERSION_MAJOR_BIT_SHIFT) | \
                  CC_SB_CERT_VERSION_MINOR;

    if (pCertHeader->certVersion != expVersion) {
        CC_PAL_LOG_ERR("Certificate version incorrect, expVersion 0x%x, pCertHeader->certVersion 0x%x\n",
                       (unsigned int)expVersion, (unsigned int)(pCertHeader->certVersion));
        return CC_BOOT_IMG_VERIFIER_CERT_VERSION_NUM_INCORRECT;
    }

    // set the actual certificate type
    *pCertType = certType;
    return CC_OK;

}



/**
   @brief This function is basic verification for all secure boot/debug certificates.
   it verifies type, size, public key and signature.
   Return pointers to certificate proprietary header, and body.
   Workspace should be clear when function returns
        call CCCertFieldsParse() - according to certificate type(x509 or not),
                copy public key, Np and signature to workspace,
                and returns pointers to certificate proprietary header, and body.
        call CCCertValidateHeader(), and verify cert type (as expected) and size (according to type).
        If expected public key hash is NULL, call CC_BsvPubKeyHashGet() with HBK type defined in certificate to get OTP HBK
        Call verifyCertPubKeyAndSign() To verify public key and certificate signature.
                Public key is verified against the expected value, and N and Np and signature resides on workspace.

 */
CCError_t CCCommonCertVerify(unsigned long   hwBaseAddress,
                             BufferInfo32_t  *pCertInfo,
                             CertFieldsInfo_t  *pCertFields,  // in/out
                             CCSbCertInfo_t  *pSbCertInfo,   //in/out
                             BufferInfo32_t  *pWorkspaceInfo,
                             CCSbX509TBSHeader_t  *pX509HeaderInfo,
                             CCSbUserAddData_t  *pUserAddData) //in/out
{
    uint32_t    	rc = 0;
    uint32_t    	certSignedSize = 0;
    keyCertFlags_t  certFlag;
    uint32_t	*pCertStartSign;
    BsvPssVerifyWorkspace_t *lpWorkspace;
    BufferInfo32_t  rsaWorkspaceInfo;
    CCSbPubKeyIndexType_t   keyIndex;

#ifndef CC_CONFIG_BSV_CERT_WITH_USER_ADDITIONAL_DATA
    CC_UNUSED_PARAM(pUserAddData);
#endif

    if ((pWorkspaceInfo == NULL) ||
            (pWorkspaceInfo->pBuffer == NULL) ||
            (pWorkspaceInfo->bufferSize < sizeof(BsvPssVerifyWorkspace_t)) ||
            (!IS_ALIGNED(pWorkspaceInfo->bufferSize, sizeof(uint32_t))) ||
            (!IS_ALIGNED(sizeof(BsvPssVerifyWorkspace_t), sizeof(uint32_t)))
#ifdef CC_CONFIG_BSV_CERT_WITH_USER_ADDITIONAL_DATA
            || (pUserAddData == NULL)
#endif
    ){
        CC_PAL_LOG_ERR("workspace and or sizes illegal\n");
        return CC_BSV_ILLEGAL_INPUT_PARAM_ERR;
    }

    UTIL_MemSet((uint8_t *)pWorkspaceInfo->pBuffer, 0, pWorkspaceInfo->bufferSize);
    lpWorkspace = (BsvPssVerifyWorkspace_t *)pWorkspaceInfo->pBuffer;

    rsaWorkspaceInfo.bufferSize = sizeof(BsvRsaExponentWorkspace_t);
    rsaWorkspaceInfo.pBuffer = (uint32_t *)&lpWorkspace->rsaExponentWs;
    /* Parse the certificate fields to get pointers to the certificate internals */
    /*---------------------------------------------------------------------------*/
    rc = CCCertFieldsParse(pCertInfo,
                           &rsaWorkspaceInfo,
                           pCertFields,
                           &pCertStartSign,
                           &certSignedSize,
                           pX509HeaderInfo);
    if (rc != CC_OK) {
        CC_PAL_LOG_ERR("Failed CCCertFieldsParse 0x%x\n", (unsigned int)rc);
        goto end_with_error;
    }
    /* Verify Magic number, and version. returns the certificate type */
    /*----------------------------------------------------------------*/
    rc = CCCertValidateHeader(&pCertFields->certHeader, &pCertFields->certType);
    if (rc != CC_OK) {
        CC_PAL_LOG_ERR("Failed CCCertValidateHeader 0x%x\n", (unsigned int)rc);
        goto end_with_error;
    }

#ifdef CC_CONFIG_BSV_CERT_WITH_USER_ADDITIONAL_DATA
    /* return user additional data from certificate */
    UTIL_MemCopy((uint8_t *)pUserAddData, (uint8_t *)pCertFields->certHeader.userAddData, sizeof(CCSbUserAddData_t));
#endif

    // Verify certificate size. no need to verify the type again
    if (((pCertFields->certType == CC_SB_KEY_CERT) ||
            (pCertFields->certType == CC_SB_CONTENT_CERT) ||
            (pCertFields->certType == CC_SB_ENABLER_CERT) ||
            (pCertFields->certType ==  CC_SB_DEVELOPER_CERT)) &&
            (certSignedSize > certMainMaxSize[pCertFields->certType])) {
        CC_PAL_LOG_ERR("certSignedSize too big 0x%x for cert %d\n", (unsigned int)certSignedSize, (unsigned int)(pCertFields->certType));
        rc = CC_BOOT_IMG_VERIFIER_INCORRECT_CERT_SIZE;
        goto end_with_error;
    }

    certFlag.flagsWord = pCertFields->certHeader.certFlags;
    keyIndex = (CCSbPubKeyIndexType_t)(certFlag.flagsBits.hbkId);
    if (pSbCertInfo->initDataFlag == CC_SB_FIRST_CERT_IN_CHAIN) {
        /* For primary key: verify and store HBK ID */
        if (keyIndex > CC_SB_HASH_BOOT_KEY_256B) {
            CC_PAL_LOG_ERR("invalid hbkId %d", pSbCertInfo->keyIndex);
            rc = CC_BOOT_IMG_VERIFIER_ILLEGAL_HBK_IDX;
            goto end_with_error;
        }
        pSbCertInfo->keyIndex = keyIndex;
    }

#ifndef CC_IOT
    /* SB: GEN_CER-3: Each certificate shall include ... Root key type (HBK ID) */
    else {
        /* For secondary key / content: verify HBK ID against HBK ID of primary */
        if (((pCertFields->certType == CC_SB_KEY_CERT) || (pCertFields->certType == CC_SB_CONTENT_CERT)) &&
             (pSbCertInfo->keyIndex != keyIndex)) {
            return CC_BOOT_IMG_VERIFIER_ILLEGAL_HBK_IDX;
        }
    }
#endif

    /* Verify certificate public key and it's signature,  pCertStartSign is word aligned for propritery and x509*/
    /*--------------------------------------------------*/
    rc = verifyCertPubKeyAndSign(hwBaseAddress,
                                 (uint32_t *)pCertStartSign,
                                 certSignedSize,
                                 pSbCertInfo,
                                 lpWorkspace);
    if (rc != CC_OK) {
        CC_PAL_LOG_ERR("verifyCertPubKeyAndSign failed 0x%X\n", (unsigned int)rc);
        goto end_with_error;
    }

    goto end;

    end_with_error:
#ifdef CC_CONFIG_BSV_CERT_WITH_USER_ADDITIONAL_DATA
    if ((rc != CC_OK) &&
        (pUserAddData != NULL)) {
        UTIL_MemSet((uint8_t *)pUserAddData, 0, sizeof(CCSbUserAddData_t));
    }
#endif
    UTIL_MemSet((uint8_t *)pCertFields, 0, sizeof(CertFieldsInfo_t));
    end:
    UTIL_MemSet((uint8_t *)pWorkspaceInfo->pBuffer, 0, pWorkspaceInfo->bufferSize);
    return rc;
}


/**
   @brief This function verifies key certificate specific fields
        The header flags, NV counter according to HBK type
        Return next certificate public key hash.
 */
uint32_t CCCommonKeyCertVerify(unsigned long   hwBaseAddress,
                               uint8_t *pCertMain,
                               CCSbCertInfo_t *pCertPkgInfo)
{
    uint32_t       rc = 0;
    KeyCertMain_t certMain;

    /* Copy non-aligned certFields.pCertBody into aligned struct */
    UTIL_MemCopy((uint8_t *)&certMain, (uint8_t *)pCertMain, sizeof(KeyCertMain_t));

    /* Verify revocation counter version is valid */
    rc = CCSbVerifyNvCounter(hwBaseAddress, certMain.nvCounter, pCertPkgInfo);
    if (rc != CC_OK) {
            CC_PAL_LOG_ERR("CCSbVerifyNvCounter failed 0x%X\n", (unsigned int)rc);
            return rc;
    }
    if (pCertPkgInfo->initDataFlag == CC_SB_FIRST_CERT_IN_CHAIN) {
            pCertPkgInfo->nvCounter = certMain.nvCounter;
    }

    /* Set function output values */
    UTIL_MemCopy((uint8_t *)pCertPkgInfo->pubKeyHash, (uint8_t *)certMain.nextPubKeyHash, sizeof(CCHashResult_t));

    return CC_OK;
}
