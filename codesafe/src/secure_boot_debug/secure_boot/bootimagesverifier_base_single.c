/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#define CC_PAL_LOG_CUR_COMPONENT CC_LOG_MASK_SECURE_BOOT

/************* Include Files ****************/
#include "secureboot_error.h"
#include "bootimagesverifier_error.h"
#include "bootimagesverifier_def.h"
#include "bootimagesverifier_parser.h"
#include "secureboot_base_func.h"
#include "secureboot_base_swimgverify.h"
#include "cc_pal_log.h"
#include "secureboot_defs.h"
#include "secdebug_defs.h"
#include "secboot_cert_defs.h"
#include "bootimagesverifier_swcomp.h"
#include "common_cert_verify.h"

/************************ Defines ******************************/


/************************ Enums ******************************/


/************************ Typedefs ******************************/


/************************ Global Data ******************************/

/************************ Private functions  ******************************/

/************************ Public functions  ******************************/

/* Trust in Soft annotations - __TRUSTINSOFT_ANALYZER__ */
/*@
    requires \valid((uint8_t*)certPkgInfo + (0 .. sizeof(CCSbCertInfo_t) - 1));
*/
CCError_t CC_SbCertChainVerificationInit(CCSbCertInfo_t *certPkgInfo)
{
    if (certPkgInfo == NULL) {
        return CC_BOOT_IMG_VERIFIER_INV_INPUT_PARAM;
    }
    /*clear the external hash */
    UTIL_MemSet((uint8_t *)&(certPkgInfo->pubKeyHash), 0x0, sizeof(certPkgInfo->pubKeyHash));
    certPkgInfo->initDataFlag = 0;


    return CC_OK;
}


/**
   @brief This function
   loadSbCert() loads the certificate from Flash to RAM
        if called first time, expected certificate is key certificate
        else, if second time, expected is key or content certificate
        else, if third, expected is content.
   Call CCCommonCertVerify(expected types) to verify common certificate fields,
        and returns pointers to certificate proprietary header, and body.
   If certificate type in proprietary header is key, call CCCommonKeyCertVerify(), to verify key certificate fields.
   Otherwise, call CCCommonContentCertVerify(), to verify Content certificate fields.
 */
/* Trust in Soft annotations - __TRUSTINSOFT_ANALYZER__ */
/*@
    requires \valid((uint8_t*)hwBaseAddress + (0 .. CC_REG_AREA_SIZE - 1));
    requires certSrcAddress != 0;
    requires \valid((uint8_t*)pWorkspace + (0 .. workspaceSize - 1));
*/
CCError_t CC_SbCertVerifySingle(CCSbFlashReadFunc flashReadFunc,
                                void *userContext,
                                unsigned long hwBaseAddress,
                                CCAddr_t certSrcAddress,
                                CCSbCertInfo_t *pCertPkgInfo,
                                CCSbX509TBSHeader_t *pX509Header,
                                uint32_t *pWorkspace,
                                uint32_t workspaceSize,
                                CCSbImagesInfo_t *pImagesInfo,
                                CCSbUserAddData_t *pUserData)
{
    CCError_t 	rc = CC_OK;
    uint32_t	certLoadWordSize;
    CertFieldsInfo_t  certFields;
    BufferInfo32_t  workspaceInfo;
    BufferInfo32_t  certInfo;

#ifndef CC_CONFIG_BSV_CERT_WITH_USER_ADDITIONAL_DATA
    CC_UNUSED_PARAM(pUserData);
#endif

    /* 1. Verify input parameters */
    /*----------------------------*/
    if ((flashReadFunc == NULL) ||
        (pCertPkgInfo == NULL) ||
        (pWorkspace == NULL) ||
        (workspaceSize == 0) ||
        ((unsigned long)pWorkspace + workspaceSize < (unsigned long)pWorkspace) ||   /* Verify no overflow in workspace */
        (workspaceSize < CC_SB_MIN_WORKSPACE_SIZE_IN_BYTES) ||
        (!IS_ALIGNED(workspaceSize, sizeof(uint32_t))) ||
        (!IS_ALIGNED(pWorkspace, sizeof(uint32_t)))) {
        CC_PAL_LOG_ERR("illegal params \n");
        rc = CC_BOOT_IMG_VERIFIER_INV_INPUT_PARAM;
        goto FinalCleaning;
    }

#ifdef CC_CONFIG_BSV_CERT_WITH_USER_ADDITIONAL_DATA
    if (pUserData == NULL) {
        CC_PAL_LOG_ERR("illegal Add params \n");
        rc = CC_BOOT_IMG_VERIFIER_INV_INPUT_PARAM;
        goto FinalCleaning;
    }
#endif

    if (CC_SB_MAX_CERT_SIZE_IN_BYTES < CC_SB_MAX_CONTENT_PKG_SIZE_IN_BYTES) {
        CC_PAL_LOG_ERR("CC_SB_MAX_CERT_SIZE_IN_BYTES \n");
        rc = CC_BOOT_IMG_VERIFIER_INV_INPUT_PARAM;
        goto FinalCleaning;
    }

    UTIL_MemSet((uint8_t *)&certFields, 0, sizeof(CertFieldsInfo_t));
    /* Clearing the RAM just to verify that there is no secret data on it, before starting to process certificate */
    UTIL_MemSet((uint8_t *)pWorkspace, 0, workspaceSize);

    if(pImagesInfo != NULL){
        /* Clear returned images info list */
        pImagesInfo->numOfImages = 0;
        UTIL_MemSet((uint8_t *)&(pImagesInfo->imagesList), 0, sizeof(VerifiedImagesList_t));
    }

    /* 2. Load the certificate from the Flash */
    /*----------------------------------------*/
    /* Set the maximum certificate size, and get back the current certificate size.
           The certificate to load is 32 bit aligned */
    certLoadWordSize = (CC_SB_MAX_CERT_SIZE_IN_BYTES / CC_32BIT_WORD_SIZE);
    rc = CCCertLoadCertificate(flashReadFunc,
                               userContext,
                               certSrcAddress,
                               pWorkspace,
                               &certLoadWordSize);
    if (rc != CC_OK) {
        CC_PAL_LOG_ERR("CCCertParserLoadCertificate  returned 0x%X\n", (unsigned int)rc);
        goto End;
    }

    /* workspace order:
           [0]	certificate
            [certificate size]   if content certificate - additional data for images and addresses
           [end of workspace]	N+Np+Signature  OR images information */
    certInfo.pBuffer =  pWorkspace;

    /* Set expected certificate type according to the certificate place in chain - first key ,
           second key or content, third content. Maximal size in content certificate is calculated according to
           MAX number of possible SW images.*/
    switch (pCertPkgInfo->initDataFlag) {
        case CC_SB_FIRST_CERT_IN_CHAIN:
            certFields.certType = CC_SB_KEY_CERT;
            certFields.certBodySize = sizeof(KeyCertMain_t);
            certInfo.bufferSize = CC_SB_MAX_KEY_CERT_SIZE_IN_BYTES;
            break;
        case CC_SB_SECOND_CERT_IN_CHAIN:
            certFields.certType = CC_SB_KEY_OR_CONTENT_CERT;
            certFields.certBodySize = CONTENT_CERT_MAIN_SIZE_IN_BYTES;
            certInfo.bufferSize = CC_SB_MAX_CONTENT_CERT_SIZE_IN_BYTES;
            break;
        case CC_SB_THIRD_CERT_IN_CHAIN:
            certFields.certType = CC_SB_CONTENT_CERT;
            certFields.certBodySize = CONTENT_CERT_MAIN_SIZE_IN_BYTES;
            certInfo.bufferSize = CC_SB_MAX_CONTENT_CERT_SIZE_IN_BYTES;
            break;
        default:
            CC_PAL_LOG_ERR("Not expecting any certificate in the chain \n");
            rc = CC_BOOT_IMG_VERIFIER_INV_INPUT_PARAM;
            goto End;
    }

    // set the workspace for N, Np and signature
    workspaceInfo.bufferSize = sizeof(BsvPssVerifyWorkspace_t);
    workspaceInfo.pBuffer = (uint32_t *)((unsigned long)pWorkspace + workspaceSize - sizeof(BsvPssVerifyWorkspace_t));

    /* 3. Verify the certificate (Verify the RSA signature and the public key hash) . */
    rc = CCCommonCertVerify(hwBaseAddress,
                            &certInfo,
                            &certFields,
                            pCertPkgInfo,
                            &workspaceInfo,
                            pX509Header,
                            pUserData);
    if (rc != CC_OK) {
        CC_PAL_LOG_ERR("CCCommonCertVerify failed 0x%X\n", (unsigned int)rc);
        goto End;
    }


    /* 4. In case of content certificate - verify the SW images */
    /*----------------------------------------------------------*/
    switch (certFields.certType) {
        case CC_SB_KEY_CERT:
            /* Verify the key certificate NV counter. */
            rc = CCCommonKeyCertVerify(hwBaseAddress,
                                       certFields.pCertBody,
                                       pCertPkgInfo);
            /* Update the certificate number in the chain.*/
            pCertPkgInfo->initDataFlag++;
            break;
        case CC_SB_CONTENT_CERT:
            if(pImagesInfo == NULL){
                return CC_BOOT_IMG_VERIFIER_INV_INPUT_PARAM;
            }

            /* Verify the content certificate NV counter and verify the SW images. If needed update the NV counter in the OTP.
                  workspaceInfo may overlap with N+Np+Signature, since N, Np and signature were already verified */
            workspaceInfo.pBuffer = pWorkspace + certLoadWordSize;
            workspaceInfo.bufferSize = workspaceSize - (certLoadWordSize * CC_32BIT_WORD_SIZE);
            rc = CCCommonContentCertVerify(flashReadFunc,
                                           userContext,
                                           hwBaseAddress,
                                           certSrcAddress + (certLoadWordSize * CC_32BIT_WORD_SIZE),
                                           pCertPkgInfo,
                                           certFields.certHeader.certFlags,
                                           certFields.pCertBody,
                                           &workspaceInfo,
                                           pImagesInfo);
            /* the content certificate is always the last. */
            pCertPkgInfo->initDataFlag = CC_SB_LAST_CERT_IN_CHAIN;
            break;
        default:
            CC_PAL_LOG_ERR("Illegal certificate type for secure boot flow.\n");
            rc = CC_BOOT_IMG_VERIFIER_INV_INPUT_PARAM;
            goto End;
    }

    End:
    /* Clear data workspace in RAM (erase footprint always) */
    UTIL_MemSet((uint8_t *)pWorkspace, 0, workspaceSize);

    FinalCleaning:
    /* Clear image table in case of error */
    if ((pImagesInfo != NULL) && (rc != CC_OK)) {
        pImagesInfo->numOfImages = 0;
        UTIL_MemSet((uint8_t *)&(pImagesInfo->imagesList), 0, sizeof(VerifiedImagesList_t));
    }

#ifdef CC_CONFIG_BSV_CERT_WITH_USER_ADDITIONAL_DATA
    if ((rc != CC_OK) && (pUserData != NULL)) {
        /* Clear additional data in case of error */
        UTIL_MemSet((uint8_t *)pUserData, 0, sizeof(CCSbUserAddData_t));
    }
#endif

    return rc;

} /* End of CC_SbCertVerifySingle */

/* Trust in Soft annotations - __TRUSTINSOFT_ANALYZER__ */
/*@
    requires address != 0;
*/
CCError_t CC_SbSwImageStoreAddrChange(uint32_t *pCert, uint32_t maxCertSizeWords, CCAddr_t address, uint32_t indexOfAddress)
{
#ifdef CC_SB_X509_CERT_SUPPORTED
    CC_UNUSED_PARAM(pCert);
    CC_UNUSED_PARAM(maxCertSizeWords);
    CC_UNUSED_PARAM(address);
    CC_UNUSED_PARAM(indexOfAddress);

    return CC_BOOT_IMG_VERIFIER_NO_SUPPORTED_ERR;
#else

    CCError_t error = CC_OK;
    CCSbCertTypes_t certType = CC_SB_CONTENT_CERT;
    uint32_t numOfComps = 0, offsetToSwCompsData = 0, certConstSize = 0;
    uint32_t *pCurrRecAddInfo = NULL;
    CCSbCertHeader_t* pCertHeader = NULL;
    CCSbCertFlags_t flags;

    /* Check inputs */
    if (pCert == NULL){
        CC_PAL_LOG_DEBUG("pCert is NULL\n");
        return CC_BOOT_IMG_VERIFIER_INV_INPUT_PARAM;
    }

    /* Verify that the certificate buffer size is big enough to contain the header */
    if (maxCertSizeWords < (sizeof(CCSbCertHeader_t) / CC_32BIT_WORD_SIZE)) {
            CC_PAL_LOG_ERR("certificate buff size too small to contain certificate header\n");
            return CC_BOOT_IMG_VERIFIER_WORKSPACE_SIZE_TOO_SMALL;
    }
    pCertHeader = (CCSbCertHeader_t*)pCert;

    /* verify the certificate header */
    error = CCCertValidateHeader(pCertHeader, &certType);
    if (error != CC_OK){
        return error;
    }

    if (certType != CC_SB_CONTENT_CERT){
        CC_PAL_LOG_DEBUG("Certificate type incorrect %d\n", certType);
        return CC_BOOT_IMG_VERIFIER_INCORRECT_CERT_TYPE;
    }

    /* Get the number of SW components from the header certSize field */
    flags.flagsWord = pCertHeader->certFlags;
    numOfComps = flags.flagsBits.numOfSwCmp;
    if ((numOfComps > CC_SB_MAX_NUM_OF_IMAGES) ||
        (numOfComps == 0)) {
        CC_PAL_LOG_DEBUG("Content certificate has no SW components!\n");
        return CC_BOOT_IMG_VERIFIER_INV_INPUT_PARAM;
    }
    if (indexOfAddress > (numOfComps-1)) {
        CC_PAL_LOG_DEBUG("Invalid index\n");
        return CC_BOOT_IMG_VERIFIER_INV_INPUT_PARAM;
    }

    /* calculate the size of the signed data in words */
    certConstSize = (uint32_t)(pCertHeader->certSize & CERT_LEN_SIGNATURE_OFFSET_BIT_MASK) /* signature offset */
                    + sizeof(CCSbSignature_t)/sizeof(uint32_t); /* signature */

    /* check certificate memory boundaries (includes SW none signed data) */
    if ( (certConstSize + numOfComps*SW_REC_NONE_SIGNED_DATA_SIZE_IN_WORDS) > maxCertSizeWords){
        return CC_BOOT_IMG_VERIFIER_INV_INPUT_PARAM;
    }

    /* Point to the relevant address */
    offsetToSwCompsData = certConstSize + indexOfAddress*SW_REC_NONE_SIGNED_DATA_SIZE_IN_WORDS;
    pCurrRecAddInfo = pCert + offsetToSwCompsData;
    if (pCurrRecAddInfo < pCert){
        return CC_BOOT_IMG_VERIFIER_INV_INPUT_PARAM;
    }

    CC_PAL_LOG_DEBUG("current address is 0x%llx, new address is 0x%llx\n", (CCImageAddrWidth_t)(*pCurrRecAddInfo), address);
    UTIL_MemCopy((uint8_t*)pCurrRecAddInfo, (uint8_t*)&address, sizeof(CCImageAddrWidth_t));

    return CC_OK;
#endif
}

CCError_t CC_SbGetCertSize(CCSbCertChainType_t chainType, uint32_t *pCert, uint32_t *pCertSizeWords)
{
#ifdef CC_SB_X509_CERT_SUPPORTED
    CC_UNUSED_PARAM(chainType);
    CC_UNUSED_PARAM(pCert);
    CC_UNUSED_PARAM(pCertSizeWords);

    return CC_BOOT_IMG_VERIFIER_NO_SUPPORTED_ERR;
#else

    CCError_t error = CC_OK;
    CCSbCertTypes_t certType = CC_SB_KEY_OR_CONTENT_CERT;
    CCSbCertHeader_t* pCertHeader = NULL;
    uint32_t sizeOfCert = 0, maxSizeOfCert = 0;
    uint32_t numOfComps = 0;
    CCSbCertFlags_t flags;

    /* Check inputs */
    if ((chainType != CC_SECURE_BOOT_CHAIN) && (chainType != CC_SECURE_DEBUG_CHAIN)) {
        CC_PAL_LOG_DEBUG("chainType is incorrect\n");
        return CC_BOOT_IMG_VERIFIER_INV_INPUT_PARAM;
    }
    if (pCert == NULL){
        CC_PAL_LOG_DEBUG("pCert is NULL\n");
        return CC_BOOT_IMG_VERIFIER_INV_INPUT_PARAM;
    }
    if (pCertSizeWords == NULL){
        CC_PAL_LOG_DEBUG("pCertSizeWords is NULL\n");
        return CC_BOOT_IMG_VERIFIER_INV_INPUT_PARAM;
    }

    /* Verify that the size given is at least header size */
    if (*pCertSizeWords < sizeof(CCSbCertHeader_t)/sizeof(uint32_t)) {
        CC_PAL_LOG_DEBUG("pCertSizeWords is smaller than certificate header size\n");
        return CC_BOOT_IMG_VERIFIER_INV_INPUT_PARAM;
    }

    pCertHeader = (CCSbCertHeader_t*)pCert;

    /* Case of Secure Boot chain */
    if (chainType == CC_SECURE_BOOT_CHAIN) {

        /* Verify magic number */
        switch (pCertHeader->magicNumber) {
            case CC_SB_KEY_CERT_MAGIC_NUMBER:
                certType = CC_SB_KEY_CERT;
                break;
            case CC_SB_CONTENT_CERT_MAGIC_NUMBER:
                certType = CC_SB_CONTENT_CERT;
                break;
            default:
                CC_PAL_LOG_DEBUG("Certificate Magic number incorrect\n");
                return CC_BOOT_IMG_VERIFIER_CERT_MAGIC_NUM_INCORRECT;
        }

        /* Validate certificate header */
        error = CCCertValidateHeader(pCertHeader, &certType);
        if (error != CC_OK){
            return error;
        }

        /* Verify certificate type */
        switch (certType){
            case CC_SB_KEY_CERT:
                sizeOfCert = CC_SB_MAX_KEY_CERT_SIZE_IN_BYTES/sizeof(uint32_t);
                break;
            case CC_SB_CONTENT_CERT:
                /* Calculate the size of the signed data in words */
                sizeOfCert = (uint32_t)(pCertHeader->certSize & CERT_LEN_SIGNATURE_OFFSET_BIT_MASK) /* signature offset */
                                + sizeof(CCSbSignature_t)/sizeof(uint32_t); /* signature */
                /* Get the number of SW components from the header certSize field */
                flags.flagsWord = pCertHeader->certFlags;
                numOfComps = flags.flagsBits.numOfSwCmp;
                if ((numOfComps > CC_SB_MAX_NUM_OF_IMAGES) || (numOfComps == 0)) {
                    CC_PAL_LOG_DEBUG("Content certificate has incorrect number of SW components!\n");
                    return CC_BOOT_IMG_VERIFIER_ILLEGAL_NUM_OF_IMAGES;
                }
                /* Add the size of unsigned data in words */
                sizeOfCert = sizeOfCert + numOfComps*SW_REC_NONE_SIGNED_DATA_SIZE_IN_WORDS;
                maxSizeOfCert = CC_SB_MAX_CONTENT_PKG_SIZE_IN_BYTES/sizeof(uint32_t);
                /* verify the calculated size is less than maximal certificate size */
                if (sizeOfCert > maxSizeOfCert) {
                    CC_PAL_LOG_DEBUG("Certificate size incorrect\n");
                    return CC_BOOT_IMG_VERIFIER_INV_INPUT_PARAM;
                }
                break;
            default:
                CC_PAL_LOG_DEBUG("Certificate type incorrect\n");
                return CC_BOOT_IMG_VERIFIER_INCORRECT_CERT_TYPE;
        }
    }

    /* Case of Secure Debug chain */
    else {

        /* Verify magic number */
        switch (pCertHeader->magicNumber) {
            case CC_SB_KEY_CERT_MAGIC_NUMBER:
                certType = CC_SB_KEY_CERT;
                break;
            case CC_CERT_SEC_DEBUG_ENABLER_MAGIC:
                certType = CC_SB_ENABLER_CERT;
                break;
            default:
                CC_PAL_LOG_DEBUG("Certificate Magic number incorrect\n");
                return CC_BOOT_IMG_VERIFIER_CERT_MAGIC_NUM_INCORRECT;
        }

        /* Validate certificate header */
        error = CCCertValidateHeader(pCertHeader, &certType);
        if (error != CC_OK){
            return error;
        }

        /* Verify certificate type */
        switch (certType){
            case CC_SB_KEY_CERT:
                sizeOfCert = (CC_SB_MAX_KEY_CERT_SIZE_IN_BYTES+CC_SB_MAX_ENABLER_CERT_SIZE_IN_BYTES+CC_SB_MAX_DEVELOPER_CERT_SIZE_IN_BYTES)/sizeof(uint32_t);
                break;
            case CC_SB_ENABLER_CERT:
                sizeOfCert = (CC_SB_MAX_ENABLER_CERT_SIZE_IN_BYTES+CC_SB_MAX_DEVELOPER_CERT_SIZE_IN_BYTES)/sizeof(uint32_t);
                break;
            default:
                CC_PAL_LOG_DEBUG("Certificate type incorrect\n");
                return CC_BOOT_IMG_VERIFIER_INCORRECT_CERT_TYPE;
        }
    }

    *pCertSizeWords = sizeOfCert;
    return CC_OK;
#endif
}


