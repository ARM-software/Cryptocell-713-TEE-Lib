/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


#define CC_PAL_LOG_CUR_COMPONENT CC_LOG_MASK_SECURE_BOOT

/************* Include Files ****************/
#include "bootimagesverifier_def.h"
#include "secureboot_error.h"
#include "bootimagesverifier_error.h"
#include "bootimagesverifier_parser.h"
#include "secureboot_stage_defs.h"
#include "bootimagesverifier_swcomp.h"
#include "secureboot_base_swimgverify.h"
#include "secureboot_base_func.h"
#include "secboot_cert_defs.h"
#include "cc_pal_log.h"

/************************ Defines ******************************/

/************************ Enums ******************************/

/************************ Typedefs ******************************/

/************************ Global Data ******************************/

/************************ Internal Functions ******************************/

/************************ Public Functions ******************************/

uint32_t CCCommonContentCertVerify(CCSbFlashReadFunc flashReadFunc,
                                   void *userContext,
                                   unsigned long hwBaseAddress,
                                   CCAddr_t certSrcAddress,
                                   CCSbCertInfo_t *certPkgInfo,
                                   uint32_t certFlags,
                                   uint8_t  *pCertMain,
                                   BufferInfo32_t  *pWorkspaceInfo,
                                   CCSbImagesInfo_t *pImagesInfo)
{
        CCError_t rc = CC_OK;
        CCSbCertParserSwCompsInfo_t swImagesData;
        /* Content additional data is always word aligned*/
        uint32_t *pSwImagesAddData;
        uint32_t sizeOfNonSignedCert = 0;
        uint32_t numOfImages = 0;
        CCSbCertFlags_t flags;
        uint32_t nvCounter;


        /* 1. Get the number of sw components from the header flags field */
        flags.flagsWord = certFlags;
        numOfImages = flags.flagsBits.numOfSwCmp;
        if ((numOfImages > CC_SB_MAX_NUM_OF_IMAGES) ||
            (numOfImages == 0)) {
                return CC_BOOT_IMG_VERIFIER_ILLEGAL_NUM_OF_IMAGES;
        }
        pImagesInfo->numOfImages = numOfImages;

        /* 2. Load the extended data (unsigned data), in this stage the certificate is already verified. */
        sizeOfNonSignedCert = numOfImages * SW_REC_NONE_SIGNED_DATA_SIZE_IN_BYTES;
        if (sizeOfNonSignedCert > pWorkspaceInfo->bufferSize) {
                return CC_BOOT_IMG_VERIFIER_INV_INPUT_PARAM;
        }

        /* Read the Non-signed part of the certificate package from the Flash, and place it right after the certificate. */
        rc = flashReadFunc(certSrcAddress, (uint8_t *)pWorkspaceInfo->pBuffer, sizeOfNonSignedCert, userContext);
        if (rc != CC_OK) {
                CC_PAL_LOG_ERR("failed flashRead_func for Non-signed part\n");
                return rc;
        }
        pSwImagesAddData = pWorkspaceInfo->pBuffer;
        pWorkspaceInfo->bufferSize -= sizeOfNonSignedCert;
        pWorkspaceInfo->pBuffer += (sizeOfNonSignedCert / CC_32BIT_WORD_SIZE) + 1;

        /* 3. verify revocation version of the certificate
           Copy 4 bytes instead of accessing the struct field, since  pCertMain is not word aligned */
        UTIL_MemCopy((uint8_t *)&nvCounter, (uint8_t *)pCertMain, sizeof(uint32_t));
        rc = CCSbVerifyNvCounter(hwBaseAddress, nvCounter, certPkgInfo);
        if (rc != CC_OK) {
                CC_PAL_LOG_ERR("CCSbVerifyNvCounter failed\n");
                return rc;
        }

        /* 4. load and verify sw comps */
        swImagesData.swCodeEncType = (CCswCodeEncType_t)(flags.flagsBits.swCodeEncType);
        swImagesData.swLoadVerifyScheme = (CCswLoadVerifyScheme_t)(flags.flagsBits.swLoadVerifyScheme);
        swImagesData.swCryptoType = (CCswCryptoType_t)(flags.flagsBits.swCryptoType);
        swImagesData.numOfSwComps = (flags.flagsBits.numOfSwCmp);

        /* move the pointers for nonce and images by sizeof bytes instead of using struct fiels, since  pCertMain is not word aligned */
        UTIL_MemCopy((uint8_t *)swImagesData.nonce, (uint8_t *)(((unsigned long)pCertMain) + sizeof(uint32_t)), sizeof(CCSbNonce_t));
        swImagesData.pSwCompsData = (uint8_t *)(((unsigned long)pCertMain) + sizeof(uint32_t) + sizeof(CCSbNonce_t));

        rc = CCCertValidateSWComps(flashReadFunc,
                                   userContext,
                                   hwBaseAddress,
                                   certPkgInfo->keyIndex,
                                   &swImagesData,
                                   pSwImagesAddData,
                                   pWorkspaceInfo->pBuffer,
                                   pWorkspaceInfo->bufferSize,
                                   &(pImagesInfo->imagesList));
        if (rc != CC_OK) {
                CC_PAL_LOG_ERR("CCCertValidateSWComps failed\n");
                return rc;
        }
        /* 5. Assuming there is only one content certificate in the chain, */
        /*    Set the sw version in the OTP (if required)  */
        rc = CCSbUpdateNvCounter(hwBaseAddress, certPkgInfo);
        if (rc != CC_OK) {
                CC_PAL_LOG_ERR("CCSbUpdateNvCounter failed\n");
                return rc;
        }

        return CC_OK;
}



CCError_t CCCertValidateSWComps(CCSbFlashReadFunc flashRead_func,
				  void *userContext,
				  unsigned long hwBaseAddress,
				  CCSbPubKeyIndexType_t keyIndex,
				  CCSbCertParserSwCompsInfo_t *pSwImagesData,
				  uint32_t *pSwImagesAddData,
				  uint32_t *workspace_ptr,
				  uint32_t workspaceSize,
				  VerifiedImagesList_t *pImagesList)
{
	/* error variable */
	CCError_t error = CC_OK;

	/* internal index */
	uint32_t i = 0;

	/* internal pointer for the certificate main body, might not be word aligned */
	uint8_t *pSwRecSignedData = NULL;
	/* the non-signed part is always word aligned */
	uint32_t *pSwRecNoneSignedData = NULL;

	/* AES IV buffer */
	AES_Iv_t AESIv;
	uint8_t *nonce;
	CCswCodeEncType_t swCodeEncType;
	CCBsvKeyType_t  keyType;
	bsvCryptoMode_t cryptoMode;
	CCswCryptoType_t swCryptoType;
	CCswLoadVerifyScheme_t swLoadVerifyScheme;
	VerifiedImageInfo_t *pImageInfo;

	uint32_t lcs;

	uint8_t isLoadFromFlash;
	uint8_t isVerifyImage;
	ContentCertImageRecord_t cntImageRec;
	CCSbSwImgAddData_t  cntNonSignedImageRec;

	/*------------------
	    CODE
	-------------------*/

	pImageInfo = (VerifiedImageInfo_t *)pImagesList;

	/* Point to the s/w record signed data: hash, load address, max size, code enc */
	pSwRecSignedData = pSwImagesData->pSwCompsData;

	/* Point to the s/w record non-signed data: storage address, actual size */
	pSwRecNoneSignedData = pSwImagesAddData;

	nonce = pSwImagesData->nonce;
	swCodeEncType = pSwImagesData->swCodeEncType;
	swCryptoType = pSwImagesData->swCryptoType;
	swLoadVerifyScheme = pSwImagesData->swLoadVerifyScheme;

	/* Set default CC mode to Hash only (no encrypted images) */
	cryptoMode = BSV_CRYPTO_HASH;
	keyType = CC_BSV_END_OF_KEY_TYPE;

	/* Get LCS */
	error = CC_BsvLcsGet(hwBaseAddress, &lcs);
	if (error != CC_OK){
		return error;
	}

	switch(swLoadVerifyScheme){
	case CC_SB_LOAD_AND_VERIFY:
		isLoadFromFlash = CC_TRUE;
		isVerifyImage = CC_TRUE;
		break;
	case CC_SB_VERIFY_ONLY_IN_FLASH:
		isLoadFromFlash = CC_TRUE;
		isVerifyImage = CC_TRUE;
		break;
	case CC_SB_VERIFY_ONLY_IN_MEM:
		isLoadFromFlash = CC_FALSE;
		isVerifyImage = CC_TRUE;
		break;
	case CC_SB_LOAD_ONLY:
		isLoadFromFlash = CC_TRUE;
		isVerifyImage = CC_FALSE;
		/* Loading only is validate only in none secure lifecycle */
		if (lcs == CC_BSV_SECURE_LCS) {
			return CC_BOOT_IMG_VERIFIER_ILLEGAL_LCS_FOR_OPERATION_ERR;
		}
		break;
	default:
		return CC_BOOT_IMG_VERIFIER_INV_INPUT_PARAM;
	}

	/* Set AES key type */
	switch (swCodeEncType){
	case CC_SB_NO_IMAGE_ENCRYPTION:
		break;
	case CC_SB_ICV_CODE_ENCRYPTION:
		keyType = CC_BSV_ICV_CE_KEY;
		if ((keyIndex!=CC_SB_HASH_BOOT_KEY_0_128B) && (keyIndex!=CC_SB_HASH_BOOT_KEY_256B)){
			return CC_BOOT_IMG_VERIFIER_INV_INPUT_PARAM;
		}
		break;
	case CC_SB_OEM_CODE_ENCRYPTION:
		keyType = CC_BSV_CE_KEY;
		if ((keyIndex!=CC_SB_HASH_BOOT_KEY_1_128B) && (keyIndex!=CC_SB_HASH_BOOT_KEY_256B)){
			return CC_BOOT_IMG_VERIFIER_INV_INPUT_PARAM;
		}
		break;
	default:
		return CC_BOOT_IMG_VERIFIER_INV_INPUT_PARAM;
	}

	/* Case of encrypted SW image */
	if (swCodeEncType != CC_SB_NO_IMAGE_ENCRYPTION) {

		/* SB should fail if CE is needed in RMA lcs */
		if (lcs == CC_BSV_RMA_LCS) {
			return CC_BOOT_IMG_VERIFIER_ILLEGAL_LCS_FOR_OPERATION_ERR;
		}

		/* image can not be encrypted in case of "load only" or "verify in flash" */
		if ( (swLoadVerifyScheme == CC_SB_LOAD_ONLY) || (swLoadVerifyScheme == CC_SB_VERIFY_ONLY_IN_FLASH) ) {
			return CC_BOOT_IMG_VERIFIER_INV_INPUT_PARAM;
		}

		/* Set crypto mode */
		switch (swCryptoType){
		case CC_SB_HASH_ON_DECRYPTED_IMAGE:
			/* do AES decrypt on cipher image, and then do hash is done on plain image */
			cryptoMode = BSV_CRYPTO_AES_TO_HASH_AND_DOUT;
			break;
		case CC_SB_HASH_ON_ENCRYPTED_IMAGE:
			/* do AES decrypt and Hash on cipher image */
			cryptoMode = BSV_CRYPTO_AES_AND_HASH;
			break;
		default:
			return CC_BOOT_IMG_VERIFIER_INV_INPUT_PARAM;
		}

		/* Initiate AES IV with nonce data */
		UTIL_MemSet((uint8_t*)AESIv, 0, BSV_AES_IV_SIZE_IN_BYTES);
		UTIL_MemCopy((uint8_t*)&AESIv[0], nonce, CC_SB_MAX_SIZE_NONCE_BYTES);
	}

	/* Load and verify all images in the certificate */
	/*-----------------------------------------------*/
	for (i = 0; i < pSwImagesData->numOfSwComps; i++ ) {

        UTIL_MemCopy((uint8_t *)&cntImageRec, (uint8_t *)pSwRecSignedData, SW_REC_SIGNED_DATA_SIZE_IN_BYTES);
        UTIL_MemCopy((uint8_t *)&cntNonSignedImageRec, (uint8_t *)pSwRecNoneSignedData, SW_REC_NONE_SIGNED_DATA_SIZE_IN_BYTES);

		/* In case of encrypted image, set AES IV CTR */
		if ((isVerifyImage == CC_TRUE) && (keyType != CC_BSV_END_OF_KEY_TYPE)) {
#ifdef BIG__ENDIAN
			UTIL_MemCopy((uint8_t*)&AESIv[2], (uint8_t*)&cntImageRec.dstAddr, sizeof(CCImageAddrWidth_t));
#else
			UTIL_ReverseMemCopy((uint8_t*)&AESIv[2], (uint8_t*)&cntImageRec.dstAddr, sizeof(CCImageAddrWidth_t));
#endif
		}

		/* Validity source/destination memory addresses */
		if ( ((swLoadVerifyScheme == CC_SB_VERIFY_ONLY_IN_FLASH) && (cntImageRec.dstAddr != CC_SW_COMP_NO_MEM_LOAD_INDICATION)) ||
		     ((swLoadVerifyScheme != CC_SB_VERIFY_ONLY_IN_FLASH) && (cntImageRec.dstAddr == CC_SW_COMP_NO_MEM_LOAD_INDICATION)) ||
		     ((swLoadVerifyScheme == CC_SB_VERIFY_ONLY_IN_MEM) && (cntNonSignedImageRec.srcAddr != CC_SW_COMP_NO_MEM_LOAD_INDICATION)) ||
		     ((swLoadVerifyScheme != CC_SB_VERIFY_ONLY_IN_MEM) && (cntNonSignedImageRec.srcAddr == CC_SW_COMP_NO_MEM_LOAD_INDICATION)) ) {
		    return CC_BOOT_IMG_VERIFIER_INV_INPUT_PARAM;
		}

		/* Validate source memory boundaries */
		if ( (swLoadVerifyScheme != CC_SB_VERIFY_ONLY_IN_MEM) &&
		     (cntNonSignedImageRec.srcAddr + cntImageRec.imageSize < cntNonSignedImageRec.srcAddr) ) {
		    return CC_BOOT_IMG_VERIFIER_INV_INPUT_PARAM;
		}

		/* Validate destination memory boundaries */
		if ( (swLoadVerifyScheme != CC_SB_VERIFY_ONLY_IN_FLASH) &&
		     (cntImageRec.dstAddr + cntImageRec.imageSize < cntImageRec.dstAddr) ) {
		    return CC_BOOT_IMG_VERIFIER_INV_INPUT_PARAM;
		}

		/* Load and/or verify image as needed */
		error = _CCSbImageLoadAndVerify(flashRead_func, userContext,/* Flash Read function */
							 hwBaseAddress,		    /* CC base address */
							 isLoadFromFlash,		/* should image be copied from Flash with user callback */
							 isVerifyImage,			/* should image be verified with hash (and Aes if needed) */
							 cryptoMode,			/* crypto mode type */
							 keyType,			/* code encryption type definition */
							 AESIv, 			/* AES IV buffer */
							 pSwRecSignedData, 		/* pointer to SW component signed data - not word aligned for x.509 */
							 pSwRecNoneSignedData,  /* pointer to SW components non-signed data. always word aligned */
							 workspace_ptr, workspaceSize,	/* workspace & workspaceSize to load the SW component into */
							 &pImageInfo[i]);       /* pointer to verified image information */
		if (error != CC_OK){
			return error;
		}



		/* Point to the next SW record */
		pSwRecSignedData = (uint8_t *)((unsigned long)pSwRecSignedData + SW_REC_SIGNED_DATA_SIZE_IN_BYTES);
		pSwRecNoneSignedData = (uint32_t *)((unsigned long)pSwRecNoneSignedData + SW_REC_NONE_SIGNED_DATA_SIZE_IN_BYTES);

	}

	return CC_OK;
}

