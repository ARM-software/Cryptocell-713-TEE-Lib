/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#define CC_PAL_LOG_CUR_COMPONENT CC_LOG_MASK_SECURE_BOOT

/************* Include Files ****************/

#include <limits.h>

#include "cc_pal_log.h"
#include "cc_pal_mem.h"
#include "cc_pal_memmap.h"
#include "cc_pal_dma_defs.h"

#include "cc_lli_defs.h"
#include "secureboot_error.h"
#include "secureboot_stage_defs.h"
#include "secureboot_defs.h"
#include "secureboot_base_swimgverify.h"
#include "secureboot_parser_gen_defs.h"
#include "bootimagesverifier_error.h"
#include "secboot_cert_defs.h"
#include "cc_sbrt_crypto_int_api.h"
#include "cc_sbrt_crypto_int_defs.h"
#include "sym_adaptor_util.h"
#include "completion.h"

/************************ Defines ******************************/
/*!
 * We cnnot insure that the buffer that we need to map will be page aligned.
 * So we assume that one entry is not fully used. for simplicity we decrease it entirely from the
 * maximum nuber of lli entries, since we cannot know which portion of it can be used
 * Each lli entry can hold the min(MEMORY_FRAGMENT_MAX_SIZE_IN_KB * 1024, 2^16
 */
#define CC_SBRT_MAX_MLLI_SIZE                   (MEMORY_FRAGMENT_MAX_SIZE_IN_KB * 1024 * (LLI_MAX_NUM_OF_ENTRIES - 1))

#define SBRT_DOUBLE_BUFFER_SKIP_RELEASE         0xaaaaaaaa
/************************ Enums ******************************/

/************************ Typedefs ******************************/
/*! The structure to store the data chunk mapping info. */
typedef struct CCSbChunkImageInfo_t {
    void* pDataIn;
    void* pDataOut;
    size_t dataSize;
    DmaBuffer_s dmaBuffIn;
    DmaBuffer_s dmaBuffOut;
    uint32_t dmaBuiltFlag;
} CCSbChunkImageInfo_t;

/*! Definition of chunk list table. */
typedef CCSbChunkImageInfo_t CCSbChunkImageList_t[CC_SB_IMG_INFO_LIST_SIZE];

typedef struct SbrtDoubleBufferData_t {
    uint32_t cnt;
    uint8_t prevIndex;
    uint8_t currIndex;
} SbrtDoubleBufferData_t;

/************************ Global Data ******************************/

/************************ Internal Functions ******************************/
static uint32_t SbrtDoubleBufferGetPrevBufferIndex(SbrtDoubleBufferData_t *pDoubleBuffer)
{
    if (pDoubleBuffer->cnt == 1) {
        return SBRT_DOUBLE_BUFFER_SKIP_RELEASE;
    }

    return pDoubleBuffer->prevIndex;
}

static void SbrtDoubleBufferAdd(SbrtDoubleBufferData_t *pDoubleBuffer, uint32_t *pChunkNum)
{

    /* first iteration no need to release previous buffer */
    if (pDoubleBuffer->cnt == 0) {
        pDoubleBuffer->currIndex = 1;

    } else {

        pDoubleBuffer->currIndex = 1 - pDoubleBuffer->currIndex;
        pDoubleBuffer->prevIndex = 1 - pDoubleBuffer->prevIndex;
    }

    *pChunkNum = pDoubleBuffer->currIndex;
    pDoubleBuffer->cnt++;

}

static void bufferListInit(CCSbChunkImageList_t imgInfoList)
{
    uint32_t i;
    for (i = 0; i < CC_SB_IMG_INFO_LIST_SIZE; i++) {
        imgInfoList[i].dmaBuiltFlag = CC_PAL_DMA_DIR_NONE;
    }
}

static CCError_t bufferListReleaseChunk(CCSbChunkImageList_t imgInfoList, uint32_t chunkNum)
{
    CCError_t error = CC_OK;
    CCSbChunkImageInfo_t *pChuckInfo = &imgInfoList[chunkNum];

    /* unmap buffer */
    error = SymDriverAdaptorBuildDataPtrFromDma(pChuckInfo->pDataIn,
                                                pChuckInfo->pDataOut,
                                                pChuckInfo->dataSize,
                                                &pChuckInfo->dmaBuffIn,
                                                &pChuckInfo->dmaBuffOut,
                                                pChuckInfo->dmaBuiltFlag,
                                                false,
                                                chunkNum + SYM_ADAPTOR_SBRT_BUFFER_INDEX);
    if (error != CC_OK) {

        CC_PAL_LOG_ERR("failed to release chunk[%u] dir[%u] dataSize[%u] dataIn[%p] " "dataOut[%p] pDmaBuffIn[%p] pDmaBuffOut[%p]\n",
                       chunkNum,
                       pChuckInfo->dmaBuiltFlag,
                       pChuckInfo->dataSize,
                       pChuckInfo->pDataIn,
                       pChuckInfo->pDataOut,
                       &pChuckInfo->dmaBuffIn,
                       &pChuckInfo->dmaBuffOut);
        return error;
    }

    pChuckInfo->dmaBuiltFlag = CC_PAL_DMA_DIR_NONE;

    return CC_OK;
}

static CCError_t bufferListReleaseAllChunks(CCSbChunkImageList_t imgInfoList)
{
    CCError_t error = CC_OK;
    uint32_t chunkNum;

    for (chunkNum = 0; chunkNum < CC_SB_IMG_INFO_LIST_SIZE; chunkNum++) {
        error = bufferListReleaseChunk(imgInfoList, chunkNum);
        if (error != CC_OK) {
            CC_PAL_LOG_ERR("failed to release chunk[%u]\n", chunkNum);
            break;
        }
    }

    return CC_OK;
}

static CCError_t bufferListAddChunk(CCSbChunkImageList_t imgInfoList,
                                    uint32_t chunkNum,
                                    void* pDataIn,
                                    void* pDataOut,
                                    size_t dataSize,
                                    DmaBuffer_s **pOutDmaBuffIn,
                                    DmaBuffer_s **pOutDmaBuffOut)
{

    CCError_t error = CC_OK;
    uint8_t isInplace =  pDataIn == pDataOut;
    CCSbChunkImageInfo_t *pChuckInfo = &imgInfoList[chunkNum];
    uint32_t dmaBuiltFlag = CC_PAL_DMA_DIR_NONE;

    if (pOutDmaBuffIn == NULL || pOutDmaBuffOut == NULL) {
        return CC_SBRT_BUFFER_COHERENCY_NULL_PTR_ERROR;
    }

    /* map buffer */
    error = SymDriverAdaptorBuildDmaFromDataPtr(pDataIn,
                                                pDataOut,
                                                dataSize,
                                                &pChuckInfo->dmaBuffIn,
                                                &pChuckInfo->dmaBuffOut,
                                                &dmaBuiltFlag,
                                                isInplace,
                                                false,
                                                chunkNum + SYM_ADAPTOR_SBRT_BUFFER_INDEX);

    if (error != CC_OK) {

        CC_PAL_LOG_ERR("failed to map chunk[%u] dir[%u] dataSize[%u] dataIn[%p] "
                        "dataOut[%p] pDmaBuffIn[%p] pDmaBuffOut[%p]\n",
                        chunkNum,
                        pChuckInfo->dmaBuiltFlag,
                        pChuckInfo->dataSize,
                        pChuckInfo->pDataIn,
                        pChuckInfo->pDataOut,
                        &pChuckInfo->dmaBuffIn,
                        &pChuckInfo->dmaBuffOut);
        return error;
    }

    /* set fields */
    pChuckInfo->dmaBuiltFlag = dmaBuiltFlag;
    pChuckInfo->dataSize = dataSize;
    pChuckInfo->pDataIn = pDataIn;
    pChuckInfo->pDataOut = pDataOut;
    *pOutDmaBuffIn = &pChuckInfo->dmaBuffIn;
    *pOutDmaBuffOut = &pChuckInfo->dmaBuffOut;

    return CC_OK;
}

/************************ Public Functions ******************************/
/**
 * This function processes an entire image in one go.
 * This function in resposnsible for locking and unlocking the syemmetric crypto mutex.
 */
CCError_t SbrtImageLoadAndVerify(CCSbFlashReadFunc preHashflashRead_func,
                                 void *preHashUserContext,
                                 unsigned long hwBaseAddress,
                                 uint8_t isLoadFromFlash,
                                 uint8_t isVerifyImage,
                                 bsvCryptoMode_t cryptoMode,
                                 CCBsvKeyType_t keyType,
                                 AES_Iv_t AESIv,
                                 uint8_t *pSwRecSignedData,
                                 uint32_t *pSwRecNonSignedData,
                                 uint32_t *workspace_ptr,
                                 uint32_t workspaceSize,
                                 VerifiedImageInfo_t *pVerifiedImageInfo)
{
    /* error variable */
    CCError_t error = CC_OK;
    uint32_t palError = 0;

    ContentCertImageRecord_t cntImageRec;
    CCSbSwImgAddData_t cntNonSignedImageRec;
    CCHashResult_t actImageHash;
    CCAddr_t currLoadStartAddress = 0;
    uint32_t chunkSizeInBytes = 0;
    uint32_t actualImageSize = 0;

    uint8_t *chunkPtr;
    DmaBuffer_s *pDmaBuffIn;
    DmaBuffer_s *pDmaBuffOut;

    /* Use user workspace in double buffer manner */
    uint32_t *workRam1 = NULL;
    uint32_t *workRam2 = NULL;
    uint8_t isToggle = CC_FALSE;
    CCSbrtFlow_t flowMode;
    uint8_t isMemoryMapped = CC_FALSE;

    /* Process data in chunks asynchronously */
    CCSbrtCompletionMode_t completionMode = CC_SBRT_COMPLETION_NO_WAIT;

    CCSbChunkImageList_t imgInfoList;
    uint32_t chunkNum = 0;
    uint32_t chunkNumToRelease = 0;
    SbrtDoubleBufferData_t doubleBufferData = { 0 } ;

    /* we use the same api as in sbrom, so we need to ignore the hwBaseAddress */
    CC_UNUSED_PARAM(hwBaseAddress);

    /* In order to improve performance the Loading from Flash will be done simultaneously with Hash calculation */

    /* Initialize parameters */
    bufferListInit(imgInfoList);

    CC_PalMemCopy((uint8_t *)&cntImageRec, (uint8_t *)pSwRecSignedData, SW_REC_SIGNED_DATA_SIZE_IN_BYTES);
    /* The non-signed is word aligned, so we can cast the pointer */
    CC_PalMemCopy((uint8_t *)&cntNonSignedImageRec, (uint8_t *)pSwRecNonSignedData, SW_REC_NONE_SIGNED_DATA_SIZE_IN_BYTES);

    actualImageSize = cntImageRec.imageSize;
    currLoadStartAddress = cntImageRec.dstAddr;

    if (cntImageRec.isAesCodeEncUsed == 0){
        /* overwrite crypto mode to hash only */
        cryptoMode = BSV_CRYPTO_HASH;
        keyType = CC_BSV_END_OF_KEY_TYPE;
    } else {
        /* verify crypto mode and key are set for aes */
        if( (cryptoMode == BSV_CRYPTO_HASH) || (keyType == CC_BSV_END_OF_KEY_TYPE) ){
            CC_PAL_LOG_ERR("AES operation is not configuraed correctly\n");
            return CC_BOOT_IMG_VERIFIER_CERT_DECODING_ILLEGAL;
        }
    }

    switch (cryptoMode) {
        case BSV_CRYPTO_HASH:
            flowMode = CC_SBRT_FLOW_HASH_MODE;
            break;
        case BSV_CRYPTO_AES_AND_HASH:
            flowMode = CC_SBRT_FLOW_AES_AND_HASH_MODE;
            break;
        case BSV_CRYPTO_AES_TO_HASH_AND_DOUT:
            flowMode = CC_SBRT_FLOW_AES_TO_HASH_MODE;
            break;
        default:
            return CC_BOOT_IMG_VERIFIER_CERT_DECODING_ILLEGAL;
    }

    /* Validate image size */
    if (cntImageRec.imageSize == 0) {
        CC_PAL_LOG_ERR("SW image size is illegal !\n");
        return CC_BOOT_IMG_VERIFIER_SW_COMP_SIZE_IS_NULL;
    }

    /* Set chunk size for read and process data */
    if ( isLoadFromFlash == CC_FALSE) {
        /* case of verify only in memory: set to max data size of CC */
        chunkSizeInBytes = CC_SBRT_MAX_MLLI_SIZE;
    } else if (cntImageRec.dstAddr != CC_SW_COMP_NO_MEM_LOAD_INDICATION){
        /* When using loadAndVerify we are not bound to any destination buffer size.
         * User can decide based on the flash read performance, what size he/she prefers to process at a time */
        chunkSizeInBytes = CC_MIN(CC_CONFIG_SB_IMAGES_OPTIMIZED_MEMORY_CHUNK_SIZE_IN_BYTES, CC_SBRT_MAX_MLLI_SIZE);
    } else {
        /* set the standard flash-memory page size (as defined by user) */
        chunkSizeInBytes = CC_SB_IMAGES_WORKSPACE_SIZE_IN_BYTES / 2;
    }

    if (cntImageRec.dstAddr == CC_SW_COMP_NO_MEM_LOAD_INDICATION) {

        /* Case of verify in flash:
         * load data to user scratch buffer and verify it (hash) */
        isToggle = CC_TRUE;

        /* The workspace minimum size must be at least CC_SB_IMAGES_WORKSPACE_SIZE_IN_BYTES,
           if its not the function will return error (if temp memory should be used) */
        if (workspaceSize < CC_SB_IMAGES_WORKSPACE_SIZE_IN_BYTES){
            CC_PAL_LOG_ERR("workspace size too small\n");
            return CC_BOOT_IMG_VERIFIER_WORKSPACE_SIZE_TOO_SMALL;
        }

        /* Divide the workspace into 2 buffers, in order to allow reading and calculating HASH
         simultaneously , each buffer size is CC_SB_IMAGES_WORKSPACE_SIZE_IN_BYTES/2 */
        workRam1 = workspace_ptr; /* Size of this section is CC_SB_IMAGES_WORKSPACE_SIZE_IN_BYTES/2 */
        workRam2 = workspace_ptr + (CC_SB_IMAGES_WORKSPACE_SIZE_IN_BYTES/2)/sizeof(uint32_t);
        cntImageRec.dstAddr = CONVERT_TO_ADDR(workRam1);

        /* For each half, always wait for completion before processng the next buffer */
        completionMode = CC_SBRT_COMPLETION_WAIT_UPON_START;

        pVerifiedImageInfo->imageMemoryType = CC_SB_IMAGE_IN_FLASH;
        pVerifiedImageInfo->imageAddr = cntNonSignedImageRec.srcAddr;

    } else {
        /* Case of load & verify or verify in memory:
         * the data is processed (Aes and hash) in sequential chunks in the RAM */

        /* store the phisical address in pVerifiedImageInfo prior to mapping the address to virtual address space */
        pVerifiedImageInfo->imageMemoryType = CC_SB_IMAGE_IN_RAM;
        pVerifiedImageInfo->imageAddr = cntImageRec.dstAddr;

        /* When verify in ram, map the phisical address to virtaul address */
        palError = CC_PalMemMapImage(cntImageRec.dstAddr, cntImageRec.imageSize, &workRam1);
        if (palError != 0) {
            CC_PAL_LOG_ERR("CC_PalMemMapImage failed [0x%08x]\n", palError);
            return CC_BOOT_IMG_VERIFIER_MAP_ERR;
        }

        cntImageRec.dstAddr = CONVERT_TO_ADDR(workRam1);
        isMemoryMapped = CC_TRUE;

    }
    pVerifiedImageInfo->imageSize = cntImageRec.imageSize;

    SbrtCryptoImageLock();

    if (isVerifyImage == CC_TRUE){

        /* initialize the AES and HASH */
        error = SbrtCryptoImageInit(hwBaseAddress, flowMode, keyType, (uint8_t *)AESIv);
        if (error != CC_OK) {
            CC_PAL_LOG_ERR("SbrtCryptoImageInit failed [0x%08x] !\n", error);
            goto exit_completion;
        }
    }

    /* Load and/or Verify image in chunks */
        /*------------------------------------*/
    while (cntImageRec.imageSize > 0) {

        /* Set number of bytes to load and/or verify */
        chunkSizeInBytes = CC_MIN(chunkSizeInBytes, cntImageRec.imageSize);
        chunkPtr = (uint8_t*) (CONVERT_TO_ADDR(cntImageRec.dstAddr));

        /* Copy data from the flash to memory with user callback */
        if (isLoadFromFlash == CC_TRUE) {
            error = preHashflashRead_func(cntNonSignedImageRec.srcAddr,
                                          chunkPtr,
                                          chunkSizeInBytes,
                                          preHashUserContext);
            if (error != CC_OK) {
                CC_PAL_LOG_ERR("preHashflashRead_func failed [0x%08x]\n", (unsigned int)error);
                goto exit_completion;
            }
        }

        if (isVerifyImage == CC_TRUE) {

            if (isToggle == CC_TRUE) {
                SbrtDoubleBufferAdd(&doubleBufferData, &chunkNum);
            }

            error = bufferListAddChunk(imgInfoList,
                                       chunkNum,
                                       chunkPtr,
                                       flowMode == CC_SBRT_FLOW_HASH_MODE ? NULL : chunkPtr,
                                       chunkSizeInBytes,
                                       &pDmaBuffIn,
                                       &pDmaBuffOut);

            if (error != CC_OK) {
                goto exit_completion;
            }

            error = SbrtCryptoImageProcess(flowMode, completionMode, pDmaBuffIn, pDmaBuffOut);
            if (error != CC_OK) {
                CC_PAL_LOG_ERR("SbrtCryptoImageProcess failed [0x%08x]\n", (unsigned int)error);
                goto exit_completion;
            }

            if (isToggle == CC_TRUE) {
                /* Case of verify in flash, completionMode is fixed to WAIT_UPON_START,
                 Meaning, HW operation ended, and the previous buffer can be unmaped (not the current one) */
                chunkNumToRelease = SbrtDoubleBufferGetPrevBufferIndex(&doubleBufferData);

                if (chunkNumToRelease != SBRT_DOUBLE_BUFFER_SKIP_RELEASE) {
                    error = bufferListReleaseChunk(imgInfoList, chunkNumToRelease);
                    if (error != CC_OK) {
                        goto exit_completion;
                    }
                }

            } else {
                /* Case of load & verify or verify in memory */
                if (completionMode == CC_SBRT_COMPLETION_WAIT_UPON_END) {
                    /* Case of load & verify or verify in memory: unmap memory after CC completion */

                    error = bufferListReleaseAllChunks(imgInfoList);
                    if (error != CC_OK) {
                        goto exit_completion;
                    }

                    /* Return to asynchronously mode */
                    completionMode = CC_SBRT_COMPLETION_NO_WAIT;

                    chunkNum = 0;
                } else {
                    chunkNum++;
                    if (chunkNum == CC_SB_IMG_INFO_LIST_SIZE - 1) {
                        /* Wait synchronously after next chunk */
                        completionMode = CC_SBRT_COMPLETION_WAIT_UPON_END;
                    }
                }
            }
        }

        /* Update for next chunk */
        cntNonSignedImageRec.srcAddr = (CCAddr_t) (cntNonSignedImageRec.srcAddr + chunkSizeInBytes);
        cntImageRec.imageSize = cntImageRec.imageSize - chunkSizeInBytes;

        if (isToggle == CC_TRUE) {
            /* Case of verify in flash */

            /* Toggle on user's workspace (double buffer) */
            if (cntImageRec.dstAddr == CONVERT_TO_ADDR(workRam1)) {
                cntImageRec.dstAddr = CONVERT_TO_ADDR(workRam2);
            } else {
                cntImageRec.dstAddr = CONVERT_TO_ADDR(workRam1);
            }

        } else {
            /* Case of load & verify or verify in memory or load only */
            cntImageRec.dstAddr = (CCAddr_t) (cntImageRec.dstAddr + chunkSizeInBytes);
        }
    }

    if (isVerifyImage == CC_TRUE) {

        /* get Hash result  and compare  */
        error = SbrtCryptoImageFinish(actImageHash);
        if (error != CC_OK) {
            CC_PAL_LOG_ERR("SbrtCryptoImageFinish failed [0x%08x] !\n", (unsigned int)error);
            goto exit_unlock;
        }

        if (CC_PalMemCmp((uint8_t *)cntImageRec.imageHash,
                        (uint8_t *)actImageHash,
                        HASH_RESULT_SIZE_IN_BYTES) != 0) {

            CC_PAL_LOG_ERR("SW comp failed verification\n");
            error = CC_BOOT_IMG_VERIFIER_SW_COMP_FAILED_VERIFICATION;
            goto exit_unlock;
        }
    }

exit_completion:
    if ((isVerifyImage == CC_TRUE) && (error != CC_OK)) {
        /* in case of failure between sbrt crypto image init to finish
         * need to send dummy descriptor with queue last indication
         */
        WaitForSequenceCompletion(CC_TRUE);
    }

exit_unlock:

    /* This releases all the buffers used by both double buffer and buffer list method.
     * Must be called for both flows */
    bufferListReleaseAllChunks(imgInfoList);

    SbrtCryptoImageUnlock();

    if (error != CC_OK) {
        /* clear image in RAM in case of error, for load&verify=1 */
        if ((isLoadFromFlash == CC_TRUE) && (isVerifyImage == CC_TRUE) &&
                        (currLoadStartAddress != CC_SW_COMP_NO_MEM_LOAD_INDICATION)) {
            CC_PalMemSetZeroPlat((uint8_t*) (CONVERT_TO_ADDR(workRam1)), actualImageSize);
        }
    }

    /* unmap in case of error as well */
    if (isMemoryMapped == CC_TRUE) {
        palError = CC_PalMemUnMapImage(workRam1, pVerifiedImageInfo->imageSize);
        if (palError != 0) {
            CC_PAL_LOG_ERR("CC_PalMemUnMapImage failed [0x%08x]\n", palError);
            if (error == CC_OK) {
                error = palError;
            }
        }
    }

    return error;
}



