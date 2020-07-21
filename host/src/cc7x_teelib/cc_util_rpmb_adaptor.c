/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

/************* Include Files ****************/
#include "cc_context_relocation.h"
#include "cc_sram_map.h"
#include "cc_hmac.h"
#include "cc_hmac_error.h"
#include "cc_plat.h"
#include "cc_pal_mem.h"
#include "cc_pal_perf.h"
#include "cc_pal_log.h"
#include "cc_pal_dma.h"
#include "cc_pal_abort.h"
#include "cc_pal_mutex.h"
#include "cc_util_rpmb_adaptor.h"
#include "dma_buffer.h"
#include "sym_adaptor_driver_int.h"
#include "sym_crypto_driver.h"
#include "completion.h"
#include "cc_lli_defs_int.h"

#ifdef DEBUG
#include <assert.h>
#endif

/************************ Statics ******************************/
static RpmbDmaBuildBuffer_t gDmaBuildBuffer;

static int RpmbSymAdaptor2CCHmacErr(int symRetCode, uint32_t errorInfo)
{
    CC_UNUSED_PARAM(errorInfo);    // remove compilation warning
    switch (symRetCode) {
        case CC_RET_UNSUPP_ALG:
            return CC_HMAC_IS_NOT_SUPPORTED;
        case CC_RET_UNSUPP_ALG_MODE:
        case CC_RET_UNSUPP_OPERATION:
            return CC_HMAC_ILLEGAL_OPERATION_MODE_ERROR;
        case CC_RET_INVARG:
            return CC_HMAC_ILLEGAL_PARAMS_ERROR;
        case CC_RET_INVARG_KEY_SIZE:
            return CC_HMAC_UNVALID_KEY_SIZE_ERROR;
        case CC_RET_INVARG_CTX_IDX:
            return CC_HMAC_INVALID_USER_CONTEXT_POINTER_ERROR;
        case CC_RET_INVARG_CTX:
            return CC_HMAC_USER_CONTEXT_CORRUPTED_ERROR;
        case CC_RET_INVARG_BAD_ADDR:
            return CC_HMAC_DATA_IN_POINTER_INVALID_ERROR;
        case CC_RET_NOMEM:
            return CC_OUT_OF_RESOURCE_ERROR;
        case CC_RET_INVARG_INCONSIST_DMA_TYPE:
            return CC_ILLEGAL_RESOURCE_VAL_ERROR;
        case CC_RET_PERM:
        case CC_RET_NOEXEC:
        case CC_RET_BUSY:
        case CC_RET_OSFAULT:
        default:
            return CC_FATAL_ERROR;
    }
}

static void RpmbClearDmaBuildBuffers(RpmbDmaBuildBuffer_t *pDmaBuildBuff)
{
    if (NULL == pDmaBuildBuff) {
        return;
    }
    CC_PalMemSetZero(pDmaBuildBuff->blocksList.pBlockEntry,
                     RPMB_MAX_PAGES_PER_BLOCK * sizeof(CCPalDmaBlockInfo_t));
    CC_PalMemSetZero(pDmaBuildBuff->blocksList.numOfBlocks,
                     RPMB_MAX_BLOCKS_PER_UPDATE * sizeof(uint32_t));

    CC_PalMemSetZero((uint8_t * )&pDmaBuildBuff->devBuffer.mlliBlockInfo,
                     sizeof(CCPalDmaBlockInfo_t));

    if (pDmaBuildBuff->devBuffer.pLliEntry != NULL) {
        CC_PalMemSetZero(pDmaBuildBuff->devBuffer.pLliEntry, LLI_MAX_NUM_OF_ENTRIES * sizeof(lliInfo_t));
    }
}

static void RpmbFreeDmaBuildBuffers(RpmbDmaBuildBuffer_t *pDmaBuildBuff)
{
    if (NULL == pDmaBuildBuff) {
        return;
    }
    if (pDmaBuildBuff->devBuffer.pLliEntry != NULL) {
        CC_PalDmaContigBufferFree(LLI_MAX_NUM_OF_ENTRIES * sizeof(lliInfo_t),
                                  (uint8_t *) pDmaBuildBuff->devBuffer.pLliEntry);
        pDmaBuildBuff->devBuffer.pLliEntry = NULL;
    }
}

static uint32_t RpmbAllocDmaBuildBuffers(RpmbDmaBuildBuffer_t *pDmaBuildBuff)
{
    uint32_t rc = 0;
    uint8_t *tmpBuff = NULL;

    if (NULL == pDmaBuildBuff) {
        return CC_RET_INVARG;
    }
    tmpBuff = (uint8_t *) pDmaBuildBuff->devBuffer.pLliEntry;
    rc = CC_PalDmaContigBufferAllocate(LLI_MAX_NUM_OF_ENTRIES * sizeof(lliInfo_t), &tmpBuff);
    if (rc != 0) {
        return CC_RET_NOMEM;
    }
    if (!IS_ALIGNED((unsigned long )tmpBuff, 4))
        return CC_RET_INVARG_BAD_ADDR;

    /* casting to void to avoid compilation error , address must be aligned to word , otherwise an error will return */
    pDmaBuildBuff->devBuffer.pLliEntry = (lliInfo_t *) ((void*) tmpBuff);

    RpmbClearDmaBuildBuffers(pDmaBuildBuff);

    return CC_RET_OK;
}

static uint32_t RpmbBuildMlliTable(int j,
                                   uint32_t numOfBlocks,
                                   mlliTable_t *pDevBuffer,
                                   RpmbDmaBuffBlocksInfo_t *pUsrBlockList)
{
    uint32_t i;
    CCPalPerfData_t perfIdx = 0;

    if ((NULL == pDevBuffer) || (NULL == pUsrBlockList)) {
        return CC_RET_INVARG;
    }
    CC_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_MLLI_BUILD);

    /* fill mlli table entry */
    for (i = 0; i < numOfBlocks; i++) {

        /* set physical address of MLLI entry */
        LLI_SET_ADDR(pDevBuffer->pLliEntry[j].lliEntry,
                     pUsrBlockList->pBlockEntry[i].blockPhysAddr);
        /* set size of MLLI entry */
        LLI_SET_SIZE(pDevBuffer->pLliEntry[j].lliEntry, pUsrBlockList->pBlockEntry[i].blockSize);

        pDevBuffer->pLliEntry[j].lliEntry[LLI_WORD0_OFFSET] = SET_WORD_LE(pDevBuffer->pLliEntry[j].lliEntry[LLI_WORD0_OFFSET]);
        pDevBuffer->pLliEntry[j].lliEntry[LLI_WORD1_OFFSET] = SET_WORD_LE(pDevBuffer->pLliEntry[j].lliEntry[LLI_WORD1_OFFSET]);

        CC_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_MLLI_BUILD);

        j++;
    }

    return 0;
}

static uint32_t RpmbBuildDmaFromDataPtr(unsigned long *pListOfDataFrames,
                                        uint32_t listSize,
                                        CCPalDmaBufferDirection_t direction,
                                        DmaBuffer_s *pDmaBuff,
                                        RpmbDmaBuildBuffer_t *pInterBuildBuff)
{
    uint32_t rc = 0;
    uint32_t numOfBlocks = 0;
    mlliTable_t *pDevBuffer = NULL;
    RpmbDmaBuffBlocksInfo_t *pUsrBlockList = NULL;
    uint8_t *pUsrBuffer;
    uint32_t i, j;

    /* check inputs */
    if ((NULL == pInterBuildBuff) || (NULL == pDmaBuff)) {
        CC_PAL_LOG_ERR("invalid parameters\n");
        return CC_RET_INVARG;
    }
    if (listSize == 0) {
        SET_DMA_BUFF_WITH_NULL(pDmaBuff);
        return 0;
    }

    j = 0;
    pDevBuffer = &pInterBuildBuff->devBuffer;
    pUsrBlockList = &pInterBuildBuff->blocksList;

    for (i = 0; i < listSize; i++) {

        pUsrBuffer = (uint8_t *) (pListOfDataFrames[i]);
        pUsrBlockList->numOfBlocks[i] = RPMB_MAX_PAGES_PER_BLOCK;    // assert max of 2 pages

        /* check if buffer is NULL, skip to error case */
        if (NULL == pUsrBuffer) {
            rc = CC_RET_NOMEM;
            goto endError_unMapDmaBuffer;
        }

        rc = CC_PalDmaBufferMap((uint8_t *) pUsrBuffer,
                                CC_UTIL_RPMB_DATA_FRAME_SIZE_IN_BYTES,
                                direction,
                                &pUsrBlockList->numOfBlocks[i],
                                pUsrBlockList->pBlockEntry,
                                &pInterBuildBuff->buffMainH[i]);

        if (rc != 0) {
            CC_PAL_LOG_ERR("failed to CC_PalDmaBufferMap for user buffer %d\n", i);
            goto endError_unMapDmaBuffer;
        }

        /* returned numOfBlocks should be either 1 or 2 */
        if (pUsrBlockList->numOfBlocks[i] > RPMB_MAX_PAGES_PER_BLOCK) {
            CC_PAL_LOG_ERR("failed to CC_PalDmaBufferMap for user buffer %d\n", i);
            rc = CC_RET_OSFAULT;
            i++;
            goto endError_unMapDmaBuffer;
        }

        /* add block entry to MLLI table */
        RpmbBuildMlliTable(j, pUsrBlockList->numOfBlocks[i], pDevBuffer, pUsrBlockList);

        j += pUsrBlockList->numOfBlocks[i];
    }

    pDevBuffer->mlliBlockInfo.blockSize = j * sizeof(lliInfo_t);

    /* map MLLI table */
    numOfBlocks = SINGLE_BLOCK_ENTRY;
    rc = CC_PalDmaBufferMap((uint8_t *) pDevBuffer->pLliEntry,
                            pDevBuffer->mlliBlockInfo.blockSize,
                            CC_PAL_DMA_DIR_BI_DIRECTION,
                            &numOfBlocks,
                            &pDevBuffer->mlliBlockInfo,
                            &pInterBuildBuff->buffMlliH);
    if (rc != 0) {
        CC_PAL_LOG_ERR("failed to CC_PalDmaBufferMap for mlli table 0x%x\n", rc);
        goto endError_unMapDmaBuffer;
    }
    /* in case numOfBlocks returned bigger than 1, we declare error */
    if (numOfBlocks > SINGLE_BLOCK_ENTRY) {
        CC_PAL_LOG_ERR("failed to CC_PalDmaBufferMap for mlli numOfBlocks > 1\n");
        rc = CC_RET_OSFAULT;
        goto endError_unMapMlliBuffer;
    }
    SET_DMA_BUFF_WITH_MLLI(pDmaBuff,
                           pDevBuffer->mlliBlockInfo.blockPhysAddr,
                           pDevBuffer->mlliBlockInfo.blockSize);
    return 0;

endError_unMapMlliBuffer:
    CC_PalDmaBufferUnmap((uint8_t *) pDevBuffer->pLliEntry,
                                                   pDevBuffer->mlliBlockInfo.blockSize,
                                                   CC_PAL_DMA_DIR_BI_DIRECTION,
                                                   SINGLE_BLOCK_ENTRY,
                                                   &pDevBuffer->mlliBlockInfo,
                                                   pInterBuildBuff->buffMlliH);

endError_unMapDmaBuffer:
    /* i holds the number of buffers that should be unmapped */
    for (j = 0; j < i; j++) {
        pUsrBuffer = (uint8_t *) (pListOfDataFrames[j]);

        /* check if buffer is NULL, skip to next buffer */
        if (NULL == pUsrBuffer)
            continue;

        /* unmap the buffer */
        CC_PalDmaBufferUnmap((uint8_t *) pUsrBuffer,
                             CC_UTIL_RPMB_DATA_FRAME_SIZE_IN_BYTES,
                             direction,
                             pUsrBlockList->numOfBlocks[j],
                             pUsrBlockList->pBlockEntry,
                             pInterBuildBuff->buffMainH[j]);
    }

    return rc;
}

static uint32_t RpmbBuildDataPtrFromDma(unsigned long *pListOfDataFrames,
                                        uint32_t listSize,
                                        CCPalDmaBufferDirection_t direction,
                                        RpmbDmaBuildBuffer_t *pInterBuildBuff)
{
    uint32_t rc = 0;
    mlliTable_t *pDevBuffer = NULL;
    RpmbDmaBuffBlocksInfo_t *pUsrBlockList = NULL;
    uint8_t *pUsrBuffer;
    uint32_t i;

    /* check inputs */
    if (NULL == pInterBuildBuff) {
        CC_PAL_LOG_ERR("invalid parameters\n");
        return CC_RET_INVARG;
    }

    if (listSize == 0) {
        return 0;
    }

    pDevBuffer = &pInterBuildBuff->devBuffer;
    pUsrBlockList = &pInterBuildBuff->blocksList;

    for (i = 0; i < listSize; i++) {

        pUsrBuffer = (uint8_t *) (pListOfDataFrames[i]);

        /* check if buffer is NULL, skip to next buffer */
        if (NULL == pUsrBuffer)
            continue;

        /* unmap the buffer */
        rc |= CC_PalDmaBufferUnmap((uint8_t *) pUsrBuffer,
                                   CC_UTIL_RPMB_DATA_FRAME_SIZE_IN_BYTES,
                                   direction,
                                   pUsrBlockList->numOfBlocks[i],
                                   pUsrBlockList->pBlockEntry,
                                   pInterBuildBuff->buffMainH[i]);
    }

    /* Unmap MLLI */
    rc |= CC_PalDmaBufferUnmap((uint8_t *) pDevBuffer->pLliEntry,
                               pDevBuffer->mlliBlockInfo.blockSize,
                               CC_PAL_DMA_DIR_BI_DIRECTION,
                               SINGLE_BLOCK_ENTRY,
                               &pDevBuffer->mlliBlockInfo,
                               pInterBuildBuff->buffMlliH);

    if (rc != 0) {
        rc = CC_RET_BUSY;
    }

    return rc;
}

static int RpmbSymDriverAdaptorProcess(uint32_t *pCtx,
                                       unsigned long *pListOfDataFrames,
                                       uint32_t listSize,
                                       enum drv_crypto_alg alg)
{
    int symRc = CC_RET_OK;
    DmaBuffer_s dmaBuffIn;
    DmaBuffer_s dmaBuffOut;
    uint32_t retCode;
    CCPalPerfData_t perfIdx = 0;

    CC_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_SYM_DRV_PROC);
    CC_PAL_LOG_INFO("pCtx=%p\n", pCtx);

    retCode = CC_PalMutexLock(&CCSymCryptoMutex, CC_INFINITE);
    if (retCode != CC_SUCCESS) {
        CC_PalAbort("Fail to acquire mutex\n");
    }

    retCode = RpmbBuildDmaFromDataPtr(pListOfDataFrames,
                                      listSize,
                                      CC_PAL_DMA_DIR_TO_DEVICE,
                                      &dmaBuffIn,
                                      &gDmaBuildBuffer);
    if (retCode != 0) {
        CC_PAL_LOG_ERR("failed to RpmbBuildDmaFromDataPtr for pDataIn 0x%x\n", retCode);
        symRc = retCode;
        goto processUnlockMutex;
    }

    symRc = SymDriverAdaptorCopyCtx(DRIVER_ADAPTOR_DIR_IN,
                                    CC_SRAM_DRIVER_ADAPTOR_CONTEXT_CACHE_ADDR,
                                    pCtx,
                                    alg);
    if (symRc != CC_RET_OK) {
        goto EndWithErr;
    }

    symRc = SymDriverDispatchProcess(CC_SRAM_DRIVER_ADAPTOR_CONTEXT_CACHE_ADDR,
                                     pCtx,
                                     &dmaBuffIn,
                                     &dmaBuffOut,
                                     alg);
    if (symRc != CC_RET_OK) {
        goto EndWithErr;
    }

    WaitForSequenceCompletion(CC_TRUE);
    symRc = SymDriverAdaptorCopyCtx(DRIVER_ADAPTOR_DIR_OUT,
                                    CC_SRAM_DRIVER_ADAPTOR_CONTEXT_CACHE_ADDR,
                                    pCtx,
                                    alg);

EndWithErr:

    retCode = RpmbBuildDataPtrFromDma(pListOfDataFrames,
                                      listSize,
                                      CC_PAL_DMA_DIR_TO_DEVICE,
                                      &gDmaBuildBuffer);
    if (retCode != 0) {
        CC_PAL_LOG_ERR("failed to RpmbBuildDataPtrFromDma for pDataIn 0x%x\n", retCode);
        symRc = retCode;
    }

processUnlockMutex:

    CC_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_SYM_DRV_PROC);

    if (CC_PalMutexUnlock(&CCSymCryptoMutex) != CC_SUCCESS) {
        CC_PalAbort("Fail to release mutex\n");
    }
    return symRc;
}

static int RpmbSymDriverAdaptorFinalize(uint32_t *pCtx,
                                        unsigned long *pListOfDataFrames,
                                        uint32_t listSize,
                                        enum drv_crypto_alg alg)
{
    DmaBuffer_s dmaBuffIn, dmaBuffOut;
    int symRc = CC_RET_OK;
    uint32_t retCode;
    CCPalPerfData_t perfIdx = 0;

    CC_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_SYM_DRV_FIN);

    CC_PAL_LOG_INFO("pCtx=%p\n", pCtx);

    retCode = CC_PalMutexLock(&CCSymCryptoMutex, CC_INFINITE);
    if (retCode != CC_SUCCESS) {
        CC_PalAbort("Fail to acquire mutex\n");
    }

    retCode = RpmbBuildDmaFromDataPtr(pListOfDataFrames,
                                      listSize,
                                      CC_PAL_DMA_DIR_TO_DEVICE,
                                      &dmaBuffIn,
                                      &gDmaBuildBuffer);
    if (retCode != 0) {
        CC_PAL_LOG_ERR("failed to RpmbBuildDmaFromDataPtr for pDataIn 0x%x\n", retCode);
        symRc = retCode;
        goto finalizeUnlockMutex;
    }

    symRc = SymDriverAdaptorCopyCtx(DRIVER_ADAPTOR_DIR_IN,
                                    CC_SRAM_DRIVER_ADAPTOR_CONTEXT_CACHE_ADDR,
                                    pCtx,
                                    alg);
    if (symRc != CC_RET_OK) {
        goto EndWithErr;
    }

    symRc = SymDriverDispatchFinalize(CC_SRAM_DRIVER_ADAPTOR_CONTEXT_CACHE_ADDR,
                                      pCtx,
                                      &dmaBuffIn,
                                      &dmaBuffOut,
                                      alg);
    if (symRc != CC_RET_OK) {
        goto EndWithErr;
    }

    WaitForSequenceCompletion(CC_TRUE);

    symRc = SymDriverAdaptorCopyCtx(DRIVER_ADAPTOR_DIR_OUT,
                                    CC_SRAM_DRIVER_ADAPTOR_CONTEXT_CACHE_ADDR,
                                    pCtx,
                                    alg);

EndWithErr:

    retCode = RpmbBuildDataPtrFromDma(pListOfDataFrames,
                                                  listSize,
                                                  CC_PAL_DMA_DIR_TO_DEVICE,
                                                  &gDmaBuildBuffer);
    if (retCode != 0) {
        CC_PAL_LOG_ERR("failed to RpmbBuildDataPtrFromDma for pDataIn 0x%x\n", retCode);
        symRc = retCode;
    }

    CC_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_SYM_DRV_FIN);

finalizeUnlockMutex:

    if (CC_PalMutexUnlock(&CCSymCryptoMutex) != CC_SUCCESS) {
        CC_PalAbort("Fail to release mutex\n");
    }
    return symRc;
}

int RpmbSymDriverAdaptorModuleInit()
{
    int symRc = CC_RET_OK;

    /* allocate internal buffer for dma device resources */
    symRc = RpmbAllocDmaBuildBuffers(&gDmaBuildBuffer);

    if (symRc != CC_RET_OK) {
        symRc = CC_RET_NOMEM;
    }

    return symRc;
}

int RpmbSymDriverAdaptorModuleTerminate()
{
    /* release internal dma buffer resources */
    RpmbFreeDmaBuildBuffers(&gDmaBuildBuffer);

    return CC_RET_OK;
}

CCError_t RpmbHmacInit(CCHmacUserContext_t *ContextID_ptr,
                                uint8_t *key_ptr,
                                size_t keySize)
{
    struct drv_ctx_hash *pHmacContext;
    CCHmacPrivateContext_t *pHmacPrivContext;
    int symRc = CC_RET_OK;

    /* initializes the HMAC machine on the CC level */
    symRc = CC_HmacInit(ContextID_ptr, CC_HASH_SHA256_mode, key_ptr, keySize);
    if (symRc != CC_OK) {
        return symRc;
    }

    /* Get pointer to contiguous context in the HOST buffer */
    pHmacContext = (struct drv_ctx_hash *) RcGetUserCtxLocation(ContextID_ptr->buff);
    pHmacPrivContext = (CCHmacPrivateContext_t *) &(((uint32_t*) pHmacContext)[CC_HMAC_USER_CTX_ACTUAL_SIZE_IN_WORDS - 1]);

    /* init private context */
    pHmacPrivContext->isLastBlockProcessed = 0;

    return CC_OK;
}

CCError_t RpmbHmacUpdate(CCHmacUserContext_t *ContextID_ptr,
                         unsigned long *pListOfDataFrames,
                         uint32_t listSize)
{
    struct drv_ctx_hash *pHmacContext;
    CCHmacPrivateContext_t *pHmacPrivContext;
    int symRc = CC_RET_OK;

    /* Get pointer to contiguous context in the HOST buffer */
    pHmacContext = (struct drv_ctx_hash *) RcGetUserCtxLocation(ContextID_ptr->buff);
    pHmacPrivContext = (CCHmacPrivateContext_t *) &(((uint32_t*) pHmacContext)[CC_HMAC_USER_CTX_ACTUAL_SIZE_IN_WORDS - 1]);

    if (listSize == RPMB_MAX_BLOCKS_PER_UPDATE) {
        symRc = RpmbSymDriverAdaptorProcess((uint32_t *) pHmacContext,
                                            pListOfDataFrames,
                                            listSize,
                                            pHmacContext->alg);
        if (symRc != CC_RET_OK) {
            return CC_CRYPTO_RETURN_ERROR(symRc, 0, RpmbSymAdaptor2CCHmacErr);
        }
    } else { /* this is the last block */
        pHmacPrivContext->isLastBlockProcessed = 1;
        symRc = RpmbSymDriverAdaptorFinalize((uint32_t *) pHmacContext,
                                             pListOfDataFrames,
                                             listSize,
                                             pHmacContext->alg);
        if (symRc != CC_RET_OK) {
            return CC_CRYPTO_RETURN_ERROR(symRc, 0, RpmbSymAdaptor2CCHmacErr);
        }
    }

    if (symRc != CC_RET_OK) {
        return CC_CRYPTO_RETURN_ERROR(symRc, 0, RpmbSymAdaptor2CCHmacErr);
    }

    return CC_OK;
}

CCError_t RpmbHmacFinish(CCHmacUserContext_t *ContextID_ptr, CCHashResultBuf_t HmacResultBuff)
{
    struct drv_ctx_hash *pHmacContext;
    CCHmacPrivateContext_t *pHmacPrivContext;
    int symRc = CC_RET_OK;

    /* Get pointer to contiguous context in the HOST buffer */
    pHmacContext = (struct drv_ctx_hash *) RcGetUserCtxLocation(ContextID_ptr->buff);
    pHmacPrivContext = (CCHmacPrivateContext_t *) &(((uint32_t*) pHmacContext)[CC_HMAC_USER_CTX_ACTUAL_SIZE_IN_WORDS
                    - 1]);

    if (pHmacPrivContext->isLastBlockProcessed == 0) {
        symRc = RpmbSymDriverAdaptorFinalize((uint32_t *) pHmacContext, NULL, 0, pHmacContext->alg);
        if (symRc != CC_RET_OK) {
            return CC_CRYPTO_RETURN_ERROR(symRc, 0, RpmbSymAdaptor2CCHmacErr);
        }
    }

    CC_PalMemCopy(HmacResultBuff, pHmacContext->digest, CC_SHA256_DIGEST_SIZE);
    return CC_OK;
}
