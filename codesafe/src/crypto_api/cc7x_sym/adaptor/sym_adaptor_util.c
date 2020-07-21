/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */
#define CC_PAL_LOG_CUR_COMPONENT CC_LOG_MASK_CC_SYM_DRIVER

#include "sym_adaptor_util.h"
#include "sym_adaptor_driver_int.h"
#include "cc_pal_log.h"
#include "cc_hw_queue_defs.h"

/******************************************************************************
 *                          DEFINITIONS
 ******************************************************************************/

#define NUM_OF_DMA_BUFFS           (SYM_ADAPTOR_SBRT_BUFFER_NUM + SYM_ADAPTOR_BUFFER_NUM)

/******************************************************************************
 *                          MACROS
 ******************************************************************************/

/******************************************************************************
 *                          TYPES
 ******************************************************************************/
typedef enum eUnmapFlag_t {
    UNMAP_FLAG_NONE = 0x0,
    UNMAP_FLAG_CONTIG_DLLI = 0x1,
    UNMAP_FLAG_SMALL_SIZE_DLLI = 0x2,
    UNMAP_FLAG_MLLI_MAIN = 0x4,
    UNMAP_FLAG_MLLI_TABLE = 0x10
} eUnmapFlag_t;

typedef struct dmaBuffBlocksInfo_t {
    /* number of entries in pBlockEntry member */
    uint32_t numOfBlocks;
    /* an array of blocks and their sizes. the block are fragments of the data */
    CCPalDmaBlockInfo_t pBlockEntry[LLI_MAX_NUM_OF_ENTRIES];
} dmaBuffBlocksInfo_t;

typedef struct interDmaBuildBuffer_t {
    /* stores data needed to construct and map the MLLI table. */
    mlliTable_t devBuffer;
    /* used to for optimisation. when data is less than DLLI_OPTIMIZED_BUFF_SIZE,
     * copy data to since contiguous buffer and use DLLI. */
    uint8_t * optimizationBuff;
    /* holds an array of fragmented blocks of the data */
    dmaBuffBlocksInfo_t blocksList;
    /* a handle to the main data mapping. used to optimized the un-mapping and freeing process */
    CC_PalDmaBufferHandle buffMainH;
    /* a handle to the temp data buffer mapping. used to optimized the un-mapping and freeing process */
    CC_PalDmaBufferHandle buffOptH;
    /* a handle to the compiled MLLI table data. used to optimized the un-mapping and freeing process */
    CC_PalDmaBufferHandle buffMlliH;
    /* used to identify the buffer */
    uint8_t index;
} interDmaBuildBuffer_t;

/******************************************************************************
 *                          GLOBALS
 ******************************************************************************/
interDmaBuildBuffer_t g_dmaInBuildBuffArrH[NUM_OF_DMA_BUFFS];
interDmaBuildBuffer_t g_dmaOutBuildBuffArrH[NUM_OF_DMA_BUFFS];

/******************************************************************************
 *                          FUNCTION PROTOTYPES
 ******************************************************************************/
/**
 * This function reset the internal fields of the interDmaBuildBuffer_t structure
 *
 * @param dir           the dir indicating the buffer to clear
 */
static void clearDmaBuildBuffers(eDmaBuiltDir_t dir)
{
    uint32_t index;
    interDmaBuildBuffer_t *pDmaBuildBuffArr;

    if (dir >= DMA_BUILD_DIR_MAX) {
        CC_PAL_LOG_ERR("dir is not valid[%u]\n", dir);
        return;
    }

    pDmaBuildBuffArr = (dir == DMA_BUILD_DIR_IN ? g_dmaInBuildBuffArrH : g_dmaOutBuildBuffArrH);

    for (index = 0; index < NUM_OF_DMA_BUFFS; ++index) {
        interDmaBuildBuffer_t *pDmaBuildBuff = &pDmaBuildBuffArr[index];
        CC_PalMemSetZero(pDmaBuildBuff->blocksList.pBlockEntry,
                         LLI_MAX_NUM_OF_ENTRIES * sizeof(CCPalDmaBlockInfo_t));
        pDmaBuildBuff->blocksList.numOfBlocks = 0;

        CC_PalMemSetZero((uint8_t * )&pDmaBuildBuff->devBuffer.mlliBlockInfo,
                         sizeof(CCPalDmaBlockInfo_t));

        if (pDmaBuildBuff->optimizationBuff != NULL) {
            CC_PalMemSetZero(pDmaBuildBuff->optimizationBuff, DLLI_OPTIMIZED_BUFF_SIZE);
        }
        if (pDmaBuildBuff->devBuffer.pLliEntry != NULL) {
            CC_PalMemSetZero(pDmaBuildBuff->devBuffer.pLliEntry,
                             LLI_MAX_NUM_OF_ENTRIES * sizeof(lliInfo_t));
        }

        pDmaBuildBuff->index = index;
    }
}

/**
* @brief   fills mlli entries based on physical addresses and sizes from blockList
 *
 *
 * @param[in] pUsrBlockList - list of blocks
 * @param[out] pDevBuffer - mlli list to fill
 *
 * @return success/fail
 */
static uint32_t buildMlliTable(mlliTable_t *pDevBuffer, dmaBuffBlocksInfo_t *pUsrBlockList)
{
    uint32_t i = 0;
    uint32_t mlliEntries = 0;
    CCPalPerfData_t perfIdx = 0;

    if ((NULL == pDevBuffer) || (NULL == pUsrBlockList)) {
        return CC_RET_INVARG;
    }

    mlliEntries = pUsrBlockList->numOfBlocks;

    // calculate mlli table size,
    pDevBuffer->mlliBlockInfo.blockSize = mlliEntries * sizeof(lliInfo_t);
    CC_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_MLLI_BUILD);

    // fill other mlli table entries. Note that pUsrBlockList->pBlockEntry
    for (i = 0; i < mlliEntries; i++) {

        // Verify blockSize is not bigger than MLLI
        if (pUsrBlockList->pBlockEntry[i].blockSize > MAX_MLLI_ENTRY_SIZE) {
            CC_PalMemSetZero(pDevBuffer->pLliEntry, LLI_MAX_NUM_OF_ENTRIES * sizeof(lliInfo_t));
            return 1;
        }
        // set physical address of MLLI entry
        LLI_SET_ADDR(pDevBuffer->pLliEntry[i].lliEntry, pUsrBlockList->pBlockEntry[i].blockPhysAddr);
        // set size of MLLI entry
        LLI_SET_SIZE(pDevBuffer->pLliEntry[i].lliEntry, pUsrBlockList->pBlockEntry[i].blockSize);

        // copy lliEntry to MLLI table - LE/BE must be considered
        pDevBuffer->pLliEntry[i].lliEntry[LLI_WORD0_OFFSET] = SET_WORD_LE(pDevBuffer->pLliEntry[i].lliEntry[LLI_WORD0_OFFSET]);
        pDevBuffer->pLliEntry[i].lliEntry[LLI_WORD1_OFFSET] = SET_WORD_LE(pDevBuffer->pLliEntry[i].lliEntry[LLI_WORD1_OFFSET]);
    }

    CC_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_MLLI_BUILD);

    return 0;
}

/**
 * @brief   sets user buffer into dma buffer to be used by HW
 *
 *
 * @param[in] pUsrBuffer - address of the buffer allocated by user
 * @param[in] usrBuffSize - data direction: into device, from device or bidirectional
 * @param[in] direction - bi-directional/to/from device
 * @param[out] pDmaBuff - dma buffer to be used by HW
 * @param[out] pInterBuildBuff - mlli list,  page list abd cookies used to build the dms bufffer
 *
 * @return success/fail
 */
static uint32_t buildDmaFromDataPtr(uint8_t *pUsrBuffer,
                                    size_t usrBuffSize,
                                    CCPalDmaBufferDirection_t direction,
                                    DmaBuffer_s *pDmaBuff,
                                    interDmaBuildBuffer_t *pInterBuildBuff)
{
    uint32_t rc = 0;
    uint32_t numOfBlocks = 0;
    mlliTable_t *pDevBuffer = NULL;
    dmaBuffBlocksInfo_t *pUsrBlockList = NULL;
    uint8_t *pOptBuff = NULL;
    uint32_t errorClearFlag = 0;

    CC_PAL_LOG_INFO("%s:%d: pUsrBuffer[%p] cache dir[%s] usrBuffSize[%zu]\n", __func__, __LINE__,
                    pUsrBuffer, (const char *[]){ "none", "to", "from", "bi" }[direction], usrBuffSize);

    // check inputs
    if ((NULL == pInterBuildBuff) || (NULL == pDmaBuff)) {
        CC_PAL_LOG_ERR("invalid parameters\n");
        return CC_RET_INVARG;
    }

    // first check if buffer is NULL, build simple empty dma buffer
    if ((NULL == pUsrBuffer) || (0 == usrBuffSize)) {
        SET_DMA_BUFF_WITH_NULL(pDmaBuff);
        return 0;
    }

    pDevBuffer = &pInterBuildBuff->devBuffer;
    pUsrBlockList = &pInterBuildBuff->blocksList;
    pOptBuff = pInterBuildBuff->optimizationBuff;
    pUsrBlockList->numOfBlocks = LLI_MAX_NUM_OF_ENTRIES;

    // second case, if buffer is contiguous build DLLI
    if (CC_PalIsDmaBufferContiguous(pUsrBuffer, usrBuffSize)) {

        // Verify size of max DLLI
        if (usrBuffSize > MAX_DLLI_BLOCK_SIZE) {
            return CC_RET_NOMEM;
        }
        pUsrBlockList->numOfBlocks = SINGLE_BLOCK_ENTRY;

        rc = CC_PalDmaBufferMap(pUsrBuffer,
                                usrBuffSize,
                                direction,
                                &pUsrBlockList->numOfBlocks,
                                pUsrBlockList->pBlockEntry,
                                &pInterBuildBuff->buffMainH);

        if (rc != 0) {
            CC_PAL_LOG_ERR("failed to CC_PalDmaBufferMap for dlli contig user buffer 0x%x\n", rc);
            rc = CC_RET_NOMEM;
            goto endError_dataPtrToDma;
        }
        // if case numOfBlocks returned bigger than 1, we declare error
        if (pUsrBlockList->numOfBlocks > SINGLE_BLOCK_ENTRY) {
            errorClearFlag = UNMAP_FLAG_CONTIG_DLLI;
            CC_PAL_LOG_ERR("failed to CC_PalDmaBufferMap for contig mem numOfBlocks > 1\n");
            rc = CC_RET_OSFAULT;
            goto endError_dataPtrToDma;
        }
        SET_DMA_BUFF_WITH_DLLI(pDmaBuff, pUsrBlockList->pBlockEntry[0].blockPhysAddr, usrBuffSize);
        return 0;
    }

    // in case buffer is not contiguous:
    // if buffer size smaller than  DLLI_OPTIMIZED_BUFF_SIZE:
    // copy user buffer to optimizedBuff to improve performance and build DLLI
    if (usrBuffSize < DLLI_OPTIMIZED_BUFF_SIZE) {
        // copy userBuffer to optimizedBuff
        if ((CC_PAL_DMA_DIR_TO_DEVICE == direction) || (CC_PAL_DMA_DIR_BI_DIRECTION == direction)) {
            CC_PalMemCopy(pOptBuff, pUsrBuffer, usrBuffSize);
        }
        // map optimizedBuff to get physical address and lock+invalidate
        pUsrBlockList->numOfBlocks = SINGLE_BLOCK_ENTRY;
        rc = CC_PalDmaBufferMap(pOptBuff,
                                usrBuffSize,
                                direction,
                                &pUsrBlockList->numOfBlocks,
                                pUsrBlockList->pBlockEntry,
                                &pInterBuildBuff->buffOptH);
        if (rc != 0) {
            CC_PAL_LOG_ERR("failed to CC_PalDmaBufferMap for dlli optimizedBuff 0x%x\n", rc);
            rc = CC_RET_NOMEM;
            goto endError_dataPtrToDma;
        }
        // if case numOfBlocks returned bigger than 1, we declare error
        if (pUsrBlockList->numOfBlocks > SINGLE_BLOCK_ENTRY) {
            CC_PAL_LOG_ERR("failed to CC_PalDmaBufferMap for dlli optimizedBuff numOfBlocks > 1\n");
            errorClearFlag = UNMAP_FLAG_SMALL_SIZE_DLLI;
            rc = CC_RET_OSFAULT;
            goto endError_dataPtrToDma;
        }
        SET_DMA_BUFF_WITH_DLLI(pDmaBuff, pUsrBlockList->pBlockEntry[0].blockPhysAddr, usrBuffSize);
        return 0;
    }

    pUsrBlockList->numOfBlocks = LLI_MAX_NUM_OF_ENTRIES;
    rc = CC_PalDmaBufferMap(pUsrBuffer,
                            usrBuffSize,
                            direction,
                            &pUsrBlockList->numOfBlocks,
                            pUsrBlockList->pBlockEntry,
                            &pInterBuildBuff->buffMainH);
    if (rc != 0) {
        CC_PAL_LOG_ERR("failed to CC_PalDmaBufferMap for mlli user buffer 0x%x\n", rc);
        rc = CC_RET_NOMEM;
        goto endError_dataPtrToDma;
    }

    // if case numOfBlocks returned bigger than LLI_MAX_NUM_OF_ENTRIES, we declare error
    if (pUsrBlockList->numOfBlocks > LLI_MAX_NUM_OF_ENTRIES) {
        CC_PAL_LOG_ERR("failed to CC_PalDmaBufferMap for mlli numOfBlocks > LLI_MAX_NUM_OF_ENTRIES\n");
        errorClearFlag = UNMAP_FLAG_MLLI_MAIN;
        rc = CC_RET_OSFAULT;
        goto endError_dataPtrToDma;
    }

    // build MLLI
    buildMlliTable(pDevBuffer, pUsrBlockList);

    // map MLLI
    numOfBlocks = SINGLE_BLOCK_ENTRY;
    rc = CC_PalDmaBufferMap((uint8_t *) pDevBuffer->pLliEntry,
                            (pUsrBlockList->numOfBlocks) * sizeof(lliInfo_t),
                            CC_PAL_DMA_DIR_BI_DIRECTION,
                            &numOfBlocks,
                            &pDevBuffer->mlliBlockInfo,
                            &pInterBuildBuff->buffMlliH);
    if (rc != 0) {
        CC_PAL_LOG_ERR("failed to CC_PalDmaBufferMap for mlli table 0x%x\n", rc);
        errorClearFlag = UNMAP_FLAG_MLLI_MAIN;
        rc = CC_RET_NOMEM;
        goto endError_dataPtrToDma;
    }

    // if case numOfBlocks returned bigger than 1, we declare error
    if (numOfBlocks > SINGLE_BLOCK_ENTRY) {
        CC_PAL_LOG_ERR("failed to CC_PalDmaBufferMap for mlli numOfBlocks > 1\n");
        errorClearFlag = (UNMAP_FLAG_MLLI_MAIN | UNMAP_FLAG_MLLI_TABLE);
        rc = CC_RET_OSFAULT;
        goto endError_dataPtrToDma;
    }

    SET_DMA_BUFF_WITH_MLLI(pDmaBuff,
                           pDevBuffer->mlliBlockInfo.blockPhysAddr,
                           pDevBuffer->mlliBlockInfo.blockSize);
    return 0;

endError_dataPtrToDma:

    if ((UNMAP_FLAG_MLLI_MAIN & errorClearFlag) || (UNMAP_FLAG_CONTIG_DLLI & errorClearFlag)) {
        CC_PalDmaBufferUnmap(pUsrBuffer,
                             usrBuffSize,
                             direction,
                             pUsrBlockList->numOfBlocks,
                             pUsrBlockList->pBlockEntry,
                             pInterBuildBuff->buffMainH);
    }
    if (UNMAP_FLAG_SMALL_SIZE_DLLI & errorClearFlag) {
        CC_PalDmaBufferUnmap(pOptBuff,
                             usrBuffSize,
                             direction,
                             pUsrBlockList->numOfBlocks,
                             pUsrBlockList->pBlockEntry,
                             pInterBuildBuff->buffOptH);
    }
    if (UNMAP_FLAG_MLLI_TABLE & errorClearFlag) {
        CC_PalDmaBufferUnmap((uint8_t *) pDevBuffer->pLliEntry,
                             pUsrBlockList->numOfBlocks * sizeof(lliInfo_t),
                             CC_PAL_DMA_DIR_BI_DIRECTION,
                             SINGLE_BLOCK_ENTRY,
                             &pDevBuffer->mlliBlockInfo,
                             pInterBuildBuff->buffMlliH);
    }
    return rc;

}

/**
 * @brief   sets user buffer into dma buffer to be used by HW
 *
 *
 * @param[in] pUsrBuffer - address of the buffer allocated by user
 * @param[in] usrBuffSize - data direction: into device, from device or bidirectional
 * @param[in] direction - bi-directional/to/from device
 * @param[in] pDmaBuff - dma buffer to be used by HW
 * @param[in] pInterBuildBuff - mlli list,  page list abd cookies used to build the dms bufffer
 *
 * @return success/fail
 */
static uint32_t buildDataPtrFromDma(uint8_t *pUsrBuffer,
                                    size_t usrBuffSize,
                                    CCPalDmaBufferDirection_t direction,
                                    DmaBuffer_s *pDmaBuff,
                                    interDmaBuildBuffer_t *pInterBuildBuff)
{
    uint32_t rc = 0;
    uint8_t *pOptBuff = NULL;
    mlliTable_t *pDevBuffer = NULL;
    dmaBuffBlocksInfo_t *pUsrBlockList = NULL;
    CC_PAL_LOG_INFO("%s:%d: uncache dir[%s] usrBuffSize[%zu]\n",
                    __func__,
                    __LINE__,
                    (const char *[]){ "none",
                    "to",
                    "from",
                    "bi" }[direction],
                    usrBuffSize);

    CC_UNUSED_PARAM(pDmaBuff);

    // check inputs
    if (NULL == pInterBuildBuff) {
        CC_PAL_LOG_ERR("invalid parameters\n");
        return CC_RET_INVARG;
    }
    // first check if buffer is NULL, build simple empty dma buffer
    if ((NULL == pUsrBuffer) || (0 == usrBuffSize)) {
        return 0;
    }

    pDevBuffer = &pInterBuildBuff->devBuffer;
    pUsrBlockList = &pInterBuildBuff->blocksList;
    pOptBuff = pInterBuildBuff->optimizationBuff;

    // second case, if buffer is contiguous build DLLI
    if (CC_PalIsDmaBufferContiguous(pUsrBuffer, usrBuffSize)) {
        rc = CC_PalDmaBufferUnmap(pUsrBuffer,
                                  usrBuffSize,
                                  direction,
                                  pUsrBlockList->numOfBlocks,
                                  pUsrBlockList->pBlockEntry,
                                  pInterBuildBuff->buffMainH);
        goto endError_dmaToDataPtr;
    }

    // in case buffer is not contiguous:
    // if buffer size smaller than  DLLI_OPTIMIZED_BUFF_SIZE:
    // copy user buffer to optimizedBuff to improve performance and build DLLI
    if (usrBuffSize < DLLI_OPTIMIZED_BUFF_SIZE) {
        // map optimizedBuff to get physical address and lock+invalidate
        rc = CC_PalDmaBufferUnmap((uint8_t *) pOptBuff,
                                  usrBuffSize,
                                  direction,
                                  pUsrBlockList->numOfBlocks,
                                  pUsrBlockList->pBlockEntry,
                                  pInterBuildBuff->buffOptH);

        // copy userBuffer to optimizedBuff
        if ((CC_PAL_DMA_DIR_FROM_DEVICE == direction) || (CC_PAL_DMA_DIR_BI_DIRECTION == direction)) {
            CC_PalMemCopy(pUsrBuffer, pOptBuff, usrBuffSize);
        }
        goto endError_dmaToDataPtr;
    }

    // otherwise (buffer size bigger than  DLLI_OPTIMIZED_BUFF_SIZE) build MLLI:
    // unmap the buffer
    rc = CC_PalDmaBufferUnmap(pUsrBuffer,
                              usrBuffSize,
                              direction,
                              pUsrBlockList->numOfBlocks,
                              pUsrBlockList->pBlockEntry,
                              pInterBuildBuff->buffMainH);
    // Unmap MLLI
    rc |= CC_PalDmaBufferUnmap((uint8_t *) pDevBuffer->pLliEntry,
                               pUsrBlockList->numOfBlocks * sizeof(lliInfo_t),
                               CC_PAL_DMA_DIR_BI_DIRECTION,
                               SINGLE_BLOCK_ENTRY,
                               &pDevBuffer->mlliBlockInfo,
                               pInterBuildBuff->buffMlliH);

endError_dmaToDataPtr:

    if (rc != 0) {
        rc = CC_RET_BUSY;
    }
    return rc;

}

/******************************************************************************
 *                          FUNCTION PROTOTYPES
 ******************************************************************************/
void freeDmaBuildBuffers(eDmaBuiltDir_t dir)
{
    uint32_t index;
    interDmaBuildBuffer_t *pDmaBuildBuffArr;

    if (dir >= DMA_BUILD_DIR_MAX) {
        CC_PAL_LOG_ERR("dir is not valid[%u]\n", dir);
        return;
    }

    pDmaBuildBuffArr = (dir == DMA_BUILD_DIR_IN ? g_dmaInBuildBuffArrH : g_dmaOutBuildBuffArrH);

    for (index = 0; index < NUM_OF_DMA_BUFFS; ++index) {

        interDmaBuildBuffer_t *pDmaBuildBuff = &pDmaBuildBuffArr[index];

        if (pDmaBuildBuff->optimizationBuff != NULL) {
            CC_PalDmaContigBufferFree(DLLI_OPTIMIZED_BUFF_SIZE, pDmaBuildBuff->optimizationBuff);
            pDmaBuildBuff->optimizationBuff = NULL;
        }
        if (pDmaBuildBuff->devBuffer.pLliEntry != NULL) {
            CC_PalDmaContigBufferFree(LLI_MAX_NUM_OF_ENTRIES * sizeof(lliInfo_t),
                                      (uint8_t *) pDmaBuildBuff->devBuffer.pLliEntry);
            pDmaBuildBuff->devBuffer.pLliEntry = NULL;
        }
    }
}

uint32_t allocDmaBuildBuffers(eDmaBuiltDir_t dir)
{
    uint32_t rc = 0;
    uint8_t *tmpBuff = NULL;
    uint32_t index;
    interDmaBuildBuffer_t *pDmaBuildBuffArr;

    if (dir >= DMA_BUILD_DIR_MAX) {
        CC_PAL_LOG_ERR("dir is not valid[%u]\n", dir);
        return CC_RET_INVARG;
    }

    pDmaBuildBuffArr = (dir == DMA_BUILD_DIR_IN ? g_dmaInBuildBuffArrH : g_dmaOutBuildBuffArrH);

    for (index = 0; index < NUM_OF_DMA_BUFFS; ++index) {

        interDmaBuildBuffer_t *pDmaBuildBuff = &pDmaBuildBuffArr[index];
        tmpBuff = (uint8_t *) pDmaBuildBuff->devBuffer.pLliEntry;
        rc = CC_PalDmaContigBufferAllocate(LLI_MAX_NUM_OF_ENTRIES * sizeof(lliInfo_t), &tmpBuff);
        if (rc != 0) {
            CC_PAL_LOG_ERR("failed to allocated pLliEntry in index[%u]\n", index);
            return CC_RET_NOMEM;
        }
        if (!IS_ALIGNED((unsigned long) tmpBuff, 4))
        {
            CC_PAL_LOG_ERR("Allocated pLliEntry in not alligned to 4, index[%u]\n", index);
            return CC_RET_INVARG_BAD_ADDR;
        }

        /* casting to void to avoid compilation error , address must be aligned to word , otherwise an error will return */
        pDmaBuildBuff->devBuffer.pLliEntry = (lliInfo_t *) ((void*) tmpBuff);

        rc = CC_PalDmaContigBufferAllocate(DLLI_OPTIMIZED_BUFF_SIZE,
                                           &pDmaBuildBuff->optimizationBuff);
        if (rc != 0) {
            freeDmaBuildBuffers(dir);
            CC_PAL_LOG_ERR("failed to allocated optimizationBuff in index[%u]\n", index);
            return CC_RET_NOMEM;
        }
    }

    clearDmaBuildBuffers(dir);

    return CC_RET_OK;
}

uint32_t SymDriverAdaptorBuildDataPtrFromDma(void* pDataIn,
                                             void* pDataOut,
                                             size_t dataSize,
                                             DmaBuffer_s *pDmaBuffIn,
                                             DmaBuffer_s *pDmaBuffOut,
                                             eDmaBuiltFlag_t dmaBuiltFlag,
                                             bool isSm4Ofb,
                                             uint32_t dmaBuildBufferIndex)
{
    uint32_t retCode = 0;
    uint32_t finRetCode = 0;

    // in case of inplace - unmap only one buffer bi directional
    if (dmaBuiltFlag & DMA_BUILT_FLAG_BI_DIR) {
        retCode = buildDataPtrFromDma((uint8_t *) pDataIn,
                                      dataSize,
                                      CC_PAL_DMA_DIR_BI_DIRECTION,
                                      pDmaBuffIn,
                                      &g_dmaInBuildBuffArrH[dmaBuildBufferIndex]);
        if (retCode != 0) {
            CC_PAL_LOG_ERR("failed to buildDataPtrFromDma for pDataIn inplace 0x%x\n", retCode);
            finRetCode = retCode;
        }
    }

    /* for SM4 OFB use const DIN - no dma buffer exists */
    if ((dmaBuiltFlag & DMA_BUILT_FLAG_INPUT_BUFF) && (isSm4Ofb == false)) {
        retCode = buildDataPtrFromDma((uint8_t *) pDataIn,
                                      dataSize,
                                      CC_PAL_DMA_DIR_TO_DEVICE,
                                      pDmaBuffIn,
                                      &g_dmaInBuildBuffArrH[dmaBuildBufferIndex]);
        if (retCode != 0) {
            CC_PAL_LOG_ERR("failed to buildDataPtrFromDma for pDataIn 0x%x\n", retCode);
            if (finRetCode == 0) {
                finRetCode = retCode;
            }
        }
    }

    if (dmaBuiltFlag & DMA_BUILT_FLAG_OUTPUT_BUFF) {
        retCode = buildDataPtrFromDma((uint8_t *) pDataOut,
                                      dataSize,
                                      CC_PAL_DMA_DIR_FROM_DEVICE,
                                      pDmaBuffOut,
                                      &g_dmaOutBuildBuffArrH[dmaBuildBufferIndex]);
        if (retCode != 0) {
            CC_PAL_LOG_ERR("failed to buildDataPtrFromDma for pDataOut 0x%x\n", retCode);
            if (finRetCode == 0) {
                finRetCode = retCode;
            }
        }
    }

    return finRetCode;
}

uint32_t SymDriverAdaptorBuildDmaFromDataPtr(void* pDataIn,
                                             void* pDataOut,
                                             size_t dataSize,
                                             DmaBuffer_s *pDmaBuffIn,
                                             DmaBuffer_s *pDmaBuffOut,
                                             eDmaBuiltFlag_t *pDmaBuiltFlag,
                                             uint8_t isInPlace,
                                             bool isSm4Ofb,
                                             uint32_t dmaBuildBufferIndex)
{
    uint32_t retCode = 0;

    /* in case of inplace - map only one buffer bi directional */
    if (isInPlace == INPLACE) {
        retCode = buildDmaFromDataPtr((uint8_t *) pDataIn,
                                      dataSize,
                                      CC_PAL_DMA_DIR_BI_DIRECTION,
                                      pDmaBuffIn,
                                      &g_dmaInBuildBuffArrH[dmaBuildBufferIndex]);
        if (retCode != 0) {
            CC_PAL_LOG_ERR("failed to buildDmaFromDataPtr for pDataIn inplace 0x%x\n", retCode);
            goto EndWithErr;
        }

        *pDmaBuiltFlag = DMA_BUILT_FLAG_BI_DIR;
        COPY_DMA_BUFF((*pDmaBuffOut), (*pDmaBuffIn));
    } else {

        if (isSm4Ofb == true) {
            /* for SM4 OFB use const DIN - no need to build dma buffer */
            pDmaBuffIn->size = dataSize;
            pDmaBuffIn->dmaBufType = DMA_SRAM;
        } else {

            retCode = buildDmaFromDataPtr((uint8_t *) pDataIn,
                                          dataSize,
                                          CC_PAL_DMA_DIR_TO_DEVICE,
                                          pDmaBuffIn,
                                          &g_dmaInBuildBuffArrH[dmaBuildBufferIndex]);

            if (retCode != 0) {
                CC_PAL_LOG_ERR("failed to buildDmaFromDataPtr for pDataIn 0x%x\n", retCode);
                goto EndWithErr;
            }
        }

        *pDmaBuiltFlag = DMA_BUILT_FLAG_INPUT_BUFF;
        retCode = buildDmaFromDataPtr((uint8_t *) pDataOut,
                                      dataSize,
                                      CC_PAL_DMA_DIR_FROM_DEVICE,
                                      pDmaBuffOut,
                                      &g_dmaOutBuildBuffArrH[dmaBuildBufferIndex]);

        if (retCode != 0) {
            CC_PAL_LOG_ERR("failed to buildDmaFromDataPtr for pDataOut 0x%x\n", retCode);
            uint32_t localRetCode = 0;

            localRetCode = buildDataPtrFromDma((uint8_t *) pDataIn,
                                               dataSize,
                                               CC_PAL_DMA_DIR_TO_DEVICE,
                                               pDmaBuffIn,
                                               &g_dmaInBuildBuffArrH[dmaBuildBufferIndex]);
            if (localRetCode != 0) {
                CC_PAL_LOG_ERR("failed to buildDataPtrFromDma for pDataIn 0x%x\n", localRetCode);
                goto EndWithErr;
            }

        }

        *pDmaBuiltFlag |= DMA_BUILT_FLAG_OUTPUT_BUFF;
    }

    return 0;

EndWithErr:
    *pDmaBuiltFlag = 0;
    return retCode;
}
