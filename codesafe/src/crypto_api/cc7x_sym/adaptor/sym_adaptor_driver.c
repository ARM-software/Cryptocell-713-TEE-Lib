/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */
#define CC_PAL_LOG_CUR_COMPONENT CC_LOG_MASK_CC_SYM_DRIVER

#include "cc_pal_types.h"
#include "cc_plat.h"
#include "cc_pal_mem.h"
#include "cc_pal_dma.h"
#include "cc_pal_log.h"
#include "cc_pal_mutex.h"
#include "cc_pal_abort.h"
#include "cc_sym_error.h"
#include "cc_plat.h"
#include "cc_crypto_ctx.h"
#include "completion.h"
#include "cc_pal_perf.h"
#include "sym_crypto_driver.h"
#include "sym_adaptor_driver.h"
#include "sym_adaptor_util.h"
#include "sym_adaptor_driver_int.h"
#include "cc_sram_map.h"
#include "cc_hal.h"
#include "cc_lli_defs.h"
#include "cc_int_general_defs.h"

/******************************************************************************
 *              TYPES
 ******************************************************************************/

/******************************************************************************
 *				GLOBALS
 ******************************************************************************/

extern CC_PalMutex CCSymCryptoMutex;
/******************************************************************************
 *				PRIVATE FUNCTIONS
 ******************************************************************************/

/*!
 * The function returns the context size according to the algorithm type
 *
 *
 * \param pCtx
 *
 * \return int The size of the context in bytes.
 */
static int getCtxSize(enum drv_crypto_alg alg)
{
    uint32_t ctxSize; /*size in words*/

    switch (alg) {
        case DRV_CRYPTO_ALG_DES:
        case DRV_CRYPTO_ALG_AES:
        case DRV_CRYPTO_ALG_SM4:
            /* copied fields block_state + key + xex_key */
            ctxSize = CC_AES_BLOCK_SIZE + CC_AES_KEY_SIZE_MAX + CC_AES_KEY_SIZE_MAX;
            break;
        case DRV_CRYPTO_ALG_HMAC:
            /* digest + k0 size + CurrentDigestedLength */
            ctxSize = CC_DIGEST_SIZE_MAX + CC_HMAC_BLOCK_SIZE_MAX
                            + DRV_HASH_LENGTH_WORDS * sizeof(uint32_t);
            break;
        case DRV_CRYPTO_ALG_HASH:
        case DRV_CRYPTO_ALG_SM3:
            /* digest + CurrentDigestedLength */
            ctxSize = CC_DIGEST_SIZE_MAX + DRV_HASH_LENGTH_WORDS * sizeof(uint32_t);
            break;

        case DRV_CRYPTO_ALG_BYPASS:
            ctxSize = sizeof(uint32_t);
            break;
        case DRV_CRYPTO_ALG_AEAD:
            /* block_state + mac_state + key + nonce + j0 + LenA & LenC */
            ctxSize = 5 * CC_AES_BLOCK_SIZE + CC_AES_KEY_SIZE_MAX;
            break;
        default:
            ctxSize = 0;
            break;
    }
    return ctxSize;
}

static void isCopyCtxRequired(enum drv_crypto_alg alg, int mode, uint8_t *flag)
{
    *flag = 0;

    switch (alg) {
        case DRV_CRYPTO_ALG_AES:
            if (mode == DRV_CIPHER_XCBC_MAC) {
                *flag = 1;
            }
            break;
        case DRV_CRYPTO_ALG_AEAD:
        case DRV_CRYPTO_ALG_DES:
        case DRV_CRYPTO_ALG_HMAC:
        case DRV_CRYPTO_ALG_HASH:
        case DRV_CRYPTO_ALG_SM3:
            *flag = 1;
            break;
        case DRV_CRYPTO_ALG_BYPASS:
            break;
        default:
            break;
    }
}

/******************************************************************************
 *				PUBLIC FUNCTIONS
 ******************************************************************************/

/*!
 * Allocate sym adaptor driver resources
 *
 * \param None
 *
 * \return 0 for success, otherwise failure
 */
int SymDriverAdaptorModuleInit()
{
    int symRc = CC_RET_OK;

    symRc = allocDmaBuildBuffers(DMA_BUILD_DIR_IN);
    if (symRc != CC_RET_OK) {
        return CC_RET_NOMEM;
    }

    symRc = allocDmaBuildBuffers(DMA_BUILD_DIR_OUT);
    if (symRc != CC_RET_OK) {
        freeDmaBuildBuffers(DMA_BUILD_DIR_IN);
        return CC_RET_NOMEM;
    }

    symRc = AllocCompletionPlatBuffer();
    if (symRc != CC_RET_OK) {
        freeDmaBuildBuffers(DMA_BUILD_DIR_IN);
        freeDmaBuildBuffers(DMA_BUILD_DIR_OUT);
        return CC_RET_NOMEM;
    }

    return CC_RET_OK;
}

/*!
 * Release sym adaptor driver resources
 *
 * \param None
 *
 * \return always success
 */
int SymDriverAdaptorModuleTerminate()
{
    freeDmaBuildBuffers(DMA_BUILD_DIR_IN);
    freeDmaBuildBuffers(DMA_BUILD_DIR_OUT);
    FreeCompletionPlatBuffer();

    return CC_RET_OK;
}

static uint32_t SymDriverAdaptorCopySramBuff(driverAdaptorDir_t dir,
                                             CCSramAddr_t sram_addr,
                                             uint32_t *buff,
                                             uint32_t size)
{
    DmaBuffer_s dmaBuffIn, dmaBuffOut;
    CC_PalDmaBufferHandle dmaHandle;
    CCPalDmaBlockInfo_t dmaBlockEntry;
    uint32_t numOfBlocks;
    uint32_t rc, symRc;
    numOfBlocks = SINGLE_BLOCK_ENTRY;

    rc = CC_PalDmaBufferMap((uint8_t *) buff,
                            size,
                            CC_PAL_DMA_DIR_BI_DIRECTION,
                            &numOfBlocks,
                            &dmaBlockEntry,
                            &dmaHandle);
    if (rc != 0) {
        CC_PAL_LOG_ERR("failed to CC_PalDmaBufferMap for contig user context  0x%x\n", rc);
        return CC_RET_NOMEM;
    }

    if (dir == DRIVER_ADAPTOR_DIR_IN) {
        SET_DMA_BUFF_WITH_DLLI(((DmaBuffer_s* )&dmaBuffIn), dmaBlockEntry.blockPhysAddr, size);
        SET_DMA_BUFF(((DmaBuffer_s* )&dmaBuffOut), sram_addr, size, DMA_BUF_SEP, 0);
    } else {
        SET_DMA_BUFF_WITH_DLLI(((DmaBuffer_s* )&dmaBuffOut), dmaBlockEntry.blockPhysAddr, size);
        SET_DMA_BUFF(((DmaBuffer_s* )&dmaBuffIn), sram_addr, size, DMA_BUF_SEP, 0);
    }

    /* Write BYPASS without use of context. the ALG of bypass is now passed as a parameter to the
     dispatch process. the context address is not used by processBypass  */
    symRc = SymDriverDispatchProcess(0, buff, &dmaBuffIn, &dmaBuffOut, DRV_CRYPTO_ALG_BYPASS);
    if (symRc != CC_RET_OK) {
        goto EndWithErr;
    }

    WaitForSequenceCompletion(CC_TRUE);

EndWithErr:

    rc = CC_PalDmaBufferUnmap((uint8_t *) buff,
                              size,
                              CC_PAL_DMA_DIR_BI_DIRECTION,
                              numOfBlocks,
                              &dmaBlockEntry,
                              dmaHandle);
    if (symRc) {
        return symRc;
    }

    return rc;
}

uint32_t SymDriverAdaptorCopyCtx(driverAdaptorDir_t dir,
                                 CCSramAddr_t sram_address,
                                 uint32_t *pCtx,
                                 enum drv_crypto_alg alg)
{
    uint32_t rc = 0;
    switch (dir) {
        case DRIVER_ADAPTOR_DIR_IN:
        case DRIVER_ADAPTOR_DIR_OUT:
            rc = SymDriverAdaptorCopySramBuff(dir,
                                              sram_address,
                                              (uint32_t*) pCtx,
                                              getCtxSize(alg));
            break;
        default:
            rc = CC_RET_INVARG;
            break;
    }

    return rc;
}

/*!
 * Initializes the caller context by invoking the symmetric dispatcher driver.
 * The caller context may resides in SRAM or DCACHE SEP areas.
 * This function flow is synchronous.
 *
 * \param pCtx
 *
 * \return int One of CC_RET_* error codes defined in cc_sym_error.h.
 */
int SymDriverAdaptorInit(uint32_t *pCtx, enum drv_crypto_alg alg, int mode)
{
    int symRc = CC_RET_OK;
    CCPalPerfData_t perfIdx = 0;
    uint8_t isCpyCtxFlag = 0;

    CC_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_SYM_DRV_INIT);
    CC_PAL_LOG_INFO("pCtx=%p\n", pCtx);
    if (pCtx == NULL) {
        CC_PAL_LOG_ERR("NULL pointer was given for ctx\n");
        CC_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_SYM_DRV_INIT);
        return CC_RET_INVARG_CTX;
    }

    symRc = CC_PalMutexLock(&CCSymCryptoMutex, CC_INFINITE);
    if (symRc != CC_SUCCESS) {
        CC_PalAbort("Fail to acquire mutex\n");
    }

    isCopyCtxRequired(alg, mode, &isCpyCtxFlag);

    if (isCpyCtxFlag) {
        symRc = SymDriverAdaptorCopyCtx(DRIVER_ADAPTOR_DIR_IN,
                                        CC_SRAM_DRIVER_ADAPTOR_CONTEXT_CACHE_ADDR,
                                        pCtx,
                                        alg);
        if (symRc != CC_RET_OK) {
            goto EndWithErr;
        }
    }

    /* call the dispatcher with the new context pointer in SRAM */
    symRc = SymDriverDispatchInit(CC_SRAM_DRIVER_ADAPTOR_CONTEXT_CACHE_ADDR, pCtx, alg);
    if (symRc != CC_RET_OK) {
        goto EndWithErr;
    }

    WaitForSequenceCompletion(CC_TRUE);

    if (isCpyCtxFlag) {
        symRc = SymDriverAdaptorCopyCtx(DRIVER_ADAPTOR_DIR_OUT,
                                        CC_SRAM_DRIVER_ADAPTOR_CONTEXT_CACHE_ADDR,
                                        pCtx,
                                        alg);
    }

EndWithErr:

    CC_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_SYM_DRV_INIT);

    if (CC_PalMutexUnlock(&CCSymCryptoMutex) != CC_SUCCESS) {
        CC_PalAbort("Fail to release mutex\n");
    }
    return symRc;
}

/*!
 * Process a cryptographic data by invoking the symmetric dispatcher driver.
 * The invoker may request any amount of data aligned to the given algorithm
 * block size. It uses a scratch pad to copy (in cpu mode) the user
 * data from DCACHE/ICACHE to SRAM for processing. This function flow is
 * synchronous.
 *
 * \param pCtx may resides in SRAM or DCACHE SeP areas
 * \param pDataIn The input data buffer. It may reside in SRAM, DCACHE or ICACHE SeP address range
 * \param pDataOut The output data buffer. It may reside in SRAM or DCACHE SeP address range
 * \param DataSize The data input size in octets
 * \param alg The algorithm of the operation.
 *
 * \return int One of CC_RET_* error codes defined in cc_sym_error.h.
 */
int SymDriverAdaptorProcess(uint32_t* pCtx,
                            void* pDataIn,
                            void* pDataOut,
                            size_t DataSize,
                            enum drv_crypto_alg alg)
{
    int symRc = CC_RET_OK;
    int localSymRc = CC_RET_OK;

    DmaBuffer_s dmaBuffIn;
    DmaBuffer_s dmaBuffOut;
    struct drv_ctx_cipher *pContext = (struct drv_ctx_cipher *) pCtx;
    uint32_t dmaBuiltFlag = DMA_BUILT_FLAG_NONE;
    CCPalPerfData_t perfIdx = 0;
    bool isSm4Ofb;

    CC_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_SYM_DRV_PROC);
    CC_PAL_LOG_INFO("pCtx=%p\n", pCtx);
    CC_PAL_LOG_INFO("IN addr=%p OUT addr=%p DataSize=%u\n", pDataIn, pDataOut, DataSize);

    if (pCtx == NULL) {
        CC_PAL_LOG_ERR("NULL pointer was given for ctx\n");
        CC_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_SYM_DRV_PROC);
        return CC_RET_INVARG_CTX;
    }

    isSm4Ofb = (alg == DRV_CRYPTO_ALG_SM4) && (pContext->isSm4Ofb == true);

    if ((isSm4Ofb == false) && (pDataIn == NULL)) {
        CC_PAL_LOG_ERR("NULL pointer was given for din\n");
        CC_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_SYM_DRV_PROC);
        return CC_RET_INVARG_CTX;
    }

    /* In AES mac modes there is no output so it needs special treatment */
    if ((alg == DRV_CRYPTO_ALG_AES)
                    && ((pContext->mode == DRV_CIPHER_CBC_MAC)
                                    || (pContext->mode == DRV_CIPHER_XCBC_MAC)
                                    || (pContext->mode == DRV_CIPHER_CMAC))) {
        /* clear the output to mark that it is not used */
        pDataOut = NULL;
    }

    symRc = CC_PalMutexLock(&CCSymCryptoMutex, CC_INFINITE);
    if (symRc != CC_SUCCESS) {
        CC_PalAbort("Fail to acquire mutex\n");
    }

    symRc = SymDriverAdaptorBuildDmaFromDataPtr(pDataIn,
                                                pDataOut,
                                                DataSize,
                                                &dmaBuffIn,
                                                &dmaBuffOut,
                                                &dmaBuiltFlag,
                                                (pDataIn == pDataOut) ? INPLACE : NOT_INPLACE,
                                                isSm4Ofb,
                                                SYM_ADAPTOR_BUFFER_INDEX);
    if (symRc != CC_RET_OK) {
        /* skip unmapping of the buffers */
        goto ProcessUnlockMutex;
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
    localSymRc = SymDriverAdaptorBuildDataPtrFromDma(pDataIn,
                                                     pDataOut,
                                                     DataSize,
                                                     &dmaBuffIn,
                                                     &dmaBuffOut,
                                                     dmaBuiltFlag,
                                                     isSm4Ofb,
                                                     SYM_ADAPTOR_BUFFER_INDEX);

    if (symRc == CC_RET_OK) {
        symRc = localSymRc;
    }

ProcessUnlockMutex:
    CC_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_SYM_DRV_PROC);

    if (CC_PalMutexUnlock(&CCSymCryptoMutex) != CC_SUCCESS) {
        CC_PalAbort("Fail to release mutex\n");
    }

    return symRc;
}

/*!
 * Finalizing the cryptographic data by invoking the symmetric dispatcher driver.
 * It calls the `SymDriverDcacheAdaptorFinalize` function for processing by leaving
 * any reminder for the finalize operation.
 *
 * \param pCtx may resides in SRAM or DCACHE SeP areas
 * \param pDataIn The input data buffer. It may reside in SRAM, DCACHE or ICACHE SeP address range
 * \param pDataOut The output data buffer. It may reside in SRAM or DCACHE SeP address range
 * \param DataSize The data input size in octets
 * \param alg The algorithm of the operation.
 *
 * \return int One of CC_RET_* error codes defined in cc_sym_error.h.
 */
int SymDriverAdaptorFinalize(uint32_t* pCtx,
                             void* pDataIn,
                             void* pDataOut,
                             size_t DataSize,
                             enum drv_crypto_alg alg)
{
    DmaBuffer_s dmaBuffIn;
    DmaBuffer_s dmaBuffOut;
    int symRc = CC_RET_OK;
    int localSymRc = CC_RET_OK;
    struct drv_ctx_cipher *pAesContext = (struct drv_ctx_cipher *) pCtx;
    uint32_t retCode;
    /* used to differ AES MAC modes (where the dout is not NULL, but is not access via DMA */
    uint32_t isMac = CC_FALSE;
    void *pTmpDataOut = pDataOut;
    uint32_t dmaBuiltFlag = DMA_BUILT_FLAG_NONE;
    CCPalPerfData_t perfIdx = 0;
    bool isSm4Ofb;

    CC_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_SYM_DRV_FIN);

    CC_PAL_LOG_INFO("pCtx=%p\n", pCtx);
    CC_PAL_LOG_INFO("IN addr=%p OUT addr=%p DataSize=%u\n", pDataIn, pDataOut, DataSize);

    /* do not check din pointer since hash/hmac algs has no data input */
    if (pCtx == NULL) {
        CC_PAL_LOG_ERR("NULL pointer was given for ctx\n");
        CC_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_SYM_DRV_FIN);
        return CC_RET_INVARG_CTX;
    }

    isSm4Ofb = (alg == DRV_CRYPTO_ALG_SM4) && (pAesContext->isSm4Ofb == true) &&
            (DataSize != 0);

    if ((alg == DRV_CRYPTO_ALG_AES)
                    && ((pAesContext->mode == DRV_CIPHER_CBC_MAC)
                                    || (pAesContext->mode == DRV_CIPHER_XCBC_MAC)
                                    || (pAesContext->mode == DRV_CIPHER_CMAC))) {
        isMac = CC_TRUE;
        pTmpDataOut = NULL;
    }

    retCode = CC_PalMutexLock(&CCSymCryptoMutex, CC_INFINITE);
    if (retCode != CC_SUCCESS) {
        CC_PalAbort("Fail to acquire mutex\n");
    }

    // in case of inplace - map only one buffer bi directional
    symRc = SymDriverAdaptorBuildDmaFromDataPtr(pDataIn,
                                                pTmpDataOut,
                                                DataSize,
                                                &dmaBuffIn,
                                                &dmaBuffOut,
                                                &dmaBuiltFlag,
                                                (pDataIn == pDataOut && !isMac) ?
                                                                INPLACE : NOT_INPLACE,
                                                isSm4Ofb,
                                                SYM_ADAPTOR_BUFFER_INDEX);
    if (symRc != CC_RET_OK) {
        /* skip unmapping of the buffers */
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
    if (symRc != CC_RET_OK) {
        goto EndWithErr;
    }

    if (isMac == CC_TRUE) {
        switch (pAesContext->mode) {
            case DRV_CIPHER_CBC_MAC:
            case DRV_CIPHER_XCBC_MAC:
            case DRV_CIPHER_CMAC:
                if (pDataOut == NULL) { /* in case of MAC the data out must not be NULL (MAC is copied to it) */
                    symRc = CC_RET_INVARG;
                    goto EndWithErr;
                }
                CC_PalMemCopy(pDataOut, pAesContext->block_state, CC_AES_BLOCK_SIZE);
                break;
            default:
                break;
        }
    }

EndWithErr:
    localSymRc = SymDriverAdaptorBuildDataPtrFromDma(pDataIn,
                                                     pTmpDataOut,
                                                     DataSize,
                                                     &dmaBuffIn,
                                                     &dmaBuffOut,
                                                     dmaBuiltFlag,
                                                     isSm4Ofb,
                                                     SYM_ADAPTOR_BUFFER_INDEX);

    if (symRc == CC_RET_OK) {
        symRc = localSymRc;
    }

finalizeUnlockMutex:

    CC_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_SYM_DRV_FIN);

    if (CC_PalMutexUnlock(&CCSymCryptoMutex) != CC_SUCCESS) {
        CC_PalAbort("Fail to release mutex\n");
    }

    return symRc;
}

