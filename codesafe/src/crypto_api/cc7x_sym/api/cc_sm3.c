/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#define CC_PAL_LOG_CUR_COMPONENT CC_LOG_MASK_CC_API

#include "cc_pal_types.h"
#include "cc_pal_mem.h"
#include "cc_sm3_defs.h"
#include "cc_sm3_error.h"
#include "sym_adaptor_driver.h"
#include "dma_buffer.h"
#include "cc_sym_error.h"
#include "cc_context_relocation.h"
#include "cc_pal_perf.h"
#include "cc_chinese_cert_defs.h"

/************************ Defines ******************************/
#if ( CC_DRV_CTX_SIZE_WORDS > CC_SM3_USER_CTX_SIZE_IN_WORDS )
#error CC_SM3_USER_CTX_SIZE_IN_WORDS is not defined correctly.
#endif
/* Since the user context in the TEE is doubled to allow it to be contiguous we must get */
/* the real size of the context to get the private context pointer                       */
#define CC_SM3_USER_CTX_ACTUAL_SIZE_IN_WORDS   ((CC_SM3_USER_CTX_SIZE_IN_WORDS - 3)/2)

/************************ Type definitions **********************/
typedef struct {
    uint8_t remainingBuf[CC_SM3_BLOCK_SIZE_IN_BYTES];
    uint32_t remainingBufSize;
} CCSm3PrivCtx_t;

/************************ Public Functions ******************************/

/*!
 * Converts Symmetric Adaptor return code to CC error code.
 *
 * \param symRetCode Symmetric Adaptor return error.
 * \param errorInfo Ignored.
 *
 * \return CCError_t one of CC_* error codes defined in cc_error.h
 */
static CCError_t SymAdaptor2CCSm3Err(int symRetCode, uint32_t errorInfo)
{
    errorInfo = errorInfo;
    switch (symRetCode) {
        case CC_RET_UNSUPP_ALG:
            return CC_SM3_IS_NOT_SUPPORTED;
        case CC_RET_INVARG:
            return CC_SM3_ILLEGAL_PARAMS_ERROR;
        case CC_RET_INVARG_KEY_SIZE:
        case CC_RET_INVARG_CTX_IDX:
            return CC_SM3_INVALID_USER_CONTEXT_POINTER_ERROR;
        case CC_RET_INVARG_CTX:
            return CC_SM3_USER_CONTEXT_CORRUPTED_ERROR;
        case CC_RET_INVARG_BAD_ADDR:
            return CC_SM3_DATA_IN_POINTER_INVALID_ERROR;
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

CEXPORT_C CCError_t CC_Sm3Init(CCSm3UserContext_t *pContextID)
{
    struct drv_ctx_hash *pSm3Context;
    CCSm3PrivCtx_t *pSm3PrivCtx;
    CCPalPerfData_t perfIdx = 0;
    int symRc = CC_RET_OK;

    CC_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_CC_SM3_INIT);

    CHECK_AND_RETURN_ERR_UPON_CH_CERT_ERROR();

    if (pContextID == NULL) {
        return CC_SM3_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    /* Pointer for CTX  allocation*/
    /* FUNCTION LOGIC: Get pointer to contiguous context in the HOST buffer */
    pSm3Context = (struct drv_ctx_hash *) RcInitUserCtxLocation(pContextID->buff,
                                                                sizeof(CCSm3UserContext_t),
                                                                sizeof(struct drv_ctx_hash));

    if (pSm3Context == NULL) {
        return CC_SM3_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    pSm3PrivCtx = (CCSm3PrivCtx_t *) &(((uint32_t*) pSm3Context)[CC_DRV_CTX_SIZE_WORDS - 1]);
    pSm3Context->alg = DRV_CRYPTO_ALG_SM3;
    pSm3PrivCtx->remainingBufSize = 0;
    pSm3Context->mode = DRV_HASH_SM3;
    symRc = SymDriverAdaptorInit((uint32_t *) pSm3Context, pSm3Context->alg, pSm3Context->mode);

    CC_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_CC_SM3_INIT);

    return CC_CRYPTO_RETURN_ERROR(symRc, 0, SymAdaptor2CCSm3Err);
}

CEXPORT_C CCError_t CC_Sm3Update(CCSm3UserContext_t *pContextID,
                                 uint8_t *pDataIn,
                                 size_t DataInSize)
{
    struct drv_ctx_hash *pSm3Context;
    CCSm3PrivCtx_t *pSm3PrivCtx;
    uint32_t sm3_block_size_in_bytes = 0;
    uint32_t dataToProcessSize = 0;
    CCPalPerfData_t perfIdx = 0;
    int symRc = CC_RET_OK;

    CC_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_CC_SM3_UPDATE);

    CHECK_AND_RETURN_ERR_UPON_CH_CERT_ERROR();

    if (pContextID == NULL) {
        return CC_SM3_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    if (DataInSize == 0) {
        return CC_OK;
    }

    if (pDataIn == NULL) {
        return CC_SM3_DATA_IN_POINTER_INVALID_ERROR;
    }

    /* Get pointer to contiguous context in the HOST buffer */
    pSm3Context = (struct drv_ctx_hash *) RcGetUserCtxLocation(pContextID->buff);
    pSm3PrivCtx = (CCSm3PrivCtx_t *) &(((uint32_t*) pSm3Context)[CC_DRV_CTX_SIZE_WORDS - 1]);
    sm3_block_size_in_bytes = CC_SM3_BLOCK_SIZE_IN_BYTES;

    /* If there is previous data in the remaining buffer, try to fill the buffer with the current data */
    dataToProcessSize = min((sm3_block_size_in_bytes - pSm3PrivCtx->remainingBufSize)
                                            % sm3_block_size_in_bytes,
                            DataInSize);
    if (dataToProcessSize > 0) {
        /* add the data to the remaining buffer */
        CC_PalMemCopy(&(pSm3PrivCtx->remainingBuf[pSm3PrivCtx->remainingBufSize]),
                      pDataIn,
                      dataToProcessSize);
        pSm3PrivCtx->remainingBufSize += dataToProcessSize;
        /* and "remove" it from the buffer of DataIn  */
        pDataIn += dataToProcessSize;
        DataInSize -= dataToProcessSize;
    }

    /* If the remaining buffer is full, process the block (else, the remaining buffer will be processed in the next update or finish) */
    if (pSm3PrivCtx->remainingBufSize == sm3_block_size_in_bytes) {
        symRc = SymDriverAdaptorProcess((uint32_t *) pSm3Context,
                                        pSm3PrivCtx->remainingBuf,
                                        NULL,
                                        pSm3PrivCtx->remainingBufSize,
                                        pSm3Context->alg);
        if (symRc != CC_RET_OK) {
            return CC_CRYPTO_RETURN_ERROR(symRc, 0, SymAdaptor2CCSm3Err);
        }
        pSm3PrivCtx->remainingBufSize = 0;
    }

    /* Process all the blocks that remain in the data */
    dataToProcessSize = (DataInSize / sm3_block_size_in_bytes) * sm3_block_size_in_bytes;
    if (dataToProcessSize > 0) {
        symRc = SymDriverAdaptorProcess((uint32_t *) pSm3Context,
                                        pDataIn,
                                        NULL,
                                        dataToProcessSize,
                                        pSm3Context->alg);
        if (symRc != CC_RET_OK) {
            return CC_CRYPTO_RETURN_ERROR(symRc, 0, SymAdaptor2CCSm3Err);
        }
        /* "remove" the processed data from the buffer of DataIn  */
        pDataIn += dataToProcessSize;
        DataInSize -= dataToProcessSize;
    }

    /* The remaining partial block is kept to the next update or finish */
    dataToProcessSize = DataInSize;
    if (dataToProcessSize > 0) {
        CC_PalMemCopy(&(pSm3PrivCtx->remainingBuf[pSm3PrivCtx->remainingBufSize]),
                      pDataIn,
                      dataToProcessSize);
        pSm3PrivCtx->remainingBufSize += dataToProcessSize;
    }

    CC_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_CC_SM3_UPDATE);

    return CC_OK;

}

CEXPORT_C CCError_t CC_Sm3Finish(CCSm3UserContext_t *pContextID, CCSm3ResultBuf_t Sm3ResultBuff)
{
    struct drv_ctx_hash *pSm3Context;
    CCSm3PrivCtx_t *pSm3PrivCtx;
    uint8_t* DataIn_ptr = NULL;
    uint32_t DataInSize = 0;
    CCPalPerfData_t perfIdx = 0;
    int symRc = CC_RET_OK;

    CC_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_CC_SM3_FIN);

    CHECK_AND_RETURN_ERR_UPON_CH_CERT_ERROR();

    if (pContextID == NULL) {
        return CC_SM3_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    if (Sm3ResultBuff == NULL) {
        return CC_SM3_INVALID_RESULT_BUFFER_POINTER_ERROR;
    }

    /* Get pointer to contiguous context in the HOST buffer */
    pSm3Context = (struct drv_ctx_hash *) RcGetUserCtxLocation(pContextID->buff);
    pSm3PrivCtx = (CCSm3PrivCtx_t *) &(((uint32_t*) pSm3Context)[CC_DRV_CTX_SIZE_WORDS - 1]);

    /* if there is data in the remaining data, process it (else, use null DataIn buffer) */
    if (pSm3PrivCtx->remainingBufSize > 0) {
        DataIn_ptr = pSm3PrivCtx->remainingBuf;
        DataInSize = pSm3PrivCtx->remainingBufSize;
    }
    symRc = SymDriverAdaptorFinalize((uint32_t *) pSm3Context,
                                     DataIn_ptr,
                                     NULL,
                                     DataInSize,
                                     pSm3Context->alg);
    if (symRc != CC_RET_OK) {
        return CC_CRYPTO_RETURN_ERROR(symRc, 0, SymAdaptor2CCSm3Err);
    }
    pSm3PrivCtx->remainingBufSize = 0;

    /* Copy the result to the user buffer */
    CC_PalMemCopy(Sm3ResultBuff, pSm3Context->digest, CC_SM3_RESULT_SIZE_IN_BYTES);

    CC_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_CC_HASH_FIN);
    return CC_OK;
}

CEXPORT_C CCError_t CC_Sm3Free(CCSm3UserContext_t *pContextID)
{
    CHECK_AND_RETURN_ERR_UPON_CH_CERT_ERROR();

    if (pContextID == NULL) {
        return CC_SM3_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    CC_PalMemSetZero(pContextID, sizeof(CCSm3UserContext_t));

    return CC_OK;
}

CEXPORT_C CCError_t CC_Sm3(uint8_t *pDataIn, size_t DataInSize, CCSm3ResultBuf_t Sm3ResultBuff)
{
    CCError_t Error = CC_OK;
    CCSm3UserContext_t UserContext;

    Error = CC_Sm3Init(&UserContext);
    if (Error != CC_OK) {
        goto end;
    }

    Error = CC_Sm3Update(&UserContext, pDataIn, DataInSize);
    if (Error != CC_OK) {
        goto end;
    }

    Error = CC_Sm3Finish(&UserContext, Sm3ResultBuff);

end:

    CC_Sm3Free(&UserContext);

    return Error;
}

