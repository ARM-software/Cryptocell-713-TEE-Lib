/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#define CC_PAL_LOG_CUR_COMPONENT CC_LOG_MASK_CC_API

#include "cc_pal_types.h"
#include "cc_pal_mem.h"
#include "cc_sm4.h"
#include "cc_sm4_error.h"
#include "sym_adaptor_driver.h"
#include "cc_sym_error.h"
#include "cc_crypto_ctx.h"
#include "cc_context_relocation.h"
#include "cc_pal_perf.h"
#include "cc_chinese_cert_defs.h"

#define CC_SM4_REQUIRED_CTX_SIZE  2*CC_DRV_CTX_SIZE_WORDS+3

/* SM4 OFB use CBC encryption with const SRAM DIN.
 * The block size is limited according to the SRAM size
 * 16KB - 16B
 */
#define CC_SM4_MAX_SRAM_SIZE    16368

CC_PAL_COMPILER_ASSERT(CC_SM4_REQUIRED_CTX_SIZE == CC_SM4_USER_CTX_SIZE_IN_WORDS, "CC_SM4_USER_CTX_SIZE_IN_WORDS is not defined correctly!");
CC_PAL_COMPILER_ASSERT((uint32_t)CC_SM4_ENCRYPT == (uint32_t)DRV_CRYPTO_DIRECTION_ENCRYPT, "Sm4 direction enum mismatch!");
CC_PAL_COMPILER_ASSERT((uint32_t)CC_SM4_DECRYPT == (uint32_t)DRV_CRYPTO_DIRECTION_DECRYPT, "Sm4 direction enum mismatch!");

/******************************************************************************
 *               PRIVATE FUNCTIONS
 ******************************************************************************/

static CCError_t SymAdaptor2CCSm4Err(int symRetCode, uint32_t errorInfo)
{
    errorInfo = errorInfo;

    switch (symRetCode) {
        case CC_RET_UNSUPP_ALG:
            return CC_SM4_IS_NOT_SUPPORTED;
        case CC_RET_UNSUPP_ALG_MODE:
        case CC_RET_UNSUPP_OPERATION:
            return CC_SM4_ILLEGAL_OPERATION_MODE_ERROR;
        case CC_RET_INVARG:
            return CC_SM4_ILLEGAL_PARAMS_ERROR;
        case CC_RET_INVARG_KEY_SIZE:
            return CC_SM4_ILLEGAL_KEY_SIZE_ERROR;
        case CC_RET_INVARG_CTX_IDX:
            return CC_SM4_INVALID_USER_CONTEXT_POINTER_ERROR;
        case CC_RET_INVARG_CTX:
            return CC_SM4_USER_CONTEXT_CORRUPTED_ERROR;
        case CC_RET_INVARG_BAD_ADDR:
            return CC_SM4_DATA_IN_POINTER_INVALID_ERROR;
        case CC_RET_NOMEM:
            return CC_OUT_OF_RESOURCE_ERROR;
        case CC_RET_INVARG_INCONSIST_DMA_TYPE:
            return CC_ILLEGAL_RESOURCE_VAL_ERROR;
        default:
            return CC_FATAL_ERROR;
    }
}

static enum drv_cipher_mode Sm4Mode2CipherMode(CCSm4OperationMode_t operationMode)
{
    switch (operationMode) {
        case CC_SM4_MODE_ECB:
            return DRV_CIPHER_ECB;
        case CC_SM4_MODE_CBC:
        case CC_SM4_MODE_OFB:
            // OFB is not supported by HW - use CBC with const zero plain text
            return DRV_CIPHER_CBC;
        case CC_SM4_MODE_CTR:
            return DRV_CIPHER_CTR;
        default:
            return DRV_CIPHER_NULL_MODE;
    }
}

static enum drv_crypto_direction Sm4Dir2CipherDir(CCSm4EncryptMode_t direction,
                                            CCSm4OperationMode_t operationMode)
{
    if (operationMode == CC_SM4_MODE_OFB) {
        // for OFB - use CBC encryption for both encrypt & decrypt
        return DRV_CRYPTO_DIRECTION_ENCRYPT;
    }
    // Conversion is not required
    // We force both enums to have the same values using CC_PAL_COMPILER_ASSERT
    return (enum drv_crypto_direction) direction;
}

static void Sm4OfbXorResults(uint8_t *pDataIn, size_t dataSize,
		uint8_t *pDataOut)
{
	// for SM4 OFB - xor the results with input buffer
	for (unsigned int i = 0; i < dataSize; i++) {
		pDataOut[i] ^= pDataIn[i];
	}
}

/******************************************************************************
 *               FUNCTIONS
 ******************************************************************************/

CIMPORT_C CCError_t CC_Sm4Init(CCSm4UserContext_t *pContext,
                               CCSm4EncryptMode_t encryptDecryptFlag,
                               CCSm4OperationMode_t operationMode)
{
    CCError_t rc = CC_OK;
    struct drv_ctx_cipher *pSm4Ctx;
    CCPalPerfData_t perfIdx = 0;

    CC_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_SM4_INIT);

    CHECK_AND_RETURN_ERR_UPON_CH_CERT_ERROR();

    /* Checking validity of the input parameters */

    /* If the users context ID pointer is NULL return an error */
    if (pContext == NULL) {
        rc = CC_SM4_INVALID_USER_CONTEXT_POINTER_ERROR;
        goto EndInit;
    }

    /* Check if the operation mode is legal */
    if (operationMode >= CC_SM4_NUM_OF_OPERATION_MODES) {
        rc = CC_SM4_ILLEGAL_OPERATION_MODE_ERROR;
        goto EndInit;
    }

    /* Check the Encrypt / Decrypt flag validity */
    if (encryptDecryptFlag >= CC_SM4_NUM_OF_ENCRYPT_MODES) {
        rc = CC_SM4_INVALID_ENCRYPT_MODE_ERROR;
        goto EndInit;
    }

    /* Get pointer to contiguous context in the HOST buffer */
    pSm4Ctx = (struct drv_ctx_cipher *) RcInitUserCtxLocation(pContext->buff,
                                                              sizeof(CCSm4UserContext_t),
                                                              sizeof(struct drv_ctx_cipher));
    if (pSm4Ctx == NULL) {
        rc = CC_SM4_INVALID_USER_CONTEXT_POINTER_ERROR;
        goto EndInit;
    }

    /* Zeroization of new context */
    CC_PalMemSetZero(pSm4Ctx, sizeof(struct drv_ctx_cipher));

    /* Setting fixed fields for SM4 operation */
    pSm4Ctx->alg = DRV_CRYPTO_ALG_SM4;
    pSm4Ctx->mode = Sm4Mode2CipherMode(operationMode);
    pSm4Ctx->direction = Sm4Dir2CipherDir(encryptDecryptFlag, operationMode);
    pSm4Ctx->padding_type = DRV_PADDING_NONE;

    if (operationMode == CC_SM4_MODE_OFB) {
        // SM4 OFB is not supported - use CBC with const zero plain text
        pSm4Ctx->isSm4Ofb = true;
    }

EndInit:

    CC_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_SM4_INIT);

    return rc;
}

CIMPORT_C CCError_t CC_Sm4SetKey(CCSm4UserContext_t *pContext, CCSm4Key_t pKey)
{
    CCError_t rc = CC_OK;
    int symRc;
    struct drv_ctx_cipher *pSm4Ctx;
    CCPalPerfData_t perfIdx = 0;

    CC_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_SM4_SET_KEY);

    CHECK_AND_RETURN_ERR_UPON_CH_CERT_ERROR();

    /* Checking validity of the input parameters */

    /* If the users context ID pointer is NULL return an error */
    if (pContext == NULL) {
        rc = CC_SM4_INVALID_USER_CONTEXT_POINTER_ERROR;
        goto EndSetKey;
    }

    /* Check user key validity */
    if (pKey == NULL) {
        rc = CC_SM4_INVALID_KEY_POINTER_ERROR;
        goto EndSetKey;
    }

    /* Get pointer to contiguous context in the HOST buffer */
    pSm4Ctx = (struct drv_ctx_cipher *) RcGetUserCtxLocation(pContext->buff);

    /* Update key information in the context */
    pSm4Ctx->crypto_key_type = DRV_USER_KEY;
    pSm4Ctx->key_size = CC_SM4_KEY_SIZE_IN_BYTES;
    CC_PalMemCopy(pSm4Ctx->key, pKey, sizeof(CCSm4Key_t));

    /* Call symmetric adaptor to initiate cipher operation */
    symRc = SymDriverAdaptorInit((uint32_t *) pSm4Ctx, pSm4Ctx->alg, pSm4Ctx->mode);
    rc = CC_CRYPTO_RETURN_ERROR(symRc, 0, SymAdaptor2CCSm4Err);

EndSetKey:

    CC_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_SM4_SET_KEY);

    return rc;
}

CIMPORT_C CCError_t CC_Sm4SetIv(CCSm4UserContext_t *pContext, CCSm4Iv_t pIV)
{
    CCError_t rc = CC_OK;
    struct drv_ctx_cipher *pSm4Ctx;

    CHECK_AND_RETURN_ERR_UPON_CH_CERT_ERROR();

    /* Checking validity of the input parameters */

    /* If the users context ID pointer is NULL return an error */
    if (pContext == NULL) {
        rc = CC_SM4_INVALID_USER_CONTEXT_POINTER_ERROR;
        goto EndSetIv;
    }

    /* Check user IV validity */
    if (pIV == NULL) {
        rc = CC_SM4_INVALID_IV_POINTER_ERROR;
        goto EndSetIv;
    }

    /* Get pointer to contiguous context in the HOST buffer */
    pSm4Ctx = (struct drv_ctx_cipher *) RcGetUserCtxLocation(pContext->buff);

    if ((pSm4Ctx->mode != DRV_CIPHER_CBC) && (pSm4Ctx->mode != DRV_CIPHER_CTR)) {
        rc = CC_SM4_ILLEGAL_OPERATION_MODE_ERROR;
        goto EndSetIv;
    }

    /* Update IV information in the context */
    CC_PalMemCopy(pSm4Ctx->block_state, pIV, sizeof(CCSm4Iv_t));

EndSetIv:

    return rc;
}

CIMPORT_C CCError_t CC_Sm4GetIv(CCSm4UserContext_t *pContext, CCSm4Iv_t pIV)
{
    CCError_t rc = CC_OK;
    struct drv_ctx_cipher *pSm4Ctx;

    CHECK_AND_RETURN_ERR_UPON_CH_CERT_ERROR();

    /* Checking validity of the input parameters */

    /* If the users context ID pointer is NULL return an error */
    if (pContext == NULL) {
        rc = CC_SM4_INVALID_USER_CONTEXT_POINTER_ERROR;
        goto EndGetIv;
    }

    /* Check user IV validity */
    if (pIV == NULL) {
        rc = CC_SM4_INVALID_IV_POINTER_ERROR;
        goto EndGetIv;
    }

    /* Get pointer to contiguous context in the HOST buffer */
    pSm4Ctx = (struct drv_ctx_cipher *) RcGetUserCtxLocation(pContext->buff);

    if ((pSm4Ctx->mode != DRV_CIPHER_CBC) && (pSm4Ctx->mode != DRV_CIPHER_CTR)) {
        rc = CC_SM4_ILLEGAL_OPERATION_MODE_ERROR;
        goto EndGetIv;
    }

    /* Update IV information from the context */
    CC_PalMemCopy(pIV, pSm4Ctx->block_state, sizeof(CCSm4Iv_t));

EndGetIv:

    return rc;
}

CIMPORT_C CCError_t CC_Sm4Block(CCSm4UserContext_t *pContext,
                                uint8_t *pDataIn,
                                size_t dataSize,
                                uint8_t *pDataOut)
{
    CCError_t rc = CC_OK;
    int symRc;
    struct drv_ctx_cipher *pSm4Ctx;
    CCPalPerfData_t perfIdx = 0;

    CC_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_SM4_BLOCK);

    CHECK_AND_RETURN_ERR_UPON_CH_CERT_ERROR();

    /* Checking validity of the input parameters */

    /* If the users context ID pointer is NULL return an error */
    if (pContext == NULL) {
        rc = CC_SM4_INVALID_USER_CONTEXT_POINTER_ERROR;
        goto EndBlock;
    }

    /* Verify input pointer validity */
    if (pDataIn == NULL) {
        rc = CC_SM4_DATA_IN_POINTER_INVALID_ERROR;
        goto EndBlock;
    }

    /* Verify output pointer validity */
    if (pDataOut == NULL) {
        rc = CC_SM4_DATA_OUT_POINTER_INVALID_ERROR;
        goto EndBlock;
    }

    /* Check data unit validity for sm4:
     * should be block multiple, and != 0 */
    if ((dataSize == 0) || (dataSize % CC_SM4_BLOCK_SIZE_IN_BYTES != 0)) {
        CC_PAL_LOG_ERR("Invalid data size: %u\n", (unsigned int)dataSize);
        rc = CC_SM4_DATA_IN_SIZE_ILLEGAL;
        goto EndBlock;
    }

    /* Get pointer to contiguous context in the HOST buffer */
    pSm4Ctx = (struct drv_ctx_cipher *) RcGetUserCtxLocation(pContext->buff);

    if (pSm4Ctx->isSm4Ofb == true) {
        /* SM4 OFB use CBC encryption with const SRAM DIN.
         * The block size is limited to the SRAM size -
         * when getting size > SRAM size, need to break the data to blocks
         */
        size_t currData = 0;

        if (pDataOut == pDataIn) {
            /* for SM4 OFB - no inplace operations */
            rc = CC_SM4_ILLEGAL_INPLACE_ERROR;
            goto EndBlock;
        }

        while ((currData < dataSize) && (rc == CC_OK)) {
            size_t currSize;

            if ((dataSize - currData) > CC_SM4_MAX_SRAM_SIZE) {
                currSize = CC_SM4_MAX_SRAM_SIZE;
            } else {
                currSize = dataSize - currData;
            }

            /* Call symmetric adaptor to process cipher block operation */
            symRc = SymDriverAdaptorProcess((uint32_t *) pSm4Ctx,
                                            NULL,
                                            &pDataOut[currData],
                                            currSize,
                                            pSm4Ctx->alg);
            rc = CC_CRYPTO_RETURN_ERROR(symRc, 0, SymAdaptor2CCSm4Err);

            currData += currSize;
        }

        if (rc == CC_OK) {
            /* for SM4 OFB - use CBC encryption and then xor the results with
             * input data
             */
            Sm4OfbXorResults(pDataIn, dataSize, pDataOut);
        }

    } else {
        /* Call symmetric adaptor to process cipher block operation */
        symRc = SymDriverAdaptorProcess((uint32_t *) pSm4Ctx,
                                        pDataIn,
                                        pDataOut,
                                        dataSize,
                                        pSm4Ctx->alg);
        rc = CC_CRYPTO_RETURN_ERROR(symRc, 0, SymAdaptor2CCSm4Err);
    }

EndBlock:

    CC_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_SM4_BLOCK);

    return rc;
}

CIMPORT_C CCError_t CC_Sm4Finish(CCSm4UserContext_t *pContext,
                                 uint8_t *pDataIn,
                                 size_t dataSize,
                                 uint8_t *pDataOut)
{
    CCError_t rc = CC_OK;
    int symRc;
    struct drv_ctx_cipher *pSm4Ctx;
    CCPalPerfData_t perfIdx = 0;
    size_t currData = 0;
    size_t finishSize = dataSize;
    uint8_t *pFinishDataIn = pDataIn;
    uint8_t *pFinishDataOut = pDataOut;

    CC_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_SM4_FIN);

    CHECK_AND_RETURN_ERR_UPON_CH_CERT_ERROR();

    /* Checking validity of the input parameters */

    /* If the users context ID pointer is NULL return an error */
    if (pContext == NULL) {
        rc = CC_SM4_INVALID_USER_CONTEXT_POINTER_ERROR;
        goto EndFinish;
    }

    /* Verify input pointer validity */
    if ((pDataIn == NULL) && (dataSize != 0)) {
        rc = CC_SM4_DATA_IN_POINTER_INVALID_ERROR;
        goto EndFinish;
    }

    /* Verify output pointer validity */
    if ((pDataOut == NULL) && (dataSize != 0)) {
        rc = CC_SM4_DATA_OUT_POINTER_INVALID_ERROR;
        goto EndFinish;
    }

    /* Get pointer to contiguous context in the HOST buffer */
    pSm4Ctx = (struct drv_ctx_cipher *) RcGetUserCtxLocation(pContext->buff);

    if ((pSm4Ctx->isSm4Ofb == true) && (pDataOut != NULL) && (pDataOut == pDataIn)) {
        /* for SM4 OFB - no inplace operations */
        rc = CC_SM4_ILLEGAL_INPLACE_ERROR;
        goto EndFinish;
    }

    /* For ECB, CBC modes data size MUST be a multiple of 16 bytes. */
    if (((dataSize % CC_SM4_BLOCK_SIZE_IN_BYTES) != 0)
                    && ((pSm4Ctx->mode == DRV_CIPHER_ECB) || (pSm4Ctx->mode == DRV_CIPHER_CBC))) {
        rc = CC_SM4_DATA_IN_SIZE_ILLEGAL;
        goto EndFinish;
    }

    if ((pSm4Ctx->isSm4Ofb == true) && (dataSize != 0)) {
        /* SM4 OFB use CBC encryption with const SRAM DIN.
         * The block size is limited to the SRAM size -
         * when getting size > SRAM size, need to break the data to blocks
         */
        size_t currSize;

        while ((currData < dataSize) && (rc == CC_OK)) {

            if ((dataSize - currData) > CC_SM4_MAX_SRAM_SIZE) {
                currSize = CC_SM4_MAX_SRAM_SIZE;
            } else {
                currSize = dataSize - currData;
                if ((currSize % CC_SM4_BLOCK_SIZE_IN_BYTES != 0)) {
                    /* Process can get only block multiple */
                    break;
                }
            }

            /* Call symmetric adaptor to process cipher block operation */
            symRc = SymDriverAdaptorProcess((uint32_t *) pSm4Ctx,
                                            NULL,
                                            &pDataOut[currData],
                                            currSize,
                                            pSm4Ctx->alg);
            rc = CC_CRYPTO_RETURN_ERROR(symRc, 0, SymAdaptor2CCSm4Err);

            currData += currSize;
        }

        if (rc != CC_OK) {
            goto EndFinish;
        }

        if (currData < dataSize) {
            /* send the rest of the data to finish - not a multiple of block size */
            pFinishDataOut = &pDataOut[currData];
            finishSize = currSize;
        } else {
            /* send empty data to finish */
            finishSize = 0;
            pFinishDataOut = NULL;
        }

        pFinishDataIn = NULL;
    }

    /* Call symmetric adaptor to process cipher block operation */
    symRc = SymDriverAdaptorFinalize((uint32_t *) pSm4Ctx,
                                     pFinishDataIn,
                                     pFinishDataOut,
                                     finishSize,
                                     pSm4Ctx->alg);
    rc = CC_CRYPTO_RETURN_ERROR(symRc, 0, SymAdaptor2CCSm4Err);

    if ((pSm4Ctx->isSm4Ofb == true) && (dataSize != 0) && (rc == CC_OK)) {
        /* for SM4 OFB - use CBC encryption and then xor the results with
         * input data
         */
        Sm4OfbXorResults(pDataIn, dataSize, pDataOut);
    }

EndFinish:

    CC_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_SM4_FIN);

    return rc;
}

CIMPORT_C CCError_t CC_Sm4Free(CCSm4UserContext_t *pContext)
{
    CCError_t rc = CC_OK;
    struct drv_ctx_cipher *pSm4Ctx;

    CHECK_AND_RETURN_ERR_UPON_CH_CERT_ERROR();

    /* Checking validity of the input parameters */

    /* If the users context ID pointer is NULL return an error */
    if (pContext == NULL) {
        rc = CC_SM4_INVALID_USER_CONTEXT_POINTER_ERROR;
        goto EndFree;
    }

    /* Get pointer to contiguous context in the HOST buffer */
    pSm4Ctx = (struct drv_ctx_cipher *) RcGetUserCtxLocation(pContext->buff);

    /* Zero the context */
    CC_PalMemSetZero(pSm4Ctx, sizeof(struct drv_ctx_cipher));

EndFree:

    return rc;
}

CIMPORT_C CCError_t CC_Sm4(CCSm4Iv_t pIV,
                           CCSm4Key_t pKey,
                           CCSm4EncryptMode_t encryptDecryptFlag,
                           CCSm4OperationMode_t operationMode,
                           uint8_t *pDataIn,
                           size_t dataSize,
                           uint8_t *pDataOut)
{
    CCError_t rc = CC_OK;
    CCSm4UserContext_t sm4Context;

    /* Checking validity of the input parameters */

    /* In case input size is 0 - do nothing and return with success */
    if (dataSize == 0) {
        return CC_OK;
    }

    /* Init Sm4 operation */
    rc = CC_Sm4Init(&sm4Context, encryptDecryptFlag, operationMode);
    if (rc != CC_OK) {
        goto EndSm4;
    }

    /* Set Key for SM4 operation */
    rc = CC_Sm4SetKey(&sm4Context, pKey);
    if (rc != CC_OK) {
        goto EndSm4;
    }

    /* Set IV for CBC, OFB and CTR operations */
    if ((operationMode == CC_SM4_MODE_CBC) || (operationMode == CC_SM4_MODE_CTR) ||
        (operationMode == CC_SM4_MODE_OFB)) {
        rc = CC_Sm4SetIv(&sm4Context, pIV);
        if (rc != CC_OK) {
            goto EndSm4;
        }
    }

    /* Finish all data processing in one operation */
    rc = CC_Sm4Finish(&sm4Context, pDataIn, dataSize, pDataOut);

EndSm4:

    CC_Sm4Free(&sm4Context);    // ignore CC_Sm4Free returned value, to keep original rc value

    return rc;
}

