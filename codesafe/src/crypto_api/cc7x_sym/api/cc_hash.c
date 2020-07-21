/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#define CC_PAL_LOG_CUR_COMPONENT CC_LOG_MASK_CC_API

#include "cc_pal_types.h"
#include "cc_pal_mem.h"
#include "cc_hash_defs.h"
#include "cc_hash_error.h"
#include "hash.h"
#include "sym_adaptor_driver.h"
#include "dma_buffer.h"
#include "cc_sym_error.h"
#include "cc_context_relocation.h"
#include "cc_pal_perf.h"
#include "cc_fips_defs.h"

/************************ Defines ******************************/

#if ( CC_DRV_CTX_SIZE_WORDS > CC_HASH_USER_CTX_SIZE_IN_WORDS )
#error CC_HASH_USER_CTX_SIZE_IN_WORDS is not defined correctly.
#endif
/* Since the user context in the TEE is doubled to allow it to be contiguous we must get */
/*  the real size of the context (SEP context) to get the private context pointer  */
#define CC_HASH_USER_CTX_ACTUAL_SIZE_IN_WORDS    ((CC_HASH_USER_CTX_SIZE_IN_WORDS - 3)/2)

/************************ Type definitions **********************/
typedef struct CCHashPrivateContext_t {
    uint8_t remainingBuf[CC_HASH_SHA512_BLOCK_SIZE_IN_BYTES]; /* max(CC_HASH_BLOCK_SIZE_IN_WORDS, CC_HASH_SHA512_BLOCK_SIZE_IN_WORDS) */
    uint32_t remainingBufSize;
} CCHashPrivateContext_t;

/************************ Public Functions ******************************/

/*!
 * Converts Symmetric Adaptor return code to CC error code.
 *
 * \param symRetCode Symmetric Adaptor return error.
 * \param errorInfo Ignored.
 *
 * \return CCError_t one of CC_* error codes defined in cc_error.h
 */
static CCError_t SymAdaptor2CCHashErr(int symRetCode, uint32_t errorInfo)
{
    errorInfo = errorInfo;
    switch (symRetCode) {
        case CC_RET_UNSUPP_ALG:
            return CC_HASH_IS_NOT_SUPPORTED;
        case CC_RET_UNSUPP_ALG_MODE:
        case CC_RET_UNSUPP_OPERATION:
            return CC_HASH_ILLEGAL_OPERATION_MODE_ERROR;
        case CC_RET_INVARG:
            return CC_HASH_ILLEGAL_PARAMS_ERROR;
        case CC_RET_INVARG_KEY_SIZE:
        case CC_RET_INVARG_CTX_IDX:
            return CC_HASH_INVALID_USER_CONTEXT_POINTER_ERROR;
        case CC_RET_INVARG_CTX:
            return CC_HASH_USER_CONTEXT_CORRUPTED_ERROR;
        case CC_RET_INVARG_BAD_ADDR:
            return CC_HASH_DATA_IN_POINTER_INVALID_ERROR;
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

/**
 * This function initializes the HASH machine on the CryptoCell level.
 *
 * This function allocates and initializes the HASH Context .
 * The function receives as input a pointer to store the context handle to HASH Context ,
 * it initializes the
 * HASH Context with the cryptographic attributes that are needed for
 * the HASH block operation ( initialize H's value for the HASH algorithm ).
 *
 * The function flow:
 *
 * 1) checking the validity of the arguments - returnes an error on an illegal argument case.
 * 2) Aquiring the working context from the CCM manager.
 * 3) Initializing the context with the parameters passed by the user and with the init values
 *    of the HASH.
 * 4) loading the user tag to the context.
 * 5) release the CCM context.
 *
 * @param[in] ContextID_ptr - a pointer to the HASH context buffer allocated by the user that
 *                       is used for the HASH machine operation.
 *
 * @param[in] OperationMode - The operation mode : MD5 or SHA1.
 *
 * @return CCError_t on success the function returns CC_OK else non ZERO error.
 *
 */
CEXPORT_C CCError_t CC_HashInit(CCHashUserContext_t* ContextID_ptr,
                                CCHashOperationMode_t OperationMode)
{
    struct drv_ctx_hash *pHashContext;
    CCHashPrivateContext_t *pHashPrivContext;
    int symRc = CC_RET_OK;
    CCPalPerfData_t perfIdx = 0;

    CC_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_CC_HASH_INIT);

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    if (ContextID_ptr == NULL) {
        return CC_HASH_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    if (OperationMode >= CC_HASH_NumOfModes) {
        return CC_HASH_ILLEGAL_OPERATION_MODE_ERROR;
    }

    /*pointer for CTX  allocation*/
    /* FUNCTION LOGIC */
    /* Get pointer to contiguous context in the HOST buffer */
    pHashContext = (struct drv_ctx_hash *) RcInitUserCtxLocation(ContextID_ptr->buff,
                                                                 sizeof(CCHashUserContext_t),
                                                                 sizeof(struct drv_ctx_hash));
    if (pHashContext == NULL) {
        return CC_HASH_INVALID_USER_CONTEXT_POINTER_ERROR;
    }
    pHashPrivContext = (CCHashPrivateContext_t *) &(((uint32_t*) pHashContext)[CC_DRV_CTX_SIZE_WORDS
                    - 1]);

    pHashContext->alg = DRV_CRYPTO_ALG_HASH;
    pHashPrivContext->remainingBufSize = 0;

    switch (OperationMode) {
        case CC_HASH_SHA1_mode:
            pHashContext->mode = DRV_HASH_SHA1;
            break;
        case CC_HASH_SHA224_mode:
            pHashContext->mode = DRV_HASH_SHA224;
            break;
        case CC_HASH_SHA256_mode:
            pHashContext->mode = DRV_HASH_SHA256;
            break;
#ifdef CC_CONFIG_HASH_SHA_512_SUPPORTED
            case CC_HASH_SHA384_mode:
            pHashContext->mode = DRV_HASH_SHA384;
            break;
            case CC_HASH_SHA512_mode:
            pHashContext->mode = DRV_HASH_SHA512;
            break;
#endif
#ifdef CC_CONFIG_HASH_MD5_SUPPORTED
            case CC_HASH_MD5_mode:
            pHashContext->mode = DRV_HASH_MD5;
            break;
#endif
        default:
            return CC_HASH_ILLEGAL_OPERATION_MODE_ERROR;
    }

    symRc = SymDriverAdaptorInit((uint32_t *) pHashContext, pHashContext->alg, pHashContext->mode);
    CC_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_CC_HASH_INIT);
    return CC_CRYPTO_RETURN_ERROR(symRc, 0, SymAdaptor2CCHashErr);
}

/**
 * This function process a block of data via the HASH Hardware.
 * The function receives as input an handle to the  HASH Context , that was initialized before
 * by an CC_HashInit function or by other CC_HashUpdate
 * function. The function Sets the hardware with the last H's
 * value that where stored in the CryptoCell HASH context and then
 * process the data block using the hardware and in the end of
 * the process stores in the HASH context the H's value HASH
 * Context with the cryptographic attributes that are needed for
 * the HASH block operation ( initialize H's value for the HASH
 * algorithm ). This function is used in cases not all the data
 * is arrange in one continues buffer.
 *
 * The function flow:
 *
 * 1) checking the parameters validty if there is an error the function shall exit with an error code.
 * 2) Aquiring the working context from the CCM manager.
 * 3) If there isnt enouth data in the previous update data buff in the context plus the received data
 *    load it to the context buffer and exit the function.
 * 4) fill the previous update data buffer to contain an entire block.
 * 5) Calling the hardware low level function to execute the update.
 * 6) fill the previous update data buffer with the data not processed at the end of the received data.
 * 7) release the CCM context.
 *
 * @param[in] ContextID_ptr - a pointer to the HASH context buffer allocated by the user that
 *                       is used for the HASH machine operation.
 *
 * @param DataIn_ptr a pointer to the buffer that stores the data to be
 *                       hashed .
 *
 * @param DataInSize  The size of the data to be hashed in bytes.
 *
 * @return CCError_t on success the function returns CC_OK else non ZERO error.
 *
 */
CEXPORT_C CCError_t CC_HashUpdate(CCHashUserContext_t* ContextID_ptr,
                                  uint8_t* DataIn_ptr,
                                  size_t DataInSize)
{
    struct drv_ctx_hash *pHashContext;
    CCHashPrivateContext_t *pHashPrivContext;
    int symRc = CC_RET_OK;
    uint32_t hash_block_size_in_bytes = 0;
    CCPalPerfData_t perfIdx = 0;
    uint32_t dataToProcessSize = 0;

    CC_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_CC_HASH_UPDATE);

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    if (ContextID_ptr == NULL) {
        return CC_HASH_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    if (DataInSize == 0) {
        return CC_OK;
    }

    if (DataIn_ptr == NULL) {
        return CC_HASH_DATA_IN_POINTER_INVALID_ERROR;
    }

    /* Get pointer to contiguous context in the HOST buffer */
    pHashContext = (struct drv_ctx_hash *) RcGetUserCtxLocation(ContextID_ptr->buff);

    pHashPrivContext = (CCHashPrivateContext_t *) &(((uint32_t*) pHashContext)[CC_DRV_CTX_SIZE_WORDS
                    - 1]);

    if (pHashContext->mode < DRV_HASH_SHA512 || pHashContext->mode == DRV_HASH_MD5) {
        hash_block_size_in_bytes = CC_HASH_BLOCK_SIZE_IN_BYTES;
    } else {
        hash_block_size_in_bytes = CC_HASH_SHA512_BLOCK_SIZE_IN_BYTES;
    }

    /* If there is previous data in the remaining buffer, try to fill the buffer with the current data */
    dataToProcessSize = min((hash_block_size_in_bytes - pHashPrivContext->remainingBufSize)
                                            % hash_block_size_in_bytes,
                            DataInSize);
    if (dataToProcessSize > 0) {
        /* add the data to the remaining buffer */
        CC_PalMemCopy(&(pHashPrivContext->remainingBuf[pHashPrivContext->remainingBufSize]),
                      DataIn_ptr,
                      dataToProcessSize);
        pHashPrivContext->remainingBufSize += dataToProcessSize;
        /* and "remove" it from the buffer of DataIn  */
        DataIn_ptr += dataToProcessSize;
        DataInSize -= dataToProcessSize;
    }
    /* If the remaining buffer is full, process the block (else, the remaining buffer will be processed in the next update or finish) */
    if (pHashPrivContext->remainingBufSize == hash_block_size_in_bytes) {
        symRc = SymDriverAdaptorProcess((uint32_t *) pHashContext,
                                        pHashPrivContext->remainingBuf,
                                        NULL,
                                        pHashPrivContext->remainingBufSize,
                                        pHashContext->alg);
        if (symRc != CC_RET_OK) {
            return CC_CRYPTO_RETURN_ERROR(symRc, 0, SymAdaptor2CCHashErr);
        }
        pHashPrivContext->remainingBufSize = 0;
    }

    /* process all the blocks that remain in the data */
    dataToProcessSize = (DataInSize / hash_block_size_in_bytes) * hash_block_size_in_bytes;
    if (dataToProcessSize > 0) {
        symRc = SymDriverAdaptorProcess((uint32_t *) pHashContext,
                                        DataIn_ptr,
                                        NULL,
                                        dataToProcessSize,
                                        pHashContext->alg);
        if (symRc != CC_RET_OK) {
            return CC_CRYPTO_RETURN_ERROR(symRc, 0, SymAdaptor2CCHashErr);
        }
        /* "remove" the processed data from the buffer of DataIn  */
        DataIn_ptr += dataToProcessSize;
        DataInSize -= dataToProcessSize;
    }

    /* the remaining partial block is kept to the next update or finish */
    dataToProcessSize = DataInSize;
    if (dataToProcessSize > 0) {
        CC_PalMemCopy(&(pHashPrivContext->remainingBuf[pHashPrivContext->remainingBufSize]),
                      DataIn_ptr,
                      dataToProcessSize);
        pHashPrivContext->remainingBufSize += dataToProcessSize;
    }

    CC_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_CC_HASH_UPDATE);
    return CC_OK;
}

/**
 * This function finalize the hashing process of data block.
 * The function receives as input an handle to the HASH Context , that was initialized before
 * by an CC_HashInit function or by CC_HashUpdate function.
 * The function "adds" an header to the data block as the specific hash standard
 * specifics , then it loads the hardware and reads the final message digest.
 *
 *  the function flow:
 *
 * 1) checking the parameters validty if there is an error the function shall exit with an error code.
 * 2) Calling the hardware low level function to execute the
 *    finish.
 *
 *  @param[in] ContextID_ptr - a pointer to the HASH context buffer allocated by the user that
 *                       is used for the HASH machine operation.
 *
 *  @retval HashResultBuff a pointer to the target buffer where the
 *                       HASE result stored in the context is loaded to.
 *
 *  @return CCError_t on success the function returns CC_OK else non ZERO error.
 */

CEXPORT_C CCError_t CC_HashFinish(CCHashUserContext_t* ContextID_ptr,
                                  CCHashResultBuf_t HashResultBuff)
{
    struct drv_ctx_hash *pHashContext;
    CCHashPrivateContext_t *pHashPrivContext;
    int symRc = CC_RET_OK;
    CCPalPerfData_t perfIdx = 0;
    uint8_t* DataIn_ptr = NULL;
    uint32_t DataInSize = 0;

    CC_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_CC_HASH_FIN);

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    if (ContextID_ptr == NULL) {
        return CC_HASH_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    if (HashResultBuff == NULL) {
        return CC_HASH_INVALID_RESULT_BUFFER_POINTER_ERROR;
    }

    /* Get pointer to contiguous context in the HOST buffer */
    pHashContext = (struct drv_ctx_hash *) RcGetUserCtxLocation(ContextID_ptr->buff);

    pHashPrivContext = (CCHashPrivateContext_t *) &(((uint32_t*) pHashContext)[CC_DRV_CTX_SIZE_WORDS
                    - 1]);

    /* if there is data in the remaining data, process it (else, use null DataIn buffer) */
    if (pHashPrivContext->remainingBufSize > 0) {
        DataIn_ptr = pHashPrivContext->remainingBuf;
        DataInSize = pHashPrivContext->remainingBufSize;
    }
    symRc = SymDriverAdaptorFinalize((uint32_t *) pHashContext,
                                     DataIn_ptr,
                                     NULL,
                                     DataInSize,
                                     pHashContext->alg);
    if (symRc != CC_RET_OK) {
        return CC_CRYPTO_RETURN_ERROR(symRc, 0, SymAdaptor2CCHashErr);
    }
    pHashPrivContext->remainingBufSize = 0;

    /* Copy the result to the user buffer */
    CC_PalMemCopy(HashResultBuff,
                  pHashContext->digest,
                  CC_HASH_RESULT_SIZE_IN_WORDS*sizeof(uint32_t));

    CC_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_CC_HASH_FIN);
    return CC_OK;
}

/**
 * @brief This function clears the hash context
 *
 * @param[in] ContextID_ptr - a pointer to the HASH context
 *                       buffer allocated by the user that is
 *                       used for the HASH machine operation.
 *                       This should be the same context that
 *                       was used on the previous call of this
 *                       session.
 *
 * @return CCError_t - On success CC_OK is returned, on failure a
 *                        value MODULE_* cc_hash_error.h
 */
CEXPORT_C CCError_t CC_HashFree(CCHashUserContext_t *ContextID_ptr)
{
    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    if (ContextID_ptr == NULL) {
        return CC_HASH_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    CC_PalMemSetZero(ContextID_ptr, sizeof(CCHashUserContext_t));

    return CC_OK;
}

/**
 * This function provide HASH function to process one buffer of data.
 * The function allocates an internal HASH Context , it initializes the
 * HASH Context with the cryptographic attributes that are needed for
 * the HASH block operation ( initialize H's value for the HASH algorithm ).
 * Then the function loads the Hardware with the initializing values and after
 * that process the data block using the hardware to do hash .
 * At the end the function return the message digest of the data buffer .
 *
 * @param[in] OperationMode - The operation mode : MD5 or SHA1.
 *
 * @param DataIn_ptr a pointer to the buffer that stores the data to be
 *                       hashed .
 *
 * @param DataInSize  The size of the data to be hashed in bytes.
 *
 * @retval HashResultBuff a pointer to the target buffer where the
 *                      HASE result stored in the context is loaded to.
 *
 * @return CCError_t on success the function returns CC_OK else non ZERO error.
 *
 */
CEXPORT_C CCError_t CC_Hash(CCHashOperationMode_t OperationMode,
                            uint8_t* DataIn_ptr,
                            size_t DataSize,
                            CCHashResultBuf_t HashResultBuff)
{
    CCError_t Error = CC_OK;
    CCHashUserContext_t UserContext;

    Error = CC_HashInit(&UserContext, OperationMode);
    if (Error != CC_OK) {
        goto end;
    }

    Error = CC_HashUpdate(&UserContext, DataIn_ptr, DataSize);
    if (Error != CC_OK) {
        goto end;
    }

    Error = CC_HashFinish(&UserContext, HashResultBuff);

end:
    CC_HashFree(&UserContext);

    return Error;
}
