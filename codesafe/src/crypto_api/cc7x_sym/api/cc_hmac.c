/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#define CC_PAL_LOG_CUR_COMPONENT CC_LOG_MASK_CC_API

#include "cc_pal_types.h"
#include "cc_pal_mem.h"
#include "cc_hmac.h"
#include "cc_hmac_error.h"
#include "hmac.h"
#include "cc_hash.h"
#include "sym_adaptor_driver.h"
#include "dma_buffer.h"
#include "cc_sym_error.h"
#include "cc_context_relocation.h"
#include "cc_fips_defs.h"

/************************ Defines ******************************/
#if ( CC_DRV_CTX_SIZE_WORDS > CC_HMAC_USER_CTX_SIZE_IN_WORDS )
#error CC_HMAC_USER_CTX_SIZE_IN_WORDS is not defined correctly.
#endif

/* Since the user context in the TEE is doubled to allow it to be contiguous we must get */
/*  the real size of the context (SEP context) to get the private context pointer  */
#define CC_HMAC_USER_CTX_ACTUAL_SIZE_IN_WORDS    ((CC_HMAC_USER_CTX_SIZE_IN_WORDS - 3)/2)

/************************ Type definitions **********************/
typedef struct CCHmacPrivateContext_t {
    /* HMAC gets only multiple of block size, if HMAC update get size
     * that is not multiple of block size, keep the rest of the data
     * for the next update or to finalize */
    uint8_t hmac_aggregation_block[CC_HASH_SHA512_BLOCK_SIZE_IN_BYTES];
    size_t hmac_aggregation_block_curr;
} CCHmacPrivateContext_t;

/************************ Private Functions **********************/

/*!
 * Get Hash block Size length in bytes.
 *
 * \param mode Hash mode
 *
 * \return int digest size return value.
 */
static int GetHmacBlocktSize(const enum drv_hash_mode mode)
{
    if (mode >= DRV_HASH_MODE_NUM) {
        CC_PAL_LOG_ERR("Unsupported hash mode");
        return 0;
    }

    if (mode <= DRV_HASH_SHA224 || mode == DRV_HASH_MD5)
        return CC_HASH_BLOCK_SIZE_IN_BYTES;
    else
        return CC_HASH_SHA512_BLOCK_SIZE_IN_BYTES;

}

/*!
 * Converts Symmetric Adaptor return code to CC error code.
 *
 * \param symRetCode Symmetric Adaptor return error.
 * \param errorInfo Ignored.
 *
 * \return CCError_t one of CC_* error codes defined in cc_error.h
 */
static CCError_t SymAdaptor2CCHmacErr(int symRetCode, uint32_t errorInfo)
{
    errorInfo = errorInfo;
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

static inline enum drv_hash_mode CC2DrvHashMode(CCHashOperationMode_t OperationMode)
{
    enum drv_hash_mode result;

    switch (OperationMode) {
        case CC_HASH_SHA1_mode:
            result = DRV_HASH_SHA1;
            break;
        case CC_HASH_SHA224_mode:
            result = DRV_HASH_SHA224;
            break;
        case CC_HASH_SHA256_mode:
            result = DRV_HASH_SHA256;
            break;
#ifdef CC_CONFIG_HASH_SHA_512_SUPPORTED
            case CC_HASH_SHA384_mode:
            result = DRV_HASH_SHA384;
            break;
            case CC_HASH_SHA512_mode:
            result = DRV_HASH_SHA512;
            break;
#endif
#ifdef CC_CONFIG_HASH_MD5_SUPPORTED
            case CC_HASH_MD5_mode:
            result = DRV_HASH_MD5;
            break;
#endif
        default:
            result = DRV_HASH_NULL;
    }

    return result;
}

/************************ Public Functions **********************/

/**
 * This function initializes the HMAC machine on the CryptoCell level.
 *
 * The function allocates and initializes the HMAC Context .
 * The function receives as input a pointer to store the context handle to HMAC Context.
 *
 * The function executes a HASH_init session and processes a HASH update
 * on the Key XOR ipad and stores it in the context.
 *
 * @param[in] ContextID_ptr - A pointer to the HMAC context buffer allocated by the user
 *                       that is used for the HMAC machine operation.
 *
 * @param[in] OperationMode - The operation mode according to supported hash operation mode..
 *
 * @param[in] key_ptr - The pointer to the user's key buffer,
 *            or its digest (if larger than the hash block size).
 *
 * @param[in] keySize - The size of the received key. Must not exceed the associated
 *                      hash block size. For larger keys the caller must provide
 *                      a hash digest of the key as the actual key.
 *
 * @return CCError_t - On success the function returns the value CC_OK,
 *            and on failure a non-ZERO error.
 *
 */
CIMPORT_C CCError_t CC_HmacInit(CCHmacUserContext_t *ContextID_ptr,
                                CCHashOperationMode_t OperationMode,
                                uint8_t *key_ptr,
                                size_t keySize)
{
    struct drv_ctx_hash *pHmacContext;
    CCHmacPrivateContext_t *pHmacPrivContext;
    int symRc = CC_RET_OK;
    uint32_t HashBlockSize;
    CCError_t error = CC_OK;

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* if the users context ID pointer is NULL return an error */
    if (ContextID_ptr == NULL) {
        return CC_HMAC_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    /* check if the key pointer is valid */
    if (key_ptr == NULL) {
        return CC_HMAC_INVALID_KEY_POINTER_ERROR;
    }

    /* check if the operation mode is legal and set hash block size */
    switch (OperationMode) {
        case CC_HASH_SHA1_mode:
        case CC_HASH_SHA224_mode:
        case CC_HASH_SHA256_mode:
#ifdef CC_CONFIG_HASH_MD5_SUPPORTED
            case CC_HASH_MD5_mode:
#endif
            HashBlockSize = CC_HASH_BLOCK_SIZE_IN_BYTES;
            break;
#ifdef CC_CONFIG_HASH_SHA_512_SUPPORTED
            case CC_HASH_SHA384_mode:
            case CC_HASH_SHA512_mode:
            HashBlockSize = CC_HASH_SHA512_BLOCK_SIZE_IN_BYTES;
            break;
#endif
        default:
            return CC_HMAC_ILLEGAL_OPERATION_MODE_ERROR;
    }

    /* check if the key size is valid */
    if (keySize == 0) {
        return CC_HMAC_UNVALID_KEY_SIZE_ERROR;
    }

    /* Get pointer to contiguous context in the HOST buffer */
    pHmacContext = (struct drv_ctx_hash *) RcInitUserCtxLocation(ContextID_ptr->buff,
                                                                 sizeof(CCHmacUserContext_t),
                                                                 sizeof(struct drv_ctx_hash));
    if (pHmacContext == NULL) {
        return CC_HMAC_INVALID_USER_CONTEXT_POINTER_ERROR;
    }
    pHmacPrivContext = (CCHmacPrivateContext_t *) &(((uint32_t*) pHmacContext)[CC_DRV_CTX_SIZE_WORDS
                    - 1]);

    pHmacContext->alg = DRV_CRYPTO_ALG_HMAC;
    pHmacContext->mode = CC2DrvHashMode(OperationMode);

    /* reset the aggregation buffer */
    pHmacPrivContext->hmac_aggregation_block_curr = 0;

    if (keySize > HashBlockSize) {
        error = CC_Hash(OperationMode, key_ptr, keySize, (uint32_t*) pHmacContext->k0);/*Write the result into th context*/

        if (error != CC_OK)
            return symRc;

        /* update the new key size according to the mode */
        switch (OperationMode) {
            case CC_HASH_SHA1_mode:
                keySize = CC_HASH_SHA1_DIGEST_SIZE_IN_BYTES;
                break;
            case CC_HASH_SHA224_mode:
                keySize = CC_HASH_SHA224_DIGEST_SIZE_IN_BYTES;
                break;
            case CC_HASH_SHA256_mode:
                keySize = CC_HASH_SHA256_DIGEST_SIZE_IN_BYTES;
                break;
#ifdef CC_CONFIG_HASH_SHA_512_SUPPORTED
                case CC_HASH_SHA384_mode:
                keySize = CC_HASH_SHA384_DIGEST_SIZE_IN_BYTES;
                break;
                case CC_HASH_SHA512_mode:
                keySize = CC_HASH_SHA512_DIGEST_SIZE_IN_BYTES;
                break;
#endif
#ifdef CC_CONFIG_HASH_MD5_SUPPORTED
                case CC_HASH_MD5_mode:
                keySize = CC_HASH_MD5_DIGEST_SIZE_IN_BYTES;
                break;
#endif
            default:
                return CC_HMAC_ILLEGAL_OPERATION_MODE_ERROR;
        }
    }/* end of key larger then 64 bytes case */
    else {
        CC_PalMemCopy((uint8_t* )pHmacContext->k0, key_ptr, keySize);
    }
    pHmacContext->k0_size = keySize;

    symRc = SymDriverAdaptorInit((uint32_t *) pHmacContext, pHmacContext->alg, pHmacContext->mode);
    return CC_CRYPTO_RETURN_ERROR(symRc, 0, SymAdaptor2CCHmacErr);
}

/**
 * This function processes a HMAC block of data via the HASH hardware/software.
 * The function receives as input a handle to the HMAC Context,
 * and performs a HASH update on the data described below.
 *
 * @param[in] ContextID_ptr - A pointer to the HMAC context buffer allocated by the user
 *                       that is used for the HMAC machine operation.
 *
 * @param DataIn_ptr - A pointer to the buffer that stores the data to be hashed.
 *
 * @param DataInSize - The size of the data to be hashed, in bytes.
 *
 * @return CCError_t - On success the function returns CC_OK,
 *            and on failure a non-ZERO error.
 */

CIMPORT_C CCError_t CC_HmacUpdate(CCHmacUserContext_t *ContextID_ptr,
                                  uint8_t *DataIn_ptr,
                                  size_t DataInSize)
{
    struct drv_ctx_hash *pHmacContext;
    CCHmacPrivateContext_t *pHmacPrivContext;
    int symRc = CC_RET_OK;
    uint32_t blockSizeBytes;
    size_t currDataIn = 0;
    size_t leftDataIn;

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* if the users context ID pointer is NULL return an error */
    if (ContextID_ptr == NULL) {
        return CC_HMAC_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    /* if the users Data In pointer is illegal and the size is not 0 return an error */
    if ((DataIn_ptr == NULL) && DataInSize) {
        return CC_HMAC_DATA_IN_POINTER_INVALID_ERROR;
    }

    /* if the data size is zero no need to execute an update , return CC_OK */
    if (DataInSize == 0) {
        return CC_OK;
    }

    /* Get pointer to contiguous context in the HOST buffer */
    pHmacContext = (struct drv_ctx_hash *) RcGetUserCtxLocation(ContextID_ptr->buff);
    pHmacPrivContext = (CCHmacPrivateContext_t *) &(((uint32_t*) pHmacContext)[CC_DRV_CTX_SIZE_WORDS
                    - 1]);

    blockSizeBytes = GetHmacBlocktSize(pHmacContext->mode);

    if ((pHmacPrivContext->hmac_aggregation_block_curr != 0) &&
            ((pHmacPrivContext->hmac_aggregation_block_curr + DataInSize) >= blockSizeBytes)) {

        /* call hmac process with size of block size consists of -
         * 1. the rest of the data left from previous update
         * 2. start of new data */
        CC_PalMemCopy(&pHmacPrivContext->hmac_aggregation_block[pHmacPrivContext->hmac_aggregation_block_curr],
                DataIn_ptr,
                blockSizeBytes - pHmacPrivContext->hmac_aggregation_block_curr);
        currDataIn = blockSizeBytes - pHmacPrivContext->hmac_aggregation_block_curr;
        symRc = SymDriverAdaptorProcess((uint32_t *) pHmacContext,
                                        pHmacPrivContext->hmac_aggregation_block,
                                        NULL,
                                        blockSizeBytes,
                                        pHmacContext->alg);
        if (symRc != CC_RET_OK) {
            return CC_CRYPTO_RETURN_ERROR(symRc, 0, SymAdaptor2CCHmacErr);
        }
        pHmacPrivContext->hmac_aggregation_block_curr = 0;
    }

    /* HMAC gets only multiple of block size - need to keep the rest of the
     * data to next HMAC update or to finalize
     */
    leftDataIn = ((DataInSize - currDataIn) % blockSizeBytes);

    if (((DataInSize - currDataIn)  >= blockSizeBytes) ) {
        symRc = SymDriverAdaptorProcess((uint32_t *) pHmacContext,
                                        &DataIn_ptr[currDataIn],
                                        NULL,
                                        (DataInSize - currDataIn) - leftDataIn,
                                        pHmacContext->alg);
        if (symRc != CC_RET_OK) {
            return CC_CRYPTO_RETURN_ERROR(symRc, 0, SymAdaptor2CCHmacErr);
        }
    }

    if (leftDataIn != 0) {
        /* keep the rest of the data to next update or finalize */
        CC_PalMemCopy(&pHmacPrivContext->
                hmac_aggregation_block[pHmacPrivContext->hmac_aggregation_block_curr],
                &DataIn_ptr[DataInSize - leftDataIn],
                leftDataIn);
        pHmacPrivContext->hmac_aggregation_block_curr += leftDataIn;
    }

    return CC_OK;
}

/**
 * This function finalizes the HMAC processing of a data block.
 * The function receives as input a handle to the HMAC Context that was previously initialized
 * by a CC_HmacInit function or by a CC_HmacUpdate function.
 * This function finishes the HASH operation on the ipad and text, and then
 * executes a new HASH operation with the key XOR opad and the previous HASH operation result.
 *
 *  @param[in] ContextID_ptr - A pointer to the HMAC context buffer allocated by the user
 *                       that is used for the HMAC machine operation.
 *
 *  @retval HmacResultBuff - A pointer to the target buffer where the
 *                       HMAC result stored in the context is loaded to.
 *
 * @return CCError_t - On success the function returns CC_OK,
 *            and on failure a non-ZERO error.
 */
CIMPORT_C CCError_t CC_HmacFinish(CCHmacUserContext_t *ContextID_ptr,
                                  CCHashResultBuf_t HmacResultBuff)
{
    struct drv_ctx_hash *pHmacContext;
    CCHmacPrivateContext_t *pHmacPrivContext;
    int symRc = CC_RET_OK;
    uint32_t hmacDigesSize;

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* if the users context ID pointer is NULL return an error */
    if (ContextID_ptr == NULL) {
        return CC_HMAC_INVALID_USER_CONTEXT_POINTER_ERROR;
    }
    /* if the result buffer pointer is NULL return an error */
    if (HmacResultBuff == NULL) {
        return CC_HMAC_INVALID_RESULT_BUFFER_POINTER_ERROR;
    }

    /* Get pointer to contiguous context in the HOST buffer */
    pHmacContext = (struct drv_ctx_hash *) RcGetUserCtxLocation(ContextID_ptr->buff);
    pHmacPrivContext = (CCHmacPrivateContext_t *) &(((uint32_t*) pHmacContext)[CC_DRV_CTX_SIZE_WORDS
                    - 1]);

    if (pHmacPrivContext->hmac_aggregation_block_curr != 0) {
        /* call to finalize with the rest of the data of the last update */
        symRc = SymDriverAdaptorFinalize((uint32_t *) pHmacContext,
                pHmacPrivContext->hmac_aggregation_block,
                NULL,
                pHmacPrivContext->hmac_aggregation_block_curr,
                pHmacContext->alg);
    } else {
        symRc = SymDriverAdaptorFinalize((uint32_t *) pHmacContext,
                                         NULL,
                                         NULL,
                                         0,
                                         pHmacContext->alg);
    }

    if (symRc != CC_RET_OK) {
        return CC_CRYPTO_RETURN_ERROR(symRc, 0, SymAdaptor2CCHmacErr);
    }

    switch (pHmacContext->mode) {
        case DRV_HASH_SHA1:
            hmacDigesSize = CC_SHA1_DIGEST_SIZE;
            break;
        case DRV_HASH_SHA224:
            hmacDigesSize = CC_SHA224_DIGEST_SIZE;
            break;
        case DRV_HASH_SHA256:
            hmacDigesSize = CC_SHA256_DIGEST_SIZE;
            break;
#ifdef CC_CONFIG_HASH_SHA_512_SUPPORTED
            case DRV_HASH_SHA384:
            hmacDigesSize = CC_SHA384_DIGEST_SIZE;
            break;
            case DRV_HASH_SHA512:
            hmacDigesSize = CC_SHA512_DIGEST_SIZE;
            break;
#endif
#ifdef CC_CONFIG_HASH_MD5_SUPPORTED
            case DRV_HASH_MD5:
            hmacDigesSize = CC_MD5_DIGEST_SIZE;
            break;
#endif
        default:
            hmacDigesSize = 0;
            return CC_HMAC_ILLEGAL_OPERATION_MODE_ERROR;
    }

    CC_PalMemCopy(HmacResultBuff, pHmacContext->digest, hmacDigesSize);
    return CC_OK;
}

/**
 * @brief This function clears the hash context
 *
 * @param[in] ContextID_ptr - a pointer to the HMAC context
 *                       buffer allocated by the user that is
 *                       used for the HMAC machine operation.
 *                       This should be the same context that
 *                       was used on the previous call of this
 *                       session.
 *
 * @return CCError_t - On success CC_OK is returned, on failure a
 *                        value MODULE_* cc_hash_error.h
 */
CEXPORT_C CCError_t CC_HmacFree(CCHmacUserContext_t *ContextID_ptr)
{
    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    if (ContextID_ptr == NULL) {
        return CC_HMAC_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    CC_PalMemSetZero(ContextID_ptr, sizeof(CCHmacUserContext_t));

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
 *
 * @param[in] OperationMode - The operation mode according to supported hash operation mode.
 *
 * @param[in] key_ptr - The pointer to the users key buffer.
 *
 * @oaram[in] keySize - The size of the received key.
 *
 * @param[in] ContextID_ptr - a pointer to the HMAC context buffer allocated by the user that
 *                       is used for the HMAC machine operation.
 *
 * @param[in] DataIn_ptr - The pointer to the buffer of the input data to the HMAC. The pointer does
 *                         not need to be aligned. On CSI input mode the pointer must be equal to
 *                         value (0xFFFFFFFC | DataInAlignment).
 *
 * @param[in] DataInSize - The size of the data to be hashed in bytes. On CSI data transfer mode the size must
 *                         multiple of HASH_BLOCK_SIZE for used HASH mode.
 *
 * param[out] HashResultBuff - a pointer to the target buffer where the
 *                      HMAC result stored in the context is loaded to.
 *
 * @return CCError_t on success the function returns CC_OK else non ZERO error.
 *
 */
CIMPORT_C CCError_t CC_Hmac(CCHashOperationMode_t OperationMode,
                            uint8_t *key_ptr,
                            size_t keySize,
                            uint8_t *DataIn_ptr,
                            size_t DataSize,
                            CCHashResultBuf_t HmacResultBuff)
{
    CCHmacUserContext_t UserContext;
    CCError_t Error = CC_OK;

    Error = CC_HmacInit(&UserContext, OperationMode, key_ptr, keySize);
    if (Error != CC_OK) {
        goto end;
    }

    Error = CC_HmacUpdate(&UserContext, DataIn_ptr, DataSize);
    if (Error != CC_OK) {
        goto end;
    }
    Error = CC_HmacFinish(&UserContext, HmacResultBuff);

end:
    return Error;
}

