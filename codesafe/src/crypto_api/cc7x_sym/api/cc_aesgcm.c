/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#define CC_PAL_LOG_CUR_COMPONENT CC_LOG_MASK_CC_API

#include "cc_aesgcm.h"
#include "cc_aesgcm_error.h"
#include "aead.h"
#include "cc_crypto_ctx.h"
#include "sym_adaptor_driver.h"
#include "cc_pal_mem.h"
#include "dma_buffer.h"
#include "cc_sym_error.h"
#include "cc_context_relocation.h"
#include "cc_fips_defs.h"

/************************ Defines ******************************/
#if ( CC_DRV_CTX_SIZE_WORDS > CC_AESGCM_USER_CTX_SIZE_IN_WORDS )
#error CC_AESGCM_USER_CTX_SIZE_IN_WORDS is not defined correctly.
#endif

/* Since the user context in the TEE is doubled to allow it to be contiguous we must get */
/*  the real size of the context (SEP context) to get the private context pointer  */
#define CC_AESGCM_USER_CTX_ACTUAL_SIZE_IN_WORDS    ((CC_AESGCM_USER_CTX_SIZE_IN_WORDS - 3)/2)

#define AESGCM_PRIVATE_CONTEXT_SIZE_WORDS 1


/************************ Type definitions **********************/

typedef struct CC_AesGcmPrivateContext {
    uint32_t isA0BlockProcessed;
} CCAesGcmPrivateContext_t;

/************************ Private Functions **********************/
/*!
 * Converts Symmetric Adaptor return code to CC error code.
 *
 * \param symRetCode Symmetric Adaptor return error.
 * \param errorInfo Ignored.
 *
 * \return CCError_t one of CC_* error codes defined in cc_error.h
 */
static CCError_t SymAdaptor2CCAesGcmErr(int symRetCode, uint32_t errorInfo)
{
    CC_UNUSED_PARAM(errorInfo);
    switch (symRetCode) {
        case CC_RET_UNSUPP_ALG:
        case CC_RET_UNSUPP_ALG_MODE:
            return CC_AESGCM_IS_NOT_SUPPORTED;
        case CC_RET_INVARG:
           return CC_AESGCM_ILLEGAL_PARAMS_ERROR;
        case CC_RET_INVARG_KEY_SIZE:
            return CC_AESGCM_ILLEGAL_KEY_SIZE_ERROR;
        case CC_RET_INVARG_CTX_IDX:
            return CC_AESGCM_INVALID_USER_CONTEXT_POINTER_ERROR;
        case CC_RET_INVARG_CTX:
            return CC_AESGCM_USER_CONTEXT_CORRUPTED_ERROR;
        case CC_RET_INVARG_BAD_ADDR:
            return CC_AESGCM_ILLEGAL_PARAMETER_PTR_ERROR;
        case CC_RET_NOMEM:
            return CC_OUT_OF_RESOURCE_ERROR;
        case CC_RET_INVARG_INCONSIST_DMA_TYPE:
            return CC_AESGCM_ILLEGAL_DMA_BUFF_TYPE_ERROR;
        case CC_RET_UNSUPP_OPERATION:
        case CC_RET_PERM:
        case CC_RET_NOEXEC:
        case CC_RET_BUSY:
        case CC_RET_OSFAULT:
        default:
            return CC_FATAL_ERROR;
    }
}

CCError_t CC_AesGcmInit(CCAesGcmUserContext_t *ContextID_ptr,
            CCAesEncryptMode_t EncrDecrMode,
            CCAesGcmKey_t GCM_Key,
            CCAesGcmKeySize_t KeySizeId,
            size_t AdataSize,
            size_t TextSize,
            uint8_t *pIv,
            size_t  ivSize,
            uint8_t tagSize)
{
    uint32_t keySizeInBytes;
    uint32_t tmp[CC_AES_BLOCK_SIZE_WORDS];
    struct drv_ctx_aead *pAeadContext;
    CCAesGcmPrivateContext_t *pAesGcmPrivContext;
    int symRc = CC_RET_OK;

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* if the users context ID pointer is NULL return an error */
    if (ContextID_ptr == NULL) {
        return CC_AESGCM_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    /* check key pointer (unless secret key is used) */
    if (GCM_Key == NULL) {
        return CC_AESGCM_ILLEGAL_PARAMETER_PTR_ERROR;
    }

    /* check IV pointer */
    if (pIv == NULL) {
        return CC_AESGCM_ILLEGAL_PARAMETER_PTR_ERROR;
    }

    /* Check the IV size validity */
    if ((0 == ivSize) || (ivSize > 0xFFFFFFFF)) {
        return CC_AESGCM_IV_SIZE_ILLEGAL;
    }

    /* Verify Adata & text size are not bigger than 2^32 */
    if ((AdataSize > 0xFFFFFFFF) || (TextSize > 0xFFFFFFFF)) {
        return CC_AESGCM_ILLEGAL_PARAMETER_SIZE_ERROR;
    }

    /* Check the Tag size validity */
    if ((CC_AESGCM_TAG_SIZE_4_BYTES != tagSize)  && (CC_AESGCM_TAG_SIZE_8_BYTES != tagSize)  &&
        (CC_AESGCM_TAG_SIZE_12_BYTES != tagSize) && (CC_AESGCM_TAG_SIZE_13_BYTES != tagSize) &&
        (CC_AESGCM_TAG_SIZE_14_BYTES != tagSize) && (CC_AESGCM_TAG_SIZE_15_BYTES != tagSize) &&
        (CC_AESGCM_TAG_SIZE_16_BYTES != tagSize)) {
        return CC_AESGCM_TAG_SIZE_ILLEGAL;
    }

    /* check Key size ID and get Key size in bytes */
    switch (KeySizeId) {
        case CC_AESGCM_Key128BitSize:
            keySizeInBytes = 16;
            break;
        case CC_AESGCM_Key192BitSize:
            keySizeInBytes = 24;
            break;
        case CC_AESGCM_Key256BitSize:
            keySizeInBytes = 32;
            break;
        default:
            return CC_AESGCM_ILLEGAL_KEY_SIZE_ERROR;
    }

    /* Get pointer to contiguous context in the HOST buffer */
    pAeadContext = (struct drv_ctx_aead *) RcInitUserCtxLocation(ContextID_ptr->buff,
                                                                 sizeof(CCAesGcmUserContext_t),
                                                                 sizeof(struct drv_ctx_aead));
    if (pAeadContext == NULL) {
        return CC_AESGCM_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    pAesGcmPrivContext = (CCAesGcmPrivateContext_t *) &(((uint32_t*) pAeadContext)[CC_AESGCM_USER_CTX_ACTUAL_SIZE_IN_WORDS
                    - AESGCM_PRIVATE_CONTEXT_SIZE_WORDS]);
    /* clear private context fields */
    pAesGcmPrivContext->isA0BlockProcessed = 0;

    CC_PalMemSetZero(pAeadContext, sizeof(struct drv_ctx_aead));

    /* init. GCM context */
    pAeadContext->alg = DRV_CRYPTO_ALG_AEAD;
    pAeadContext->mode = DRV_CIPHER_GCTR;
    pAeadContext->direction = (enum drv_crypto_direction) EncrDecrMode;
    pAeadContext->key_size = keySizeInBytes;
    CC_PalMemCopy(pAeadContext->key, GCM_Key, keySizeInBytes);
    pAeadContext->header_size = AdataSize;
    pAeadContext->nonce_size = ivSize;
    pAeadContext->tag_size = tagSize;
    pAeadContext->text_size = TextSize;

    /* prepare lenA and lenC memory for GHASH */
    tmp[1] = (AdataSize << 3) & BITMASK(CC_BITS_IN_32BIT_WORD);
    tmp[1] = SWAP_ENDIAN(tmp[1]);
    tmp[0] = 0;
    tmp[3] = (TextSize << 3) & BITMASK(CC_BITS_IN_32BIT_WORD);
    tmp[3] = SWAP_ENDIAN(tmp[3]);
    tmp[2] = 0;
    CC_PalMemCopy(pAeadContext->gcm_len_block, tmp, CC_AES_BLOCK_SIZE);

    symRc = SymDriverAdaptorInit((uint32_t *) pAeadContext, pAeadContext->alg, pAeadContext->mode);
    if (symRc != CC_RET_OK) {
        return CC_CRYPTO_RETURN_ERROR(symRc, 0, SymAdaptor2CCAesGcmErr);
    }

    if (ivSize == CC_AESGCM_IV_96_BITS_SIZE_BYTES)
    {
        /* Concatenate IV||0(31)||1 */
        CC_PalMemCopy(pAeadContext->nonce, pIv, CC_AESGCM_IV_96_BITS_SIZE_BYTES);
        tmp[0] = SWAP_ENDIAN(0x00000001);
        CC_PalMemCopy(pAeadContext->nonce + CC_AESGCM_IV_96_BITS_SIZE_BYTES, tmp, sizeof(uint32_t));
    } else {
        /* j0 calculation - copy IV to sram or add to GHASH */

        /* use nonce memory to save the IV size required for GHASH calculation */
        CC_PalMemSetZeroPlat(tmp, CC_AES_BLOCK_SIZE);
        tmp[3] = (ivSize << 3) & BITMASK(CC_BITS_IN_32BIT_WORD);
        tmp[3] = SWAP_ENDIAN(tmp[3]);
        CC_PalMemCopy(pAeadContext->nonce, tmp, CC_AES_BLOCK_SIZE);

        symRc = SymDriverAdaptorProcess((uint32_t *) pAeadContext,
                                        pIv,
                                        NULL,
                                        ivSize,
                                        pAeadContext->alg);
        if (symRc != CC_RET_OK) {
            return CC_CRYPTO_RETURN_ERROR(symRc, 0, SymAdaptor2CCAesGcmErr);
        }
    }

    if (pAeadContext->text_size != 0) {
        /* prepare inc32(j0) - relevant only to encrypt/decrypt of data */
        CC_PalMemCopy(pAeadContext->block_state, pAeadContext->nonce, CC_AESGCM_IV_96_BITS_SIZE_BYTES);
        CC_PalMemCopy(tmp, pAeadContext->nonce + CC_AESGCM_IV_96_BITS_SIZE_BYTES, sizeof(uint32_t));

        tmp[0] = SWAP_ENDIAN(tmp[0]);
        /* --- Inc32 LSW --- */
        /* Check overlap and inc. by 1 */
        if (BITMASK(CC_BITS_IN_32BIT_WORD) != tmp[0]) {
            tmp[0]++;
        } else {
            tmp[0] = 0;
        }
        tmp[0] = SWAP_ENDIAN(tmp[0]);
        CC_PalMemCopy(pAeadContext->block_state + CC_AESGCM_IV_96_BITS_SIZE_BYTES, tmp, sizeof(uint32_t));
    }

    return CC_CRYPTO_RETURN_ERROR(symRc, 0, SymAdaptor2CCAesGcmErr);
}

CCError_t CC_AesGcmBlockAdata(CCAesGcmUserContext_t *ContextID_ptr,
                              uint8_t *DataIn_ptr,
                              size_t DataInSize)
{
    struct drv_ctx_aead *pAeadContext;
    CCAesGcmPrivateContext_t *pAesGcmPrivContext;
    int symRc = CC_RET_OK;

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* if the users context ID pointer is NULL return an error */
    if (ContextID_ptr == NULL) {
        return CC_AESGCM_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    /* if the users Data In pointer is illegal return an error */
    if (DataIn_ptr == NULL) {
        return CC_AESGCM_AAD_POINTER_INVALID_ERROR;
    }

    /* if the data size is illegal return an error */
    if (DataInSize == 0) {
        return CC_AESGCM_DATA_IN_SIZE_ILLEGAL;
    }

    /* Get pointer to contiguous context in the HOST buffer */
    pAeadContext = (struct drv_ctx_aead *) RcGetUserCtxLocation(ContextID_ptr->buff);

    pAesGcmPrivContext = (CCAesGcmPrivateContext_t *) &(((uint32_t*) pAeadContext)[CC_AESGCM_USER_CTX_ACTUAL_SIZE_IN_WORDS
                    - AESGCM_PRIVATE_CONTEXT_SIZE_WORDS]);

    /* additional data may be processed only once */
    if (pAesGcmPrivContext->isA0BlockProcessed == 1) {
        return CC_AESGCM_ADATA_WAS_PROCESSED_ERROR;
    }

    /* given additional data plus header meta data are smaller than AES block size: A0+Adata < 16 */
    symRc = SymDriverAdaptorProcess((uint32_t *) pAeadContext,
                                    DataIn_ptr,
                                    NULL,
                                    DataInSize,
                                    pAeadContext->alg);
    if (symRc != CC_RET_OK) {
        return CC_CRYPTO_RETURN_ERROR(symRc, 0, SymAdaptor2CCAesGcmErr);
    }

    pAesGcmPrivContext->isA0BlockProcessed = 1;

    return CC_CRYPTO_RETURN_ERROR(symRc, 0, SymAdaptor2CCAesGcmErr);
}

CCError_t CC_AesGcmBlockTextData(CCAesGcmUserContext_t *ContextID_ptr,
                                 uint8_t *DataIn_ptr,
                                 size_t DataInSize,
                                 uint8_t *DataOut_ptr)
{
    struct drv_ctx_aead *pAeadContext;
    int symRc = CC_RET_OK;
    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* if the users context ID pointer is NULL return an error */
    if (ContextID_ptr == NULL) {
        return CC_AESGCM_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    /* if the users Data In pointer is illegal return an error */
    if (DataIn_ptr == NULL) {
        return CC_AESGCM_DATA_IN_POINTER_INVALID_ERROR;
    }

    /* if the Data In size is 0, return an error */
    if (DataInSize == 0) {
        return CC_AESGCM_DATA_IN_SIZE_ILLEGAL;
    }

    /* if the users Data Out pointer is illegal return an error */
    if (DataOut_ptr == NULL) {
        return CC_AESGCM_DATA_OUT_POINTER_INVALID_ERROR;
    }

    /* Get pointer to contiguous context in the HOST buffer */
    pAeadContext = (struct drv_ctx_aead *) RcGetUserCtxLocation(ContextID_ptr->buff);

    symRc = SymDriverAdaptorProcess((uint32_t *) pAeadContext,
                                    DataIn_ptr,
                                    DataOut_ptr,
                                    DataInSize,
                                    pAeadContext->alg);

    return CC_CRYPTO_RETURN_ERROR(symRc, 0, SymAdaptor2CCAesGcmErr);
}

CEXPORT_C CCError_t CC_AesGcmFinish(CCAesGcmUserContext_t *ContextID_ptr,
                                    uint8_t *DataIn_ptr,
                                    size_t DataInSize,
                                    uint8_t *DataOut_ptr,
                                    uint8_t *tagSize,
                                    CCAesGcmTagRes_t pTag)
{
    struct drv_ctx_aead *pAeadContext;
    int symRc = CC_RET_OK;

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* if the users context ID pointer is NULL return an error */
    if (ContextID_ptr == NULL) {
        return CC_AESGCM_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    /* if the users Data In pointer is illegal return an error */
    if ((DataIn_ptr == NULL) && (DataInSize != 0)) {
        return CC_AESGCM_DATA_IN_POINTER_INVALID_ERROR;
    }

    /* if the users Data Out pointer is illegal return an error */
    if ((DataOut_ptr == NULL) && (DataInSize != 0)) {
        return CC_AESGCM_DATA_OUT_POINTER_INVALID_ERROR;
    }

    if (tagSize == NULL) {
        return CC_AESGCM_ILLEGAL_PARAMETER_SIZE_ERROR;
    }

    if (pTag == NULL) {
        return CC_AESGCM_ILLEGAL_PARAMETER_ERROR;

    }
    /* Get pointer to contiguous context in the HOST buffer */
    pAeadContext = (struct drv_ctx_aead *) RcGetUserCtxLocation(ContextID_ptr->buff);

    symRc = SymDriverAdaptorFinalize((uint32_t *) pAeadContext,
                                     DataIn_ptr,
                                     DataOut_ptr,
                                     DataInSize,
                                     pAeadContext->alg);
    if (symRc != CC_RET_OK) {
        return CC_CRYPTO_RETURN_ERROR(symRc, 0, SymAdaptor2CCAesGcmErr);
    }

    /* copy MAC result to context */
    *tagSize = pAeadContext->tag_size;

    if (pAeadContext->direction == DRV_CRYPTO_DIRECTION_DECRYPT) {
        if (CC_PalMemCmp(pTag, pAeadContext->mac_state, *tagSize)) {
            return CC_AESGCM_GCM_TAG_INVALID_ERROR;
        }
    } else { /*DRV_CRYPTO_DIRECTION_ENCRYPT*/
        CC_PalMemCopy(pTag, pAeadContext->mac_state, *tagSize);
    }

    return CC_CRYPTO_RETURN_ERROR(symRc, 0, SymAdaptor2CCAesGcmErr);
}

CIMPORT_C CCError_t CC_AesGcm(CCAesEncryptMode_t     EncrDecrMode,
                              CCAesGcmKey_t          GCM_Key,
                              CCAesGcmKeySize_t      KeySizeId,
                              uint8_t                *pIv,
                              size_t                 ivSize,
                              uint8_t                *ADataIn_ptr,
                              size_t                 ADataInSize,
                              uint8_t                *TextDataIn_ptr,
                              size_t                 TextDataInSize,
                              uint8_t                *TextDataOut_ptr,
                              uint8_t                tagSize,
                              CCAesGcmTagRes_t       pTag)
{
    CCError_t rc = CC_OK;
    CCAesGcmUserContext_t ContextID;

    rc = CC_AesGcmInit(&ContextID, EncrDecrMode, GCM_Key,
                    KeySizeId, ADataInSize, TextDataInSize,
                    pIv, ivSize, tagSize);
    if (rc != CC_OK) {
        return rc;
    }

    if (ADataInSize > 0) {
        rc = CC_AesGcmBlockAdata(&ContextID, ADataIn_ptr, ADataInSize);
        if (rc != CC_OK) {
            return rc;
        }
    }

    rc = CC_AesGcmFinish(&ContextID, TextDataIn_ptr, TextDataInSize, TextDataOut_ptr, &tagSize, pTag);
    if (rc != CC_OK) {
        if ((EncrDecrMode == CC_AES_DECRYPT) && (rc == CC_AESGCM_GCM_TAG_INVALID_ERROR)) {
            CC_PalMemSetZero(TextDataOut_ptr, TextDataInSize);
        }
        return rc;
    }

    return rc;
}

