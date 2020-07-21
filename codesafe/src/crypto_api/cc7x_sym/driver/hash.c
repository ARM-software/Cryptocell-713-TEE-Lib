/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#define CC_PAL_LOG_CUR_COMPONENT CC_LOG_MASK_CC_SYM_DRIVER

#include "cc_pal_types.h"
#include "cc_pal_mem.h"
#include "sym_crypto_driver.h"
#include "cc_sym_error.h"
#include "cc_plat.h"
#include "mlli.h"
#include "hw_queue.h"
#include "cc_crypto_ctx.h"
#include "hash_defs.h"
#include "hash.h"
#include "completion.h"

CC_PAL_COMPILER_ASSERT(sizeof(struct drv_ctx_hash)==CC_CTX_SIZE,"drv_ctx_hash is larger than 128 bytes!");
CC_PAL_COMPILER_ASSERT(sizeof(enum drv_hash_mode)==sizeof(uint32_t), "drv_hash_mode is not 32bit!");
CC_PAL_COMPILER_ASSERT(sizeof(enum drv_hash_hw_mode)==sizeof(uint32_t), "drv_hash_hw_mode is not 32bit!");
CC_PAL_COMPILER_ASSERT(sizeof(enum HashConfig1Padding)==sizeof(uint32_t), "HashConfig1Padding is not 32bit!");
CC_PAL_COMPILER_ASSERT(sizeof(enum HashCipherDoPadding)==sizeof(uint32_t), "HashCipherDoPadding is not 32bit!");

/******************************************************************************
 *                GLOBALS
 ******************************************************************************/

const uint32_t gLarvalMd5Digest[] = { HASH_LARVAL_MD5 };
const uint32_t gLarvalSha1Digest[] = { HASH_LARVAL_SHA1 };
const uint32_t gLarvalSha224Digest[] = { HASH_LARVAL_SHA224 };
const uint32_t gLarvalSha256Digest[] = { HASH_LARVAL_SHA256 };
#ifdef CC_CONFIG_HASH_SHA_512_SUPPORTED
const uint32_t gLarvalSha384Digest[] = {HASH_LARVAL_SHA384};
const uint32_t gLarvalSha512Digest[] = {HASH_LARVAL_SHA512};
#endif
const uint32_t gLarvalSm3Digest[] = { HASH_LARVAL_SM3 };
const uint32_t gOpadCurrentLength[] = { OPAD_CURRENT_LENGTH };

/* Real expected size */
const uint32_t gHashDigestSize[DRV_HASH_MODE_NUM] = { CC_SHA1_DIGEST_SIZE,
                                                      CC_SHA256_DIGEST_SIZE,
                                                      CC_SHA224_DIGEST_SIZE,
                                                      CC_SHA512_DIGEST_SIZE,
                                                      CC_SHA384_DIGEST_SIZE,
                                                      CC_MD5_DIGEST_SIZE,
                                                      CC_SM3_DIGEST_SIZE };
/* SHA224 is processed as SHA256! */
const uint32_t gHashHwDigestSize[DRV_HASH_MODE_NUM] = { CC_SHA1_DIGEST_SIZE,
                                                        CC_SHA256_DIGEST_SIZE,
                                                        CC_SHA256_DIGEST_SIZE,
                                                        CC_SHA512_DIGEST_SIZE,
                                                        CC_SHA512_DIGEST_SIZE,
                                                        CC_MD5_DIGEST_SIZE,
                                                        CC_SM3_DIGEST_SIZE };
/*from the HW side, HASH512 and HASH384 are the same*/
const uint32_t gHashHwMode[DRV_HASH_MODE_NUM] = { DRV_HASH_HW_SHA1,
                                                  DRV_HASH_HW_SHA256,
                                                  DRV_HASH_HW_SHA256,
                                                  DRV_HASH_HW_SHA512,
                                                  DRV_HASH_HW_SHA512,
                                                  DRV_HASH_HW_MD5,
                                                  DRV_HASH_HW_SM3 };

/*!
 * Translate Hash mode to hardware specific Hash mode.
 *
 * \param mode Hash mode
 * \param hwMode [out] A pointer to the hash mode return value
 *
 * \return int One of DX_SYM_* error codes defined in cc_sym_error.h.
 */
int GetHashHwMode(const enum drv_hash_mode mode, uint32_t *hwMode)
{
    if (mode >= DRV_HASH_MODE_NUM) {
        CC_PAL_LOG_ERR("Unsupported hash mode");
        *hwMode = (uint32_t) DRV_HASH_NULL;
        return CC_RET_UNSUPP_ALG_MODE;
    }

    *hwMode = gHashHwMode[mode];
    return CC_RET_OK;
}

/*!
 * Get Hash digest size in bytes.
 *
 * \param mode Hash mode
 * \param digestSize [out] A pointer to the digest size return value
 *
 * \return int One of DX_SYM_* error codes defined in cc_sym_error.h.
 */
int GetHashDigestSize(const enum drv_hash_mode mode, uint32_t *digestSize)
{
    if (mode >= DRV_HASH_MODE_NUM) {
        CC_PAL_LOG_ERR("Unsupported hash mode");
        *digestSize = 0;
        return CC_RET_UNSUPP_ALG_MODE;
    }

    *digestSize = gHashDigestSize[mode];
    return CC_RET_OK;
}

/*!
 * Get hardware digest size (HW specific) in bytes.
 *
 * \param mode Hash mode
 * \param hwDigestSize [out] A pointer to the digest size return value
 *
 * \return int One of DX_SYM_* error codes defined in cc_sym_error.h.
 */
int GetHashHwDigestSize(const enum drv_hash_mode mode, uint32_t *hwDigestSize)
{
    if (mode >= DRV_HASH_MODE_NUM) {
        CC_PAL_LOG_ERR("Unsupported hash mode");
        *hwDigestSize = 0;
        return CC_RET_UNSUPP_ALG_MODE;
    }

    *hwDigestSize = gHashHwDigestSize[mode];
    return CC_RET_OK;
}

/*!
 * Get Hash block size in bytes.
 *
 * \param mode Hash mode
 * \param blockSize [out] A pointer to the hash block size return value
 *
 * \return int One of DX_SYM_* error codes defined in cc_sym_error.h.
 */
int GetHashBlockSize(const enum drv_hash_mode mode, uint32_t *blockSize)
{
    if ((mode >= DRV_HASH_MODE_NUM) || (mode == DRV_HASH_NULL)) {
        CC_PAL_LOG_ERR("Unsupported hash mode");
        *blockSize = 0;
        return CC_RET_UNSUPP_ALG_MODE;
    }

    switch (mode) {
        case DRV_HASH_SHA1:
        case DRV_HASH_SHA256:
        case DRV_HASH_SHA224:
        case DRV_HASH_MD5:
            *blockSize = CC_SHA1_224_256_BLOCK_SIZE;
            break;
        case DRV_HASH_SM3:
            *blockSize = CC_SM3_BLOCK_SIZE;
            break;
        default:
            *blockSize = CC_SHA512_BLOCK_SIZE;
            break;
    }

    return CC_RET_OK;
}

/*!
 * Loads the hash digest and hash length to the Hash HW machine.
 *
 * \param ctxAddr Hash context
 * \param paddingSelection enable/disable Hash block padding by the Hash machine,
 *      should be either HASH_PADDING_DISABLED or HASH_PADDING_ENABLED.
 *
 * \return int One of DX_SYM_* error codes defined in cc_sym_error.h.
 */
int LoadHashState(CCSramAddr_t ctxAddr,
                  enum HashConfig1Padding paddingSelection,
                  struct drv_ctx_hash * pHashCtx)
{
    const CCSramAddr_t digestAddr = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_hash, digest);
    const CCSramAddr_t k0Addr = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_hash, k0);
    const CCSramAddr_t currentDigestedLengthAddr = GET_CTX_FIELD_ADDR(ctxAddr,
                                                                      struct drv_ctx_hash,
                                                                      CurrentDigestedLength);
    CCSramAddr_t tmpSrc = digestAddr;
    uint32_t hw_mode, DigestSize;
    int drvRc = CC_RET_OK;
    HwDesc_s desc;

    drvRc = GetHashHwMode(pHashCtx->mode, &hw_mode);
    if (drvRc != CC_RET_OK) {
        return drvRc;
    }

    /* SHA224 uses SHA256 HW mode with different init. val. */
    drvRc = GetHashHwDigestSize(pHashCtx->mode, &DigestSize);
    if (drvRc != CC_RET_OK) {
        return drvRc;
    }

    /* load intermediate hash digest */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_CIPHER_MODE(&desc, hw_mode);
    if (pHashCtx->hmacFinalization == 1) {
        tmpSrc = k0Addr;
    }
    HW_DESC_SET_STATE_DIN_PARAM(&desc, tmpSrc, DigestSize);
    if (hw_mode == DRV_HASH_HW_SM3) {
        HW_DESC_SET_SM3_MODE(&desc);
    }
    HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_HASH);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_STATE0);
    AddHWDescSequence(&desc);

    /* load the hash current length, should be greater than zero */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_CIPHER_MODE(&desc, hw_mode);
    HW_DESC_SET_CIPHER_CONFIG1(&desc, paddingSelection);
    HW_DESC_SET_CIPHER_DO(&desc, DO_NOT_PAD);

    tmpSrc = currentDigestedLengthAddr;
    /* The global array is used to set the HASH current length for HMAC finalization */
    if (pHashCtx->hmacFinalization == 1) {
        HwDesc_s tdesc;
        uint32_t blockSize;

        /* In non SEP products the OPAD digest length constant is not in the SRAM     */
        /* and it might be non contiguous. In order to overcome this problem the FW   */
        /* copies the values into the CurrentDigestLength field. The coping operation */
        /* must be done with constant descriptors to keep the asynchronious mode working */
        HW_DESC_INIT(&tdesc);
        /*clear the current digest */
        HW_DESC_SET_DIN_CONST(&tdesc, 0, (DRV_HASH_LENGTH_WORDS * sizeof(uint32_t)));
        HW_DESC_SET_STATE_DOUT_PARAM(&tdesc, tmpSrc, (DRV_HASH_LENGTH_WORDS * sizeof(uint32_t)));
        AddHWDescSequence(&tdesc);

        /* set the current length */
        HW_DESC_INIT(&tdesc);
        /*clear the current digest */
        GetHashBlockSize(pHashCtx->mode, &blockSize);
        HW_DESC_SET_DIN_CONST(&tdesc, blockSize, sizeof(uint32_t));
        HW_DESC_SET_STATE_DOUT_PARAM(&tdesc, tmpSrc, sizeof(uint32_t));
        AddHWDescSequence(&tdesc);
    }

    if (hw_mode != DRV_HASH_HW_SM3) {
        HW_DESC_SET_STATE_DIN_PARAM(&desc, tmpSrc, (DRV_HASH_LENGTH_WORDS * sizeof(uint32_t)));
    } else {
        HW_DESC_SET_STATE_DIN_PARAM(&desc, tmpSrc, (DRV_SM3_LENGTH_WORDS * sizeof(uint32_t)));
        HW_DESC_SET_SM3_MODE(&desc);
    }

    HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_HASH);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_KEY0);
    AddHWDescSequence(&desc);

    return drvRc;
}

/*!
 * Writes the hash digest and hash length back to the Hash context.
 *
 * \param ctxAddr Hash context
 *
 * \return int One of DX_SYM_* error codes defined in cc_sym_error.h.
 */
int StoreHashState(CCSramAddr_t ctxAddr, struct drv_ctx_hash * pHashCtx)
{
    const CCSramAddr_t digestAddr = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_hash, digest);
    const CCSramAddr_t currentDigestedLengthAddr = GET_CTX_FIELD_ADDR(ctxAddr,
                                                                      struct drv_ctx_hash,
                                                                      CurrentDigestedLength);
    uint32_t hw_mode, DigestSize;
    int drvRc = CC_RET_OK;
    HwDesc_s desc;

    drvRc = GetHashHwMode(pHashCtx->mode, &hw_mode);
    if (drvRc != CC_RET_OK) {
        return drvRc;
    }

    /* SHA224 uses SHA256 HW mode with different init. val. */
    drvRc = GetHashHwDigestSize(pHashCtx->mode, &DigestSize);
    if (drvRc != CC_RET_OK) {
        return drvRc;
    }

    /* store the hash digest result in the context */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_CIPHER_MODE(&desc, hw_mode);
    HW_DESC_SET_STATE_DOUT_PARAM(&desc, digestAddr, DigestSize);
    if (hw_mode == DRV_HASH_HW_SM3) {
        HW_DESC_SET_SM3_MODE(&desc);
    }
    HW_DESC_SET_FLOW_MODE(&desc, S_HASH_to_DOUT);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_WRITE_STATE0);
    AddHWDescSequence(&desc);

    /* store current hash length in the private context */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_CIPHER_MODE(&desc, hw_mode);

    if (hw_mode != DRV_HASH_HW_SM3) {
        HW_DESC_SET_STATE_DOUT_PARAM(&desc,
                                     currentDigestedLengthAddr,
                                     (DRV_HASH_LENGTH_WORDS * sizeof(uint32_t)));
    } else {
        HW_DESC_SET_STATE_DOUT_PARAM(&desc,
                                     currentDigestedLengthAddr,
                                     (DRV_SM3_LENGTH_WORDS * sizeof(uint32_t)));
        HW_DESC_SET_SM3_MODE(&desc);
    }

    HW_DESC_SET_FLOW_MODE(&desc, S_HASH_to_DOUT);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_WRITE_STATE1);
    AddHWDescSequence(&desc);

    return drvRc;
}

/******************************************************************************
 *                FUNCTIONS
 ******************************************************************************/

/*!
 * This function is used to initialize the HASH machine to perform the
 * HASH operations. This should be the first function called.
 *
 * \param ctxAddr A pointer to the context buffer in SRAM.
 * \param pCtx A pointer to the context buffer in local memory.
 *
 * \return int One of DX_SYM_* error codes defined in cc_sym_error.h.
 */
int InitHash(CCSramAddr_t ctxAddr, uint32_t *pCtx)
{
    const CCSramAddr_t digestAddr = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_hash, digest);
    const CCSramAddr_t currentDigestedLengthAddr = GET_CTX_FIELD_ADDR(ctxAddr,
                                                                      struct drv_ctx_hash,
                                                                      CurrentDigestedLength);
    struct drv_ctx_hash * pHashCtx = (struct drv_ctx_hash *) pCtx;

    /* copy the hash initial digest to the user context */
    switch (pHashCtx->mode) {
        case DRV_HASH_SHA1:
            WriteContextField(digestAddr, gLarvalSha1Digest, CC_SHA1_DIGEST_SIZE);
            break;
        case DRV_HASH_SHA224:
            WriteContextField(digestAddr, gLarvalSha224Digest, CC_SHA256_DIGEST_SIZE);
            break;
        case DRV_HASH_SHA256:
            WriteContextField(digestAddr, gLarvalSha256Digest, CC_SHA256_DIGEST_SIZE);
            break;
#ifdef CC_CONFIG_HASH_SHA_512_SUPPORTED
        case DRV_HASH_SHA384:
            WriteContextField(digestAddr, gLarvalSha384Digest, CC_SHA512_DIGEST_SIZE);
            break;
        case DRV_HASH_SHA512:
            WriteContextField(digestAddr, gLarvalSha512Digest, CC_SHA512_DIGEST_SIZE);
            break;
#endif
        case DRV_HASH_MD5:
            WriteContextField(digestAddr, gLarvalMd5Digest, CC_MD5_DIGEST_SIZE);
            break;
        case DRV_HASH_SM3:
            WriteContextField(digestAddr, gLarvalSm3Digest, CC_SM3_DIGEST_SIZE);
            break;
        default:
            CC_PAL_LOG_ERR("Unsupported hash mode %d\n", pHashCtx->mode);
            return CC_RET_UNSUPP_ALG_MODE;
    }

    /* clear hash length and load it to the hash machine -we're starting a new transaction */
    ClearCtxField(currentDigestedLengthAddr, (DRV_HASH_LENGTH_WORDS * sizeof(uint32_t)));
    pHashCtx->dataCompleted = 0;
    pHashCtx->hmacFinalization = 0;

    return CC_RET_OK;
}

/*!
 * This function is used to process a block(s) of data on HASH machine.
 * It accepts an input data aligned to hash block size, any reminder which is not
 * aligned should be passed on calling to "FinalizeHash".
 *
 * \param ctxAddr A pointer to the Hash context buffer in SRAM.
 * \param pCtx A pointer to the Hash context buffer in local memory.
 * \param pDmaInputBuffer A structure which represents the DMA input buffer.
 * \param pDmaOutputBuffer A structure which represents the DMA output buffer.
 *
 * \return int One of DX_SYM_* error codes defined in cc_sym_error.h.
 */
int ProcessHash(CCSramAddr_t ctxAddr,
                uint32_t *pCtx,
                DmaBuffer_s *pDmaInputBuffer,
                DmaBuffer_s *pDmaOutputBuffer)
{
    CCDmaAddr_t pInputData = 0;
    HwDesc_s desc;
    uint32_t DataInSize = 0;
    DmaMode_t dmaMode = NO_DMA;
    uint8_t inAxiNs = pDmaInputBuffer->axiNs;
    int drvRc = CC_RET_OK;
    struct drv_ctx_hash * pHashCtx = (struct drv_ctx_hash *) pCtx;

    CC_UNUSED_PARAM(pDmaOutputBuffer);    // remove compilation warning
    HW_DESC_INIT(&desc);

    /* load hash length and digest */
    drvRc = LoadHashState(ctxAddr, HASH_PADDING_DISABLED, pHashCtx);
    if (drvRc != CC_RET_OK) {
        goto EndWithErr;
    }

    dmaMode = DMA_BUF_TYPE_TO_MODE(pDmaInputBuffer->dmaBufType);

    /* set the input pointer according to the DMA mode */
    switch (dmaMode) {
        case DMA_MLLI:
            pInputData = MLLI_getFirstLLIPtr(MLLI_INPUT_TABLE);
            MLLI_loadTableToSRAM(pDmaInputBuffer->pData,
                                 pDmaInputBuffer->size,
                                 pDmaInputBuffer->axiNs,
                                 MLLI_INPUT_TABLE);
            /* data size should hold the number of LLIs */
            DataInSize = (pDmaInputBuffer->size) / LLI_ENTRY_BYTE_SIZE;
            break;
        case DMA_DLLI:
        case DMA_SRAM:
            pInputData = pDmaInputBuffer->pData;
            /* set the data size */
            DataInSize = pDmaInputBuffer->size;
            break;
        default:
            CC_PAL_LOG_ERR("Invalid DMA mode\n");
            drvRc = CC_RET_INVARG;
            goto EndWithErr;
    }

    /* process the HASH flow */
    HW_DESC_SET_DIN_TYPE(&desc, dmaMode, pInputData, DataInSize, inAxiNs);
    HW_DESC_SET_FLOW_MODE(&desc, DIN_HASH);
    AddHWDescSequence(&desc);

    /* write back digest and hash length */
    StoreHashState(ctxAddr, pHashCtx);

EndWithErr:

    return drvRc;
}

/*!
 * This function is used as finish operation of the HASH machine.
 * The function may either be called after "InitHash" or "ProcessHash".
 *
 * \param ctxAddr A pointer to the HASH context buffer in SRAM.
 * \param pCtx A pointer to the HASH context buffer in local memory.
 * \param pDmaInputBuffer A structure which represents the DMA input buffer.
 * \param pDmaOutputBuffer A structure which represents the DMA output buffer.
 *
 * \return int One of DX_SYM_* error codes defined in cc_sym_error.h.
 */
int FinalizeHash(CCSramAddr_t ctxAddr,
                 uint32_t *pCtx,
                 DmaBuffer_s *pDmaInputBuffer,
                 DmaBuffer_s *pDmaOutputBuffer)
{
    const CCSramAddr_t digestAddr = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_hash, digest);
    HwDesc_s desc;
    uint32_t isRemainingData = 0;
    uint32_t DataInSize = 0;
    DmaMode_t dmaMode = NO_DMA;
    CCDmaAddr_t pInputData = 0;
    uint32_t hw_mode;
    uint32_t DigestSize;
    uint8_t inAxiNs = pDmaInputBuffer->axiNs;
    int drvRc = CC_RET_OK;
    struct drv_ctx_hash * pHashCtx = (struct drv_ctx_hash *) pCtx;
    const CCSramAddr_t currentDigestedLengthAddr = GET_CTX_FIELD_ADDR(ctxAddr,
                                                                      struct drv_ctx_hash,
                                                                      CurrentDigestedLength);
    drvRc = GetHashHwMode(pHashCtx->mode, &hw_mode);
    if (drvRc != CC_RET_OK) {
        return drvRc;
    }
    CC_UNUSED_PARAM(pDmaOutputBuffer);    // remove compilation warning
    HW_DESC_INIT(&desc);

    drvRc = GetHashHwMode(pHashCtx->mode, &hw_mode);
    if (drvRc != CC_RET_OK) {
        return drvRc;
    }

    /* SHA224 uses SHA256 HW mode with different init. val. */
    /*same for SHA384 with SHA512*/
    drvRc = GetHashHwDigestSize(pHashCtx->mode, &DigestSize);
    if (drvRc != CC_RET_OK) {
        goto EndWithErr;
    }

    dmaMode = DMA_BUF_TYPE_TO_MODE(pDmaInputBuffer->dmaBufType);

    /* check if we have remaining data to process */
    switch (dmaMode) {
        case DMA_MLLI:
            isRemainingData = (pDmaInputBuffer->size > 0) ? 1 : 0;
            DataInSize = 0;
            break;
        case DMA_DLLI:
        case DMA_SRAM:
            isRemainingData = (pDmaInputBuffer->size > 0) ? 1 : 0;
            DataInSize = pDmaInputBuffer->size;
            break;
        case NO_DMA:
            break;
        default:
            CC_PAL_LOG_ERR("Invalid DMA mode\n");
            drvRc = CC_RET_INVARG;
            goto EndWithErr;
    }

    /* check if there is a remainder */
    if (isRemainingData == 1) {
        /* load hash length and digest */
        drvRc = LoadHashState(ctxAddr, HASH_PADDING_ENABLED, pHashCtx);
        if (drvRc != CC_RET_OK) {
            goto EndWithErr;
        }

        /* we have a single MLLI table */
        if (dmaMode == DMA_MLLI) {
            pInputData = MLLI_getFirstLLIPtr(MLLI_INPUT_TABLE);
            MLLI_loadTableToSRAM(pDmaInputBuffer->pData,
                                 pDmaInputBuffer->size,
                                 pDmaInputBuffer->axiNs,
                                 MLLI_INPUT_TABLE);
            /* data size should hold the number of LLIs */
            DataInSize = (pDmaInputBuffer->size) / LLI_ENTRY_BYTE_SIZE;
        } else {
            pInputData = pDmaInputBuffer->pData;
            // check sram!
        }

        /* clobber remaining HASH data */
        HW_DESC_INIT(&desc);
        HW_DESC_SET_DIN_TYPE(&desc, dmaMode, pInputData, DataInSize, inAxiNs);
        HW_DESC_SET_FLOW_MODE(&desc, DIN_HASH);
        AddHWDescSequence(&desc);
    } else {
        /* (isRemainingData == 0) */
        /* load hash length and digest */
        drvRc = LoadHashState(ctxAddr, HASH_PADDING_DISABLED, pHashCtx);
        if (drvRc != CC_RET_OK) {
            goto EndWithErr;
        }

        /* Workaround: do-pad must be enabled only when writing current length to HW */
        HW_DESC_INIT(&desc);
        HW_DESC_SET_CIPHER_MODE(&desc, hw_mode);
        HW_DESC_SET_CIPHER_CONFIG1(&desc, HASH_PADDING_DISABLED);
        HW_DESC_SET_CIPHER_DO(&desc, DO_PAD);
        if (hw_mode != DRV_HASH_HW_SM3) {
            HW_DESC_SET_STATE_DOUT_PARAM(&desc,
                                         currentDigestedLengthAddr,
                                         (DRV_HASH_LENGTH_WORDS * sizeof(uint32_t)));
        } else {
            HW_DESC_SET_STATE_DOUT_PARAM(&desc,
                                         currentDigestedLengthAddr,
                                         (DRV_SM3_LENGTH_WORDS * sizeof(uint32_t)));
            HW_DESC_SET_SM3_MODE(&desc);
        }

        HW_DESC_SET_FLOW_MODE(&desc, S_HASH_to_DOUT);
        HW_DESC_SET_SETUP_MODE(&desc, SETUP_WRITE_STATE1);
        AddHWDescSequence(&desc);
    }

    /* store the hash digest result in the context */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_CIPHER_MODE(&desc, hw_mode);

    HW_DESC_SET_STATE_DOUT_PARAM(&desc, digestAddr, DigestSize);
    if (hw_mode == DRV_HASH_HW_MD5 || hw_mode == DRV_HASH_HW_SHA512
                    || hw_mode == DRV_HASH_HW_SHA384) {
        HW_DESC_SET_BYTES_SWAP(&desc, 1);
    } else {
        HW_DESC_SET_CIPHER_CONFIG0(&desc, HASH_DIGEST_RESULT_LITTLE_ENDIAN);
    }
    HW_DESC_SET_CIPHER_CONFIG1(&desc, HASH_PADDING_DISABLED);
    HW_DESC_SET_CIPHER_DO(&desc, DO_NOT_PAD);
    if (hw_mode == DRV_HASH_HW_SM3) {
        HW_DESC_SET_SM3_MODE(&desc);
    }
    HW_DESC_SET_FLOW_MODE(&desc, S_HASH_to_DOUT);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_WRITE_STATE0);
    AddHWDescSequence(&desc);

EndWithErr:

    return drvRc;
}

