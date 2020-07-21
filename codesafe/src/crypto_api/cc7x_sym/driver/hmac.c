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
#include "completion.h"
#include "hash.h"
#include "hmac.h"
#include "hmac_defs.h"

CC_PAL_COMPILER_ASSERT(sizeof(struct drv_ctx_hash)==CC_CTX_SIZE,"drv_ctx_hash is larger than 128 bytes!");
CC_PAL_COMPILER_ASSERT(sizeof(ZeroBlock) >= (DRV_HASH_LENGTH_WORDS * sizeof(uint32_t)), "ZeroBlock is too small for HASH_LENGTH field init.");
CC_PAL_COMPILER_ASSERT(sizeof(ZeroBlock) >= CC_AES_128_BIT_KEY_SIZE, "ZeroBlock is too small for key field init.");

/******************************************************************************
 *                GLOBALS
 ******************************************************************************/
extern const uint32_t gLarvalSha1Digest[];
extern const uint32_t gLarvalSha224Digest[];
extern const uint32_t gLarvalSha256Digest[];
extern const uint32_t gLarvalMd5Digest[];
#ifdef CC_CONFIG_HASH_SHA_512_SUPPORTED
extern const uint32_t gLarvalSha384Digest[];
extern const uint32_t gLarvalSha512Digest[];
#endif

#define HMAC_IPAD_CONST_BLOCK        0x36363636
#define HMAC_OPAD_CONST_BLOCK        0x5C5C5C5C

/******************************************************************************
 *                PRIVATE FUNCTIONS
 ******************************************************************************/

static int ProcessHmacPad(uint32_t constPadData,
                          CCSramAddr_t hashData,
                          uint32_t hashDataSize,
                          enum drv_hash_mode hmode,
                          CCSramAddr_t hashCurrentLength,
                          CCSramAddr_t hashResult,
                          CCSramAddr_t ctxAddr)
{
    HwDesc_s desc;
    uint32_t lhmode;
    uint32_t DigestSize;
    CCSramAddr_t digestAddr;
    int drvRc = CC_RET_OK;

    drvRc = GetHashHwMode(hmode, &lhmode);
    if (drvRc != CC_RET_OK) {
        return drvRc;
    }

    /* SHA224 uses SHA256 HW mode with different init. val. */
    drvRc = GetHashHwDigestSize(hmode, &DigestSize);
    if (drvRc != CC_RET_OK) {
        return drvRc;
    }

#ifdef CC_SRAM_INDIRECT_ACCESS
    /* get the SRAM address right after the context cache */
    digestAddr = (ctxAddr + CC_CTX_SIZE);

    switch(hmode) {
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
        case DRV_HASH_MD5:
        WriteContextField(digestAddr, gLarvalMd5Digest, CC_MD5_DIGEST_SIZE);
        break;
#endif
        default:
        CC_PAL_LOG_ERR("Unsupported hash mode %d\n", hmode);
        return CC_RET_UNSUPP_ALG_MODE;
    }
#else
    switch (hmode) {
        case DRV_HASH_SHA1:
            digestAddr = (CCSramAddr_t) ((CCVirtAddr_t) gLarvalSha1Digest);
            break;
        case DRV_HASH_SHA224:
            digestAddr = (CCSramAddr_t) ((CCVirtAddr_t) gLarvalSha224Digest);
            break;
        case DRV_HASH_SHA256:
            digestAddr = (CCSramAddr_t) ((CCVirtAddr_t) gLarvalSha256Digest);
            break;
        case DRV_HASH_MD5:
            digestAddr = (CCSramAddr_t) ((CCVirtAddr_t) gLarvalMd5Digest);
            break;
#ifdef CC_CONFIG_HASH_SHA_512_SUPPORTED
            case DRV_HASH_SHA384:
            digestAddr = (CCSramAddr_t)((CCVirtAddr_t)gLarvalSha384Digest);
            break;
            case DRV_HASH_SHA512:
            digestAddr = (CCSramAddr_t)((CCVirtAddr_t)gLarvalSha512Digest);
            break;
#endif
        default:
            CC_PAL_LOG_ERR("Unsupported hash mode %d\n", hmode);
            return CC_RET_UNSUPP_ALG_MODE;
    }
#endif

    /* 1. Load hash initial state */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_CIPHER_MODE(&desc, lhmode);
    HW_DESC_SET_STATE_DIN_PARAM(&desc, digestAddr, DigestSize);
    HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_HASH);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_STATE0);
    AddHWDescSequence(&desc);

    /* 2. load the hash current length, should be greater than zero */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_CIPHER_MODE(&desc, lhmode);
    HW_DESC_SET_DIN_CONST(&desc, 0, (DRV_HASH_LENGTH_WORDS * sizeof(uint32_t)));
    HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_HASH);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_KEY0);
    AddHWDescSequence(&desc);

    /* 3. prapare pad key - IPAD or OPAD */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_XOR_VAL(&desc, constPadData);
    HW_DESC_SET_CIPHER_MODE(&desc, lhmode);
    HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_HASH);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_STATE1);
    AddHWDescSequence(&desc);

    /* 4. perform HASH update */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_STATE_DIN_PARAM(&desc, hashData, hashDataSize);
    HW_DESC_SET_CIPHER_MODE(&desc, lhmode);
    HW_DESC_SET_XOR_ACTIVE(&desc);
    HW_DESC_SET_FLOW_MODE(&desc, DIN_HASH);
    AddHWDescSequence(&desc);

    /* 5. Get the digset */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_CIPHER_MODE(&desc, lhmode);
    HW_DESC_SET_STATE_DOUT_PARAM(&desc, hashResult, DigestSize);
    HW_DESC_SET_FLOW_MODE(&desc, S_HASH_to_DOUT);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_WRITE_STATE0);
    AddHWDescSequence(&desc);

    /*6. store current hash length in the private context */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_CIPHER_MODE(&desc, lhmode);
    HW_DESC_SET_CIPHER_DO(&desc, DO_NOT_PAD);
    HW_DESC_SET_STATE_DOUT_PARAM(&desc,
                                 hashCurrentLength,
                                 sizeof(uint32_t) * DRV_HASH_LENGTH_WORDS);
    HW_DESC_SET_FLOW_MODE(&desc, S_HASH_to_DOUT);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_WRITE_STATE1);
    AddHWDescSequence(&desc);

    return CC_RET_OK;
}

/******************************************************************************
 *                FUNCTIONS
 ******************************************************************************/

/*!
 * This function is used to initialize the HMAC machine to perform the HMAC
 * operations. This should be the first function called.
 *
 * \param ctxAddr A pointer to the context buffer in SRAM.
 * \param pCtx A pointer to the context buffer in local memory.
 *
 * \return int One of DX_SYM_* error codes defined in cc_sym_error.h.
 */
int InitHmac(CCSramAddr_t ctxAddr, uint32_t *pCtx)
{
    const CCSramAddr_t digestAddr = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_hash, digest);
    const CCSramAddr_t k0Addr = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_hash, k0);
    const CCSramAddr_t currentDigestedLengthAddr = GET_CTX_FIELD_ADDR(ctxAddr,
                                                                      struct drv_ctx_hash,
                                                                      CurrentDigestedLength);
    uint32_t BlockSize, KeySize;
    int drvRc = CC_RET_OK;
    struct drv_ctx_hash * pHmacCtx = (struct drv_ctx_hash *) pCtx;

    drvRc = GetHashBlockSize(pHmacCtx->mode, &BlockSize);
    if (drvRc != CC_RET_OK) {
        goto EndWithErr;
    }

    /* pad the key with zeros */
    KeySize = pHmacCtx->k0_size;
#ifndef CC_SRAM_INDIRECT_ACCESS
    ClearCtxField((k0Addr + KeySize), (BlockSize - KeySize));
#else
    /*due to the limited access to the SRAM (words alignment)the key shold be Read/Modify/Write if the key is not aligned to words*/
    if (!(KeySize % sizeof(uint32_t))) {
        ClearCtxField((k0Addr + KeySize), (BlockSize - KeySize));
    } else {
        uint32_t keywords[CC_SHA512_BLOCK_SIZE/sizeof(uint32_t)];
        /* read the whole key and write it back */
        /*T.B.D - optimize this sequence to one word only*/
        ReadContextField(k0Addr, keywords, BlockSize);
        CC_PalMemSetZero(&((uint8_t *)&keywords[0])[KeySize], (BlockSize - KeySize));
        WriteContextField(k0Addr, keywords, BlockSize);
    }
#endif
    drvRc = InitHash(ctxAddr, pCtx);
    if (drvRc != CC_RET_OK) {
        goto EndWithErr;
    }

    drvRc = ProcessHmacPad(HMAC_IPAD_CONST_BLOCK,
                           k0Addr,
                           BlockSize,
                           pHmacCtx->mode,
                           currentDigestedLengthAddr,
                           digestAddr,
                           ctxAddr);
    if (drvRc != CC_RET_OK) {
        goto EndWithErr;
    }
    drvRc = ProcessHmacPad(HMAC_OPAD_CONST_BLOCK,
                           k0Addr,
                           BlockSize,
                           pHmacCtx->mode,
                           currentDigestedLengthAddr,
                           k0Addr,
                           ctxAddr);
    if (drvRc != CC_RET_OK) {
        goto EndWithErr;
    }

EndWithErr:

    return drvRc;
}

/********************************************************************************/
/********************************************************************************/
/*!! we do not implement "ProcessHmac" since it directly calls ProcessHash     */
/********************************************************************************/
/********************************************************************************/

/*!
 * This function is used as finish operation of the HMAC machine.
 * The function may be called after "InitHmac".
 *
 * \param ctxAddr A pointer to the HMAC context buffer in SRAM.
 * \param pCtx A pointer to the HMAC context buffer in local memory.
 * \param pDmaInputBuffer A structure which represents the DMA input buffer.
 * \param pDmaOutputBuffer A structure which represents the DMA output buffer.
 *
 * \return int One of DX_SYM_* error codes defined in cc_sym_error.h.
 */
int FinalizeHmac(CCSramAddr_t ctxAddr,
                 uint32_t *pCtx,
                 DmaBuffer_s *pDmaInputBuffer,
                 DmaBuffer_s *pDmaOutputBuffer)
{
    const CCSramAddr_t digestAddr = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_hash, digest);
    DmaBuffer_s HashDmaBuffer;
    uint32_t DigestSize;
    int drvRc = CC_RET_OK;
    struct drv_ctx_hash * pHmacCtx = (struct drv_ctx_hash *) pCtx;

    CC_UNUSED_PARAM(pDmaOutputBuffer);    // remove compilation warning
    drvRc = GetHashDigestSize(pHmacCtx->mode, &DigestSize);
    if (drvRc != CC_RET_OK) {
        goto EndWithErr;
    }

    /* finalize user data (data may be zero length) */
    drvRc = FinalizeHash(ctxAddr, pCtx, pDmaInputBuffer, NULL);
    if (drvRc != CC_RET_OK) {
        goto EndWithErr;
    }

    pHmacCtx->hmacFinalization = 1;
    HashDmaBuffer.pData = digestAddr;
    HashDmaBuffer.size = DigestSize;
    HashDmaBuffer.dmaBufType = DMA_BUF_SEP;
    HashDmaBuffer.axiNs = DEFALUT_AXI_SECURITY_MODE;

    drvRc = FinalizeHash(ctxAddr, pCtx, &HashDmaBuffer, NULL);

EndWithErr:

    return drvRc;
}

