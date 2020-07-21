/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#define CC_PAL_LOG_CUR_COMPONENT CC_LOG_MASK_CC_SYM_DRIVER

#include "cc_pal_mem.h"
#include "cc_plat.h"
#include "mlli.h"
#include "hw_queue.h"
#include "completion.h"
#include "cc_sym_error.h"
#include "aead.h"
#include "cc_crypto_ctx.h"
#include "hash_defs.h"

CC_PAL_COMPILER_ASSERT(sizeof(struct drv_ctx_aead)==CC_CTX_SIZE, "drv_ctx_aead is larger than 128 bytes!");
CC_PAL_COMPILER_ASSERT(sizeof(SepAeadCcmMode_e)==sizeof(uint32_t), "SepAeadCcmMode_e is not 32bit!");
CC_PAL_COMPILER_ASSERT(sizeof(DrvAeadGcmCcmFlow_e)==sizeof(uint32_t), "DrvAeadCcmFlow_e is not 32bit!");

/******************************************************************************
 *                PRIVATE FUNCTIONS
 ******************************************************************************/
static void LoadAeadMac(CCSramAddr_t ctxAddr, struct drv_ctx_aead *pCtxAead)
{
    const CCSramAddr_t macStateAddr = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_aead, mac_state);
    HwDesc_s desc;

    HW_DESC_INIT(&desc);
    HW_DESC_SET_KEY_SIZE_AES(&desc, pCtxAead->key_size);
    HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_HASH);
    HW_DESC_SET_AES_NOT_HASH_MODE(&desc);
    HW_DESC_SET_STATE_DIN_PARAM(&desc, macStateAddr, CC_AES_BLOCK_SIZE);
    HW_DESC_SET_CIPHER_CONFIG0(&desc, pCtxAead->direction);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_STATE0);
    if (pCtxAead->mode == DRV_CIPHER_CCM) {
        HW_DESC_SET_CIPHER_MODE(&desc, DRV_CIPHER_CBC_MAC);
    } else {
        HW_DESC_SET_CIPHER_MODE(&desc, DRV_HASH_HW_GHASH);
        HW_DESC_SET_CIPHER_CONFIG1(&desc, HASH_PADDING_ENABLED);
    }
    AddHWDescSequence(&desc);
}

static void StoreAeadMac(CCSramAddr_t ctxAddr, struct drv_ctx_aead *pCtxAead)
{
    const CCSramAddr_t macStateAddr = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_aead, mac_state);
    HwDesc_s desc;

    HW_DESC_INIT(&desc);
    HW_DESC_SET_STATE_DOUT_PARAM(&desc, macStateAddr, CC_AES_BLOCK_SIZE);
    if (pCtxAead->mode == DRV_CIPHER_CCM) {
        HW_DESC_SET_CIPHER_MODE(&desc, DRV_CIPHER_CBC_MAC);
    } else {
        HW_DESC_SET_CIPHER_MODE(&desc, DRV_HASH_HW_GHASH);
    }
    HW_DESC_SET_FLOW_MODE(&desc, S_HASH_to_DOUT);
    HW_DESC_SET_AES_NOT_HASH_MODE(&desc);
    HW_DESC_SET_CIPHER_CONFIG0(&desc, HASH_DIGEST_RESULT_LITTLE_ENDIAN);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_WRITE_STATE0);
    AddHWDescSequence(&desc);
}

static void LoadAeadCipherState(CCSramAddr_t ctxAddr, struct drv_ctx_aead *pCtxAead)
{
    const CCSramAddr_t blockStateAddr = GET_CTX_FIELD_ADDR(ctxAddr,
                                                           struct drv_ctx_aead,
                                                           block_state);
    HwDesc_s desc;

    HW_DESC_INIT(&desc);
    if (pCtxAead->mode == DRV_CIPHER_CCM) {
        HW_DESC_SET_CIPHER_MODE(&desc, DRV_CIPHER_CTR);
    } else {
        HW_DESC_SET_CIPHER_MODE(&desc, DRV_CIPHER_GCTR);
    }
    HW_DESC_SET_KEY_SIZE_AES(&desc, pCtxAead->key_size);
    HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_AES);
    HW_DESC_SET_STATE_DIN_PARAM(&desc, blockStateAddr, CC_AES_BLOCK_SIZE);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_STATE1);
    AddHWDescSequence(&desc);
}

static void StoreAeadCipherState(CCSramAddr_t ctxAddr, struct drv_ctx_aead *pCtxAead)
{
    const CCSramAddr_t blockStateAddr = GET_CTX_FIELD_ADDR(ctxAddr,
                                                           struct drv_ctx_aead,
                                                           block_state);
    HwDesc_s desc;

    HW_DESC_INIT(&desc);
    if (pCtxAead->mode == DRV_CIPHER_CCM) {
        HW_DESC_SET_CIPHER_MODE(&desc, DRV_CIPHER_CTR);
    } else {
        HW_DESC_SET_CIPHER_MODE(&desc, DRV_CIPHER_GCTR);
    }
    HW_DESC_SET_STATE_DOUT_PARAM(&desc, blockStateAddr, CC_AES_BLOCK_SIZE);
    HW_DESC_SET_FLOW_MODE(&desc, S_AES_to_DOUT);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_WRITE_STATE1);
    AddHWDescSequence(&desc);
}

static void LoadAeadGCMHashKey(CCSramAddr_t ctxAddr, struct drv_ctx_aead *pCtxAead)
{
    HwDesc_s desc;
    const CCSramAddr_t hkeyAddr = GET_CTX_FIELD_ADDR(ctxAddr,
                                                           struct drv_ctx_aead,
                                                           hkey);
    /* Load GHASH subkey */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_CIPHER_MODE(&desc, DRV_HASH_HW_GHASH);
    HW_DESC_SET_CIPHER_CONFIG1(&desc, HASH_PADDING_ENABLED);
    HW_DESC_SET_STATE_DIN_PARAM(&desc, hkeyAddr, CC_AES_BLOCK_SIZE);
    HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_HASH);
    HW_DESC_SET_AES_NOT_HASH_MODE(&desc);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_KEY0);

    AddHWDescSequence(&desc);

    /* Configure Hash Engine to work with GHASH.
     * Since it was not possible to extend HASH submodes to add GHASH,
     * The following command is necessary in order to
     * select GHASH (according to HW designers)
     */
    if (pCtxAead->internalMode == SEP_AEAD_MODE_GCM_INIT) {
        HW_DESC_INIT(&desc);
        HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_HASH);
        HW_DESC_SET_AES_NOT_HASH_MODE(&desc);
        HW_DESC_SET_CIPHER_MODE(&desc, DRV_HASH_HW_GHASH);
        HW_DESC_SET_CIPHER_DO(&desc, 1); //1=AES_SK RKEK
        HW_DESC_SET_CIPHER_CONFIG0(&desc, DRV_CRYPTO_DIRECTION_ENCRYPT);
        HW_DESC_SET_CIPHER_CONFIG1(&desc, HASH_PADDING_ENABLED);
        HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_KEY0);

        AddHWDescSequence(&desc);
    }
}

static void LoadAeadKey(CCSramAddr_t ctxAddr, FlowMode_t engineFlow, struct drv_ctx_aead *pCtxAead)
{
    const CCSramAddr_t keyAddr = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_aead, key);
    HwDesc_s desc;

    /* key size 24 bytes count as 32 bytes, make sure to zero wise upper 8 bytes */
    if (pCtxAead->key_size == 24) {
        ClearCtxField((keyAddr + 24), CC_AES_KEY_SIZE_MAX - 24);
    }

    if ((engineFlow == S_DIN_to_HASH) && (pCtxAead->mode == DRV_CIPHER_GCTR)) {
        LoadAeadGCMHashKey(ctxAddr, pCtxAead);
        return;
    }

    HW_DESC_INIT(&desc);
    if (engineFlow == S_DIN_to_HASH) {
        HW_DESC_SET_CIPHER_MODE(&desc, DRV_CIPHER_CBC_MAC);
        HW_DESC_SET_AES_NOT_HASH_MODE(&desc);
    } else {
        if (pCtxAead->mode == DRV_CIPHER_CCM) {
            HW_DESC_SET_CIPHER_MODE(&desc, DRV_CIPHER_CTR);
        } else {
            HW_DESC_SET_CIPHER_MODE(&desc, DRV_CIPHER_GCTR);
        }
    }

    HW_DESC_SET_KEY_SIZE_AES(&desc, pCtxAead->key_size);
    HW_DESC_SET_STATE_DIN_PARAM(&desc, keyAddr, pCtxAead->key_size);
    HW_DESC_SET_FLOW_MODE(&desc, engineFlow);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_KEY0);

    AddHWDescSequence(&desc);
}

static uint16_t FormatCcmB0(uint8_t *Buf,
                            uint8_t *Nonce,
                            uint32_t NonceSize,
                            uint32_t Tag,
                            uint32_t AddDataSize,
                            uint32_t InputDataLen)
{
    uint32_t len, Q, x, y;

    /* let's get the L value */
    len = InputDataLen;
    Q = 0;

    while (len) {
        ++Q;
        len >>= 8;
    }

    if (Q <= 1) {
        Q = 2;
    }

    /* increase L to match the nonce len */
    NonceSize = (NonceSize > 13) ? 13 : NonceSize;
    if ((15 - NonceSize) > Q) {
        Q = 15 - NonceSize;
    }

    /* form B_0 == flags | Nonce N | l(m) */
    x = 0;
    Buf[x++] = (uint8_t) (((AddDataSize > 0) ? (1 << 6) : 0) | (((Tag - 2) >> 1) << 3) | (Q - 1));

    /* nonce */
    for (y = 0; y < (16 - (Q + 1)); y++) {
        Buf[x++] = Nonce[y];
    }

    /* store len */
    len = InputDataLen;

    /* shift len so the upper bytes of len are the contents of the length */
    for (y = Q; y < 4; y++) {
        len <<= 8;
    }

    /* store l(m) (only store 32-bits) */
    for (y = 0; Q > 4 && (Q - y) > 4; y++) {
        Buf[x++] = 0;
    }

    for (; y < Q; y++) {
        Buf[x++] = (uint8_t) ((len >> 24) & 0xFF);
        len <<= 8;
    }

    return (uint16_t) Q;
}

static void InitCcmCounter(CCSramAddr_t ctxAddr,
                           uint8_t CounterInitialValue,
                           struct drv_ctx_aead *pCtxAead)
{
    const CCSramAddr_t blockStateAddr = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_aead, block_state);
    uint32_t Q = pCtxAead->q;
    uint32_t nonceSize = CC_AES_BLOCK_SIZE - (Q + 1);
    uint32_t word = 0; /*work buffer*/
    uint8_t *p = (uint8_t *) &word;
    uint32_t i = 0;
    uint32_t j = 0;
    HwDesc_s desc;
    uint32_t nonceBuff[CC_AES_BLOCK_SIZE_WORDS];
    uint8_t *nonce = (uint8_t*) &nonceBuff;

    CC_PalMemCopy(nonceBuff, pCtxAead->nonce, CC_AES_BLOCK_SIZE);
    p[0] = (uint8_t) Q - 1;
    p[1] = nonce[j++];
    p[2] = nonce[j++];
    p[3] = nonce[j++];

    word = SWAP_TO_LE(word);
    /* set 1B flags + 3B of the nonce */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_DIN_CONST(&desc, word, sizeof(uint32_t));
    HW_DESC_SET_STATE_DOUT_PARAM(&desc, blockStateAddr, sizeof(uint32_t));
    HW_DESC_SET_FLOW_MODE(&desc, BYPASS);
    AddHWDescSequence(&desc);

    /* set nonce */
    for (i = 4; j < nonceSize; i += 4) {

        p[0] = nonce[j++];
        p[1] = (j < nonceSize) ? nonce[j++] : 0;
        p[2] = (j < nonceSize) ? nonce[j++] : 0;
        p[3] = (j < nonceSize) ? nonce[j++] : 0;

        /* this is the last word so set the counter value
         as passed by the user in the LSB. The nonce value
         cannot reache the last byte */
        if (i == (CC_AES_BLOCK_SIZE - sizeof(uint32_t))) {
            p[3] = CounterInitialValue;
        }

        word = SWAP_TO_LE(word);

        HW_DESC_INIT(&desc);
        HW_DESC_SET_DIN_CONST(&desc, word, sizeof(uint32_t));
        HW_DESC_SET_STATE_DOUT_PARAM(&desc, (blockStateAddr + i), sizeof(uint32_t));
        HW_DESC_SET_FLOW_MODE(&desc, BYPASS);
        AddHWDescSequence(&desc);
    }

    /* pad remainder with zero's */
    for (; i < CC_AES_BLOCK_SIZE; i += 4) {

        word = 0; /*clear word*/

        if (i == (CC_AES_BLOCK_SIZE - sizeof(uint32_t))) {
            /* this is the last word so set the counter value
             *  as passed by the user in the LSB */
            p[3] = CounterInitialValue;
        }
        word = SWAP_TO_LE(word);

        HW_DESC_INIT(&desc);
        HW_DESC_SET_DIN_CONST(&desc, word, sizeof(uint32_t));
        HW_DESC_SET_STATE_DOUT_PARAM(&desc, (blockStateAddr + i), sizeof(uint32_t));
        HW_DESC_SET_FLOW_MODE(&desc, BYPASS);
        AddHWDescSequence(&desc);
    }
}

static void GetFinalCcmMac(CCSramAddr_t ctxAddr, struct drv_ctx_aead *pCtxAead)
{
    const CCSramAddr_t keyAddr = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_aead, key);
    const CCSramAddr_t blockStateAddr = GET_CTX_FIELD_ADDR(ctxAddr,
                                                           struct drv_ctx_aead,
                                                           block_state);
    const CCSramAddr_t macStateAddr = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_aead, mac_state);
    HwDesc_s desc;

    /* if tag-len is 0, skip finsih, relevant only for ccm-star, validated in ccm init function */
    if (pCtxAead->tag_size == 0) {
        return;
    }

    /* key size 24 bytes count as 32 bytes, make sure to zero wise upper 8 bytes */
    if (pCtxAead->key_size == 24) {
        ClearCtxField((keyAddr + 24), CC_AES_KEY_SIZE_MAX - 24);
    }

    /* initialize CTR counter */
    InitCcmCounter(ctxAddr, 0, pCtxAead);

    /* load AES-CTR state */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_CIPHER_MODE(&desc, DRV_CIPHER_CTR);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_STATE1);
    HW_DESC_SET_KEY_SIZE_AES(&desc, pCtxAead->key_size);
    HW_DESC_SET_CIPHER_CONFIG0(&desc, DRV_CRYPTO_DIRECTION_ENCRYPT);
    HW_DESC_SET_STATE_DIN_PARAM(&desc, blockStateAddr, CC_AES_BLOCK_SIZE);
    HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_AES);
    AddHWDescSequence(&desc);

    /* load AES-CTR key */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_CIPHER_MODE(&desc, DRV_CIPHER_CTR);
    HW_DESC_SET_CIPHER_CONFIG0(&desc, DRV_CRYPTO_DIRECTION_ENCRYPT);
    HW_DESC_SET_STATE_DIN_PARAM(&desc, keyAddr, pCtxAead->key_size);
    HW_DESC_SET_KEY_SIZE_AES(&desc, pCtxAead->key_size);
    HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_AES);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_KEY0);
    AddHWDescSequence(&desc);

    /* encrypt the "T" value and store MAC in mac_state */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_STATE_DIN_PARAM(&desc, macStateAddr, pCtxAead->tag_size);
    HW_DESC_SET_STATE_DOUT_PARAM(&desc, macStateAddr, pCtxAead->tag_size);
    HW_DESC_SET_FLOW_MODE(&desc, DIN_AES_DOUT);
    AddHWDescSequence(&desc);
}

static void GetFinalGcmMac(CCSramAddr_t ctxAddr, struct drv_ctx_aead *pCtxAead)
{
    const CCSramAddr_t keyAddr = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_aead, key);
    const CCSramAddr_t gcmLenBlockAddr = GET_CTX_FIELD_ADDR(ctxAddr,
                                                           struct drv_ctx_aead,
                                                           gcm_len_block);
    const CCSramAddr_t macStateAddr = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_aead, mac_state);
    const CCSramAddr_t nonceAddr = GET_CTX_FIELD_ADDR(ctxAddr,
                                                           struct drv_ctx_aead,
                                                           nonce);
    HwDesc_s desc;

    /* key size 24 bytes count as 32 bytes, make sure to zero wise upper 8 bytes */
    if (pCtxAead->key_size == 24) {
        ClearCtxField((keyAddr + 24), CC_AES_KEY_SIZE_MAX - 24);
    }

    LoadAeadKey(ctxAddr, S_DIN_to_HASH, pCtxAead);
    LoadAeadMac(ctxAddr, pCtxAead);

    /* process(ghash) gcm_block_len */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_STATE_DIN_PARAM(&desc, gcmLenBlockAddr, CC_AES_BLOCK_SIZE);
    HW_DESC_SET_FLOW_MODE(&desc, DIN_HASH);
    AddHWDescSequence(&desc);

    /* Store GHASH state after GHASH(Associated Data + Cipher +LenBlock) */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_CIPHER_MODE(&desc, DRV_HASH_HW_GHASH);
    HW_DESC_SET_DIN_NO_DMA(&desc, 0, 0xfffff0);
    HW_DESC_SET_STATE_DOUT_PARAM(&desc, macStateAddr, CC_AES_BLOCK_SIZE);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_WRITE_STATE0);
    HW_DESC_SET_FLOW_MODE(&desc, S_HASH_to_DOUT);
    HW_DESC_SET_AES_NOT_HASH_MODE(&desc);
    AddHWDescSequence(&desc);

    if (pCtxAead->text_size == 0) {
        /* load key to AES - in case data exists, already init GCTR flow */
        HW_DESC_INIT(&desc);
        HW_DESC_SET_CIPHER_MODE(&desc, DRV_CIPHER_GCTR);
        HW_DESC_SET_CIPHER_CONFIG0(&desc, DRV_CRYPTO_DIRECTION_ENCRYPT);
        HW_DESC_SET_STATE_DIN_PARAM(&desc, keyAddr, pCtxAead->key_size);
        HW_DESC_SET_KEY_SIZE_AES(&desc, pCtxAead->key_size);
        HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_AES);
        HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_KEY0);
        AddHWDescSequence(&desc);
    }

    /* load AES-GCTR state */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_CIPHER_MODE(&desc, DRV_CIPHER_GCTR);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_STATE1);
    HW_DESC_SET_KEY_SIZE_AES(&desc, pCtxAead->key_size);
    HW_DESC_SET_CIPHER_CONFIG0(&desc, DRV_CRYPTO_DIRECTION_ENCRYPT);
    HW_DESC_SET_STATE_DIN_PARAM(&desc, nonceAddr, CC_AES_BLOCK_SIZE);
    HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_AES);
    AddHWDescSequence(&desc);

    /* Memory Barrier */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_DIN_NO_DMA(&desc, 0, 0xfffff0);
    HW_DESC_SET_LAST_IND(&desc);
    AddHWDescSequence(&desc);

    /* encrypt the "T" value and store MAC in mac_state */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_CIPHER_MODE(&desc, DRV_CIPHER_GCTR);
    HW_DESC_SET_STATE_DIN_PARAM(&desc, macStateAddr, CC_AES_BLOCK_SIZE);
    HW_DESC_SET_STATE_DOUT_PARAM(&desc, macStateAddr, pCtxAead->tag_size);
    HW_DESC_SET_FLOW_MODE(&desc, DIN_AES_DOUT);
    HW_DESC_SET_QUEUE_LAST_IND(&desc);
    AddHWDescSequence(&desc);
}

static uint32_t GetActualHeaderSize(uint32_t headerSize)
{
    if (headerSize == 0) {
        return 0;
    } else if (headerSize < ((1UL << 16) - (1UL << 8))) {
        return (2 + headerSize);
    } else {
        return (6 + headerSize);
    }
}

static void AesGcmCalcH(CCSramAddr_t ctxAddr, struct drv_ctx_aead *pCtxAead)
{
    HwDesc_s desc;

    const CCSramAddr_t keyAddr = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_aead, key);
    const CCSramAddr_t hkeyAddr = GET_CTX_FIELD_ADDR(ctxAddr,
                                                           struct drv_ctx_aead,
                                                           hkey);

    /* the hash subkey for the GHASH function is generated by applying
     * the block cipher to the “zero” block
     */

    /* load key to AES*/
    HW_DESC_INIT(&desc);
    HW_DESC_SET_CIPHER_MODE(&desc, DRV_CIPHER_ECB);
    HW_DESC_SET_CIPHER_CONFIG0(&desc, DRV_CRYPTO_DIRECTION_ENCRYPT);
    HW_DESC_SET_STATE_DIN_PARAM(&desc, keyAddr, pCtxAead->key_size);
    HW_DESC_SET_KEY_SIZE_AES(&desc, pCtxAead->key_size);
    HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_AES);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_KEY0);
    AddHWDescSequence(&desc);

    /* process one zero block to generate hkey - store the results
     * at block_state */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_DIN_CONST(&desc, 0, CC_AES_BLOCK_SIZE);
    HW_DESC_SET_STATE_DOUT_PARAM(&desc, hkeyAddr, CC_AES_BLOCK_SIZE);
    HW_DESC_SET_FLOW_MODE(&desc, DIN_AES_DOUT);
    AddHWDescSequence(&desc);

    /* Memory Barrier */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_DIN_NO_DMA(&desc, 0, 0xfffff0);
    HW_DESC_SET_LAST_IND(&desc);
    AddHWDescSequence(&desc);
}

static void AesGcmCalcJ0(CCSramAddr_t ctxAddr)
{
    HwDesc_s desc;

    const CCSramAddr_t nonceAddr = GET_CTX_FIELD_ADDR(ctxAddr,
                                                           struct drv_ctx_aead,
                                                           nonce);

    /* process(ghash) IV length */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_STATE_DIN_PARAM(&desc, nonceAddr, CC_AES_BLOCK_SIZE);
    HW_DESC_SET_FLOW_MODE(&desc, DIN_HASH);
    AddHWDescSequence(&desc);

    /* Store GHASH state after GHASH(Associated Data + Cipher +LenBlock) */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_CIPHER_MODE(&desc, DRV_HASH_HW_GHASH);
    HW_DESC_SET_DOUT_SRAM(&desc, nonceAddr, CC_AES_BLOCK_SIZE);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_WRITE_STATE0);
    HW_DESC_SET_FLOW_MODE(&desc, S_HASH_to_DOUT);
    HW_DESC_SET_AES_NOT_HASH_MODE(&desc);
    AddHWDescSequence(&desc);

    /* Memory Barrier */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_DIN_NO_DMA(&desc, 0, 0xfffff0);
    HW_DESC_SET_LAST_IND(&desc);
    AddHWDescSequence(&desc);
}

/******************************************************************************
 *                FUNCTIONS
 ******************************************************************************/

/*!
 * This function is used to initialize the AES machine to perform
 * the AEAD operations. This should be the first function called.
 *
 * \param ctxAddr A pointer to the AES context buffer in SRAM.
 * \param pCtx A pointer to the AES context buffer in local memory.
 *
 * \return int One of DX_SYM_* error codes defined in cc_sym_error.h.
 */

int InitAead(CCSramAddr_t ctxAddr, uint32_t *pCtx)
{
    const CCSramAddr_t blockStateAddr = GET_CTX_FIELD_ADDR(ctxAddr,
                                                           struct drv_ctx_aead,
                                                           block_state);
    const CCSramAddr_t macStateAddr = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_aead, mac_state);
    HwDesc_s desc;
    struct drv_ctx_aead * pAeadCtx = (struct drv_ctx_aead *) pCtx;
    uint32_t headerSize = pAeadCtx->header_size;

#ifdef CC_SRAM_INDIRECT_ACCESS
    uint32_t nonceBuff[CC_AES_BLOCK_SIZE_WORDS];
    uint8_t *nonce = (uint8_t*)&nonceBuff;
    uint32_t stateBuff[CC_AES_BLOCK_SIZE_WORDS];
#endif
    switch (pAeadCtx->mode) {
        case DRV_CIPHER_CCM:
            /* set AES-CCM internal mode: initial state */
            pAeadCtx->internalMode = SEP_AEAD_MODE_CCM_A;
            if (headerSize == 0) {
                pAeadCtx->nextProcessingState = DRV_AEAD_FLOW_TEXT_DATA_INIT;
            } else {
                pAeadCtx->nextProcessingState = DRV_AEAD_FLOW_ADATA_INIT;
            }

            /* clear AES CTR/MAC states */
            ClearCtxField(blockStateAddr, CC_AES_BLOCK_SIZE);
            ClearCtxField(macStateAddr, CC_AES_BLOCK_SIZE);
            pAeadCtx->headerRemainingBytes = GetActualHeaderSize(headerSize);

            CC_PalMemCopy(nonceBuff, pAeadCtx->nonce, CC_AES_BLOCK_SIZE);
            pAeadCtx->q = FormatCcmB0((uint8_t *) stateBuff,
                                      nonce,
                                      pAeadCtx->nonce_size,
                                      pAeadCtx->tag_size,
                                      pAeadCtx->header_size,
                                      pAeadCtx->text_size);
            WriteContextField(blockStateAddr, stateBuff, CC_AES_BLOCK_SIZE);

            /* format B0 header */

            /* calc MAC signature on B0 header */
            LoadAeadMac(ctxAddr, pAeadCtx);

            LoadAeadKey(ctxAddr, S_DIN_to_HASH, pAeadCtx);

            HW_DESC_INIT(&desc);
            HW_DESC_SET_STATE_DIN_PARAM(&desc, blockStateAddr, CC_AES_BLOCK_SIZE);
            HW_DESC_SET_FLOW_MODE(&desc, DIN_HASH);
            AddHWDescSequence(&desc);

            /* MAC result stored in mac_state */
            StoreAeadMac(ctxAddr, pAeadCtx);

            break;
        case DRV_CIPHER_GCTR:
            /* set AES-GCM internal mode: not relevant */
            pAeadCtx->internalMode = SEP_AEAD_MODE_GCM_INIT;

            if (pAeadCtx->nonce_size == CC_AESGCM_IV_96_BITS_SIZE_BYTES) {
                if (pAeadCtx->header_size == 0) {
                    pAeadCtx->nextProcessingState = DRV_AEAD_FLOW_TEXT_DATA_INIT;
                } else {
                    pAeadCtx->nextProcessingState = DRV_AEAD_FLOW_ADATA_INIT;
                }
            } else {
                pAeadCtx->nextProcessingState = DRV_AEAD_FLOW_GCM_IV;
            }
            /* clear AES CTR/MAC states */
            ClearCtxField(blockStateAddr, CC_AES_BLOCK_SIZE);
            ClearCtxField(macStateAddr, CC_AES_BLOCK_SIZE);
            pAeadCtx->headerRemainingBytes = GetActualHeaderSize(headerSize);

            /* Calculate GHASH key */
            AesGcmCalcH(ctxAddr, pAeadCtx);
            break;

        default:
            CC_PAL_LOG_ERR("Alg mode not supported");
            return CC_RET_UNSUPP_ALG;
    }

    return CC_RET_OK;
}

/*!
 * This function is used to process a block(s) of data on AES machine.
 * The user must process any associated data followed by the text data
 * blocks. This function MUST be called after the InitCipher function.
 *
 * \param ctxAddr A pointer to the AES context buffer in SRAM.
 * \param pCtx A pointer to the AES context buffer in local memory.
 * \param pDmaInputBuffer A structure which represents the DMA input buffer.
 * \param pDmaOutputBuffer A structure which represents the DMA output buffer.
 *
 * \return int One of DX_SYM_* error codes defined in cc_sym_error.h.
 */
int ProcessAead(CCSramAddr_t ctxAddr,
                uint32_t *pCtx,
                DmaBuffer_s *pDmaInputBuffer,
                DmaBuffer_s *pDmaOutputBuffer)
{
    CCDmaAddr_t pInputData = 0, pOutputData = 0;
    uint32_t DataInSize = 0, DataOutSize = 0;
    HwDesc_s desc;
    FlowMode_t engineFlow = FLOW_MODE_NULL;
    DmaMode_t dmaInMode = NO_DMA;
    DmaMode_t dmaOutMode = NO_DMA;
    uint8_t inAxiNs = pDmaInputBuffer->axiNs;
    uint8_t outAxiNs = pDmaOutputBuffer->axiNs;
    struct drv_ctx_aead * pAeadCtx = (struct drv_ctx_aead *) pCtx;
    uint32_t internalMode;
    const CCSramAddr_t macStateAddr = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_aead, mac_state);

    const int isInplaceOp = ((pDmaInputBuffer->pData == pDmaOutputBuffer->pData)
                    || (pAeadCtx->nextProcessingState == DRV_AEAD_FLOW_GCM_IV)
                    || (pAeadCtx->nextProcessingState == DRV_AEAD_FLOW_ADATA_INIT)
                    || (pAeadCtx->nextProcessingState == DRV_AEAD_FLOW_ADATA_PROCESS)
                    || (pDmaOutputBuffer->pData == 0));
    int drvRc = CC_RET_OK;

    if ((pAeadCtx->mode != DRV_CIPHER_CCM) && (pAeadCtx->mode != DRV_CIPHER_GCTR)) {
        CC_PAL_LOG_ERR("Alg mode not supported");
        drvRc = CC_RET_UNSUPP_ALG;
        goto EndWithErr;
    }

    dmaInMode = DMA_BUF_TYPE_TO_MODE(pDmaInputBuffer->dmaBufType);
    dmaOutMode = DMA_BUF_TYPE_TO_MODE(pDmaOutputBuffer->dmaBufType);

    switch (pAeadCtx->nextProcessingState) {
        case DRV_AEAD_FLOW_GCM_IV:
            if (pAeadCtx->mode != DRV_CIPHER_GCTR) {
                CC_PAL_LOG_ERR("IV state valid for GCM only");
                drvRc = CC_RET_UNSUPP_ALG_MODE;
                goto EndWithErr;
            }
            LoadAeadKey(ctxAddr, S_DIN_to_HASH, pAeadCtx);
            LoadAeadMac(ctxAddr, pAeadCtx);

            engineFlow = DIN_HASH;
            break;
        case DRV_AEAD_FLOW_ADATA_INIT:

            if (pAeadCtx->mode == DRV_CIPHER_CCM) {
                /* set the next flow sate */
                if (dmaInMode == DMA_MLLI) {
                    /* if MLLI -we expect to have the all header at once,
                     *  could be one table or more but in a single descriptor processing */
                    pAeadCtx->nextProcessingState = DRV_AEAD_FLOW_TEXT_DATA_INIT;
                    pAeadCtx->headerRemainingBytes = pAeadCtx->headerRemainingBytes
                                - pAeadCtx->header_size;
                } else {
                    /* if SRAM or DLLI -user may process his associated data in a partial AES blocks */
                    pAeadCtx->nextProcessingState = DRV_AEAD_FLOW_ADATA_PROCESS;
                }

                /* initialize AES-CTR counter only once */
                InitCcmCounter(ctxAddr, 1, pAeadCtx);
            }

            /* load mac state and key */
            LoadAeadMac(ctxAddr, pAeadCtx);
            LoadAeadKey(ctxAddr, S_DIN_to_HASH, pAeadCtx);

            engineFlow = DIN_HASH;

            if (pAeadCtx->mode == DRV_CIPHER_GCTR) {
                pAeadCtx->nextProcessingState = DRV_AEAD_FLOW_TEXT_DATA_INIT;
                pAeadCtx->internalMode = SEP_AEAD_MODE_GCM_START_TEXT_GHASH;
            }

            break;
        case DRV_AEAD_FLOW_ADATA_PROCESS:
            /* set the next flow sate */
            if (dmaInMode == DMA_MLLI) {
                pAeadCtx->nextProcessingState = DRV_AEAD_FLOW_TEXT_DATA_INIT;
                pAeadCtx->headerRemainingBytes = pAeadCtx->headerRemainingBytes
                                - pAeadCtx->header_size;
            }

            LoadAeadMac(ctxAddr, pAeadCtx);
            LoadAeadKey(ctxAddr, S_DIN_to_HASH, pAeadCtx);

            engineFlow = DIN_HASH;
            break;
        case DRV_AEAD_FLOW_TEXT_DATA_INIT:
            pAeadCtx->nextProcessingState = DRV_AEAD_FLOW_TEXT_DATA_PROCESS;

            if (pAeadCtx->mode == DRV_CIPHER_CCM) {
                /* set internal mode: CCM encrypt/decrypt */
                pAeadCtx->internalMode = SEP_AEAD_CCM_SET_INTERNAL_MODE(pAeadCtx->direction);
                /* initialize AES-CTR counter only once */
                InitCcmCounter(ctxAddr, 1, pAeadCtx);
            }

            /*FALLTHROUGH*/
        case DRV_AEAD_FLOW_TEXT_DATA_PROCESS:
        default:
            LoadAeadKey(ctxAddr, S_DIN_to_AES, pAeadCtx);
            LoadAeadCipherState(ctxAddr, pAeadCtx);
            LoadAeadMac(ctxAddr, pAeadCtx);
            LoadAeadKey(ctxAddr, S_DIN_to_HASH, pAeadCtx);

            if (pAeadCtx->mode == DRV_CIPHER_CCM) {
                if (pAeadCtx->direction == DRV_CRYPTO_DIRECTION_DECRYPT) {
                    engineFlow = AES_to_HASH_and_DOUT;
                } else {
                    engineFlow = AES_and_HASH;
                }
            } else {
                pAeadCtx->internalMode = SEP_AEAD_MODE_GCM_START_TEXT_GHASH;

                if (pAeadCtx->direction == DRV_CRYPTO_DIRECTION_ENCRYPT) {
                    engineFlow = AES_to_HASH_and_DOUT;
                } else {
                    engineFlow = AES_and_HASH;
                }
            }
            break;
    }

    internalMode = pAeadCtx->internalMode;

    switch (dmaInMode) {
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

    if (isInplaceOp) {
        pOutputData = pInputData;
        DataOutSize = DataInSize;
    } else {
        switch (dmaOutMode) {
            case DMA_MLLI:
                /* get OUT MLLI tables pointer in SRAM (if not inplace operation) */
                pOutputData = MLLI_getFirstLLIPtr(MLLI_OUTPUT_TABLE);
                MLLI_loadTableToSRAM(pDmaOutputBuffer->pData,
                                     pDmaOutputBuffer->size,
                                     pDmaOutputBuffer->axiNs,
                                     MLLI_OUTPUT_TABLE);
                /* data size should hold the number of LLIs */
                DataOutSize = (pDmaOutputBuffer->size) / LLI_ENTRY_BYTE_SIZE;
                break;
            case DMA_DLLI:
            case DMA_SRAM:
                pOutputData = pDmaOutputBuffer->pData;
                /* set the data size */
                DataOutSize = pDmaOutputBuffer->size;
                break;
            default:
                if (internalMode != SEP_AEAD_MODE_CCM_A) {
                    CC_PAL_LOG_ERR("Invalid DMA mode\n");
                    drvRc = CC_RET_INVARG;
                    goto EndWithErr;
                }
        }
    }

    /* process the AEAD flow */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_DIN_TYPE(&desc, dmaInMode, pInputData, DataInSize, inAxiNs);
    if ((internalMode != SEP_AEAD_MODE_CCM_A) && (pAeadCtx->nextProcessingState != DRV_AEAD_FLOW_GCM_IV)) {
        HW_DESC_SET_DOUT_TYPE(&desc, dmaOutMode, pOutputData, DataOutSize, outAxiNs);
    }

    HW_DESC_SET_FLOW_MODE(&desc, engineFlow);

    AddHWDescSequence(&desc);

    /* store machine state */
    if (internalMode == SEP_AEAD_MODE_CCM_A) {
        StoreAeadMac(ctxAddr, pAeadCtx);

        if ((dmaInMode == DMA_DLLI) || (dmaInMode == DMA_SRAM)) {
            pAeadCtx->headerRemainingBytes = pAeadCtx->headerRemainingBytes - pDmaInputBuffer->size;
            if (pAeadCtx->headerRemainingBytes > pAeadCtx->header_size) {
                CC_PAL_LOG_ERR("Inconceivable state: Assoc remaining bytes > Header size");
                drvRc = CC_RET_NOEXEC;
                goto EndWithErr;
            }
            if (pAeadCtx->headerRemainingBytes == 0) {
                /* we're done processing associated data move on to text initialization flow */
                pAeadCtx->nextProcessingState = DRV_AEAD_FLOW_TEXT_DATA_INIT;
            }
        }
    } else if (pAeadCtx->nextProcessingState == DRV_AEAD_FLOW_GCM_IV) {
        AesGcmCalcJ0(ctxAddr);

        /* restart GHASH */
        ClearCtxField(macStateAddr, CC_AES_BLOCK_SIZE);

        if (pAeadCtx->header_size == 0) {
            pAeadCtx->nextProcessingState = DRV_AEAD_FLOW_TEXT_DATA_INIT;
        } else {
            pAeadCtx->nextProcessingState = DRV_AEAD_FLOW_ADATA_INIT;
        }
        return drvRc;
    }

    StoreAeadMac(ctxAddr, pAeadCtx);

    if ((pAeadCtx->mode == DRV_CIPHER_CCM) || (pAeadCtx->nextProcessingState == DRV_AEAD_FLOW_TEXT_DATA_PROCESS)) {
        StoreAeadCipherState(ctxAddr, pAeadCtx);
    }
EndWithErr:
    return drvRc;
}

/*!
 * This function is used as finish operation of AEAD. The function MUST either
 * be called after "InitCipher" or "ProcessCipher".
 *
 * \param ctxAddr A pointer to the AES context buffer in SRAM.
 * \param pDmaInputBuffer A structure which represents the DMA input buffer.
 * \param pDmaOutputBuffer A structure which represents the DMA output buffer.
 *
 * \return int One of DX_SYM_* error codes defined in cc_sym_error.h.
 */
int FinalizeAead(CCSramAddr_t ctxAddr,
                 uint32_t *pCtx,
                 DmaBuffer_s *pDmaInputBuffer,
                 DmaBuffer_s *pDmaOutputBuffer)
{
    uint32_t isRemainingData = 0;
    DmaMode_t dmaMode = NO_DMA;
    int drvRc = CC_RET_OK;
    struct drv_ctx_aead * pAeadCtx = (struct drv_ctx_aead *) pCtx;

    if ((pAeadCtx->mode != DRV_CIPHER_CCM) && (pAeadCtx->mode != DRV_CIPHER_GCTR)) {
        CC_PAL_LOG_ERR("Alg mode not supported");
        drvRc = CC_RET_UNSUPP_ALG;
        goto EndWithErr;
    }

    dmaMode = DMA_BUF_TYPE_TO_MODE(pDmaInputBuffer->dmaBufType);

    /* check if we have remaining data to process */
    switch (dmaMode) {
        case DMA_MLLI:
            isRemainingData = (pDmaInputBuffer->size > 0) ? 1 : 0;
            break;
        case DMA_DLLI:
        case DMA_SRAM:
            isRemainingData = (pDmaInputBuffer->size > 0) ? 1 : 0;
            break;
        case NO_DMA:
            break;
        default:
            CC_PAL_LOG_ERR("Invalid DMA mode\n");
            drvRc = CC_RET_INVARG;
            goto EndWithErr;
    }

    /* clobber remaining AEAD data */
    if (isRemainingData) {
        /* process all tables and get state from the AES machine */
        drvRc = ProcessAead(ctxAddr, pCtx, pDmaInputBuffer, pDmaOutputBuffer);
        if (drvRc != CC_RET_OK) {
            goto EndWithErr;
        }
    }

    if (pAeadCtx->mode == DRV_CIPHER_CCM) {
        /* get the CCM-MAC result */
        GetFinalCcmMac(ctxAddr, pAeadCtx);
    } else {
        GetFinalGcmMac(ctxAddr, pAeadCtx);
    }

EndWithErr:

    return drvRc;
}

