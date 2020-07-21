/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#define CC_PAL_LOG_CUR_COMPONENT CC_LOG_MASK_CC_SYM_DRIVER

#include "cc_pal_mem.h"
#include "cc_pal_log.h"
#include "cc_plat.h"
#include "mlli.h"
#include "cipher.h"
#include "cc_crypto_ctx.h"
#include "hw_queue.h"
#include "cc_sym_error.h"
#include "cc_hal_plat.h"
#include "sym_crypto_driver.h"
#include "cc_util_int_defs.h"

CC_PAL_COMPILER_ASSERT(sizeof(struct drv_ctx_cipher)==CC_CTX_SIZE,"drv_ctx_cipher is larger than 128 bytes!");
CC_PAL_COMPILER_ASSERT(sizeof(enum drv_cipher_mode)==sizeof(uint32_t), "drv_cipher_mode is not 32bit!");
CC_PAL_COMPILER_ASSERT(sizeof(DataBlockType_t)==sizeof(uint32_t), "DataBlockType_t is not 32bit!");
CC_PAL_COMPILER_ASSERT(sizeof(DrvAesCoreEngine_t)==sizeof(uint32_t), "DrvAesCoreEngine_t is not 32bit!");

/******************************************************************************
 *               PRIVATE FUNCTIONS
 ******************************************************************************/

int LoadCipherState(CCSramAddr_t ctxAddr, uint8_t is_zero_iv, struct drv_ctx_cipher *pCipherContext)
{
    const CCSramAddr_t blockStateAddr = GET_CTX_FIELD_ADDR(ctxAddr,
                                                           struct drv_ctx_cipher,
                                                           block_state);
    HwDesc_s desc;
    uint32_t blockSize;

    HW_DESC_INIT(&desc);

    switch (pCipherContext->mode) {
        case DRV_CIPHER_ECB:
            return CC_RET_OK;
        case DRV_CIPHER_CTR:
        case DRV_CIPHER_XTS:
        case DRV_CIPHER_OFB:
            HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_STATE1);
            break;
        default:
            HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_STATE0);
    }

    HW_DESC_SET_CIPHER_MODE(&desc, pCipherContext->mode);

    switch (pCipherContext->alg) {
        case DRV_CRYPTO_ALG_AES:
            blockSize = CC_AES_BLOCK_SIZE;
            if (pCipherContext->isTunnelOp == 0) {
                HW_DESC_SET_CIPHER_CONFIG0(&desc, pCipherContext->direction);
            } else {
                HW_DESC_SET_CIPHER_CONFIG0(&desc, pCipherContext->tunnetDir);
            }
            HW_DESC_SET_KEY_SIZE_AES(&desc, pCipherContext->key_size);
            HW_DESC_SET_CIPHER_CONFIG1(&desc, pCipherContext->isTunnelOp);
            if (pCipherContext->engineCore == DRV_AES_ENGINE2) {
                HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_AES2);
            } else {
                HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_AES);
            }
            break;
        case DRV_CRYPTO_ALG_SM4:
            blockSize = CC_AES_BLOCK_SIZE;
            HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_SM4);
            HW_DESC_SET_CIPHER_CONFIG0(&desc, pCipherContext->direction);
            HW_DESC_SET_KEY_SIZE_AES(&desc, pCipherContext->key_size);
            break;
        case DRV_CRYPTO_ALG_DES:
            blockSize = CC_DRV_DES_IV_SIZE;
            HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_DES);
            HW_DESC_SET_CIPHER_CONFIG0(&desc, pCipherContext->direction);
            HW_DESC_SET_KEY_SIZE_DES(&desc, pCipherContext->key_size);
            break;
        default:
            return CC_RET_UNSUPP_ALG;
    }

    /*if is_zero_iv use ZeroBlock as IV*/
    if (is_zero_iv == 1) {
        HW_DESC_SET_DIN_CONST(&desc, 0, blockSize);
    } else {
        HW_DESC_SET_STATE_DIN_PARAM(&desc, blockStateAddr, blockSize);
    }
    AddHWDescSequence(&desc);

    return CC_RET_OK;
}

int StoreCipherState(CCSramAddr_t ctxAddr, struct drv_ctx_cipher *pCipherContext)
{
    const CCSramAddr_t blockStateAddr = GET_CTX_FIELD_ADDR(ctxAddr,
                                                           struct drv_ctx_cipher,
                                                           block_state);
    HwDesc_s desc;
    uint32_t block_size;

    if (pCipherContext->mode == DRV_CIPHER_ECB) {
        return CC_RET_OK;
    }

    HW_DESC_INIT(&desc);
    HW_DESC_SET_CIPHER_MODE(&desc, pCipherContext->mode);
    switch (pCipherContext->mode) {
        case DRV_CIPHER_CTR:
        case DRV_CIPHER_OFB:
        case DRV_CIPHER_XTS:
            HW_DESC_SET_SETUP_MODE(&desc, SETUP_WRITE_STATE1);
            break;
        default:
            HW_DESC_SET_SETUP_MODE(&desc, SETUP_WRITE_STATE0);
    }

    switch (pCipherContext->alg) {
        case DRV_CRYPTO_ALG_AES:
            block_size = CC_AES_BLOCK_SIZE;
            if (pCipherContext->isTunnelOp == 0) {
                HW_DESC_SET_CIPHER_CONFIG0(&desc, pCipherContext->direction);
            } else {
                HW_DESC_SET_CIPHER_CONFIG0(&desc, pCipherContext->tunnetDir);
            }
            HW_DESC_SET_CIPHER_CONFIG1(&desc, pCipherContext->isTunnelOp);

            if (pCipherContext->engineCore == DRV_AES_ENGINE2) {
                HW_DESC_SET_FLOW_MODE(&desc, S_AES2_to_DOUT);
            } else {
                HW_DESC_SET_FLOW_MODE(&desc, S_AES_to_DOUT);
            }
            break;
        case DRV_CRYPTO_ALG_SM4:
            block_size = CC_AES_BLOCK_SIZE;
            HW_DESC_SET_CIPHER_CONFIG0(&desc, pCipherContext->direction);
            HW_DESC_SET_FLOW_MODE(&desc, S_SM4_to_DOUT);
            break;
        case DRV_CRYPTO_ALG_DES:
            block_size = CC_DRV_DES_IV_SIZE;
            HW_DESC_SET_CIPHER_CONFIG0(&desc, pCipherContext->direction);
            HW_DESC_SET_FLOW_MODE(&desc, S_DES_to_DOUT);
            break;
        default:
            return CC_RET_UNSUPP_ALG;
    }

    HW_DESC_SET_STATE_DOUT_PARAM(&desc, blockStateAddr, block_size);
    AddHWDescSequence(&desc);

    return CC_RET_OK;
}

int LoadCipherKey(CCSramAddr_t ctxAddr, struct drv_ctx_cipher *pCipherContext)
{
    HwDesc_s desc;
    const CCSramAddr_t keyAddr = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_cipher, key);
    const CCSramAddr_t xexKeyAddr = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_cipher, xex_key);
    const CCSramAddr_t xcbcKeyK1 = keyAddr + CC_AES_128_BIT_KEY_SIZE;
    const CCSramAddr_t xcbcKeyK2 = xcbcKeyK1 + CC_AES_128_BIT_KEY_SIZE;
    const CCSramAddr_t xcbcKeyK3 = xcbcKeyK2 + CC_AES_128_BIT_KEY_SIZE;
    const enum drv_crypto_direction encDecFlag = pCipherContext->direction;
    const enum drv_crypto_key_type aesKeyType = pCipherContext->crypto_key_type;

    HW_DESC_INIT(&desc);

    /* key size 24 bytes count as 32 bytes, make sure to zero wise upper 8 bytes */
    if (pCipherContext->key_size == 24) {
        ClearCtxField(keyAddr + 24, CC_AES_KEY_SIZE_MAX - 24);
    }

    HW_DESC_SET_CIPHER_MODE(&desc, pCipherContext->mode);

    switch (pCipherContext->alg) {
        case DRV_CRYPTO_ALG_AES:
            if (pCipherContext->isTunnelOp == 0) {
                HW_DESC_SET_CIPHER_CONFIG0(&desc, encDecFlag);
            } else {
                HW_DESC_SET_CIPHER_CONFIG0(&desc, pCipherContext->tunnetDir);
            }
            HW_DESC_SET_CIPHER_CONFIG1(&desc, pCipherContext->isTunnelOp);
            HW_DESC_SET_HW_CRYPTO_KEY(&desc, aesKeyType);
            HW_DESC_SET_KEY_SIZE_AES(&desc, pCipherContext->key_size);
            switch (pCipherContext->mode) {
                case DRV_CIPHER_XCBC_MAC:
                    HW_DESC_SET_STATE_DIN_PARAM(&desc, xcbcKeyK1, CC_AES_128_BIT_KEY_SIZE);
                    HW_DESC_SET_KEY_SIZE_AES(&desc, CC_AES_128_BIT_KEY_SIZE);
                    break;
                default:
                    if (aesKeyType == DRV_USER_KEY) {
                        HW_DESC_SET_STATE_DIN_PARAM(&desc, keyAddr, pCipherContext->key_size);
                    }
            }
            if (pCipherContext->engineCore == DRV_AES_ENGINE2) {
                HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_AES2);
            } else {
                HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_AES);
            }
            break;

        case DRV_CRYPTO_ALG_SM4:
            HW_DESC_SET_STATE_DIN_PARAM(&desc, keyAddr, pCipherContext->key_size);
            HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_SM4);
            HW_DESC_SET_KEY_SIZE_AES(&desc, pCipherContext->key_size);
            HW_DESC_SET_CIPHER_CONFIG0(&desc, encDecFlag);
            break;
        case DRV_CRYPTO_ALG_DES:
            HW_DESC_SET_STATE_DIN_PARAM(&desc, keyAddr, pCipherContext->key_size);
            HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_DES);
            HW_DESC_SET_KEY_SIZE_DES(&desc, pCipherContext->key_size);
            HW_DESC_SET_CIPHER_CONFIG0(&desc, encDecFlag);
            break;
        default:
            return CC_RET_UNSUPP_ALG;
    }

    HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_KEY0);
    AddHWDescSequence(&desc);

    if (pCipherContext->mode == DRV_CIPHER_XTS) {
        HW_DESC_INIT(&desc);

        /* load XEX key */
        HW_DESC_SET_CIPHER_MODE(&desc, pCipherContext->mode);
        if (pCipherContext->isTunnelOp == 0) {
            HW_DESC_SET_CIPHER_CONFIG0(&desc, encDecFlag);
        } else {
            HW_DESC_SET_CIPHER_CONFIG0(&desc, pCipherContext->tunnetDir);
        }
        HW_DESC_SET_STATE_DIN_PARAM(&desc, xexKeyAddr, pCipherContext->key_size);
        HW_DESC_SET_XEX_DATA_UNIT_SIZE(&desc, pCipherContext->data_unit_size);
        HW_DESC_SET_CIPHER_CONFIG1(&desc, pCipherContext->isTunnelOp);
        if (pCipherContext->engineCore == DRV_AES_ENGINE2) {
            HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_AES2);
        } else {
            HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_AES);
        }
        HW_DESC_SET_KEY_SIZE_AES(&desc, pCipherContext->key_size);
        HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_XEX_KEY);
        AddHWDescSequence(&desc);
    }

    if (pCipherContext->mode == DRV_CIPHER_XCBC_MAC) {
        /* load K2 key */
        /* NO init - reuse previous descriptor settings */
        HW_DESC_SET_STATE_DIN_PARAM(&desc, xcbcKeyK2, CC_AES_128_BIT_KEY_SIZE);
        HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_STATE1);
        AddHWDescSequence(&desc);

        /* load K3 key */
        /* NO init - reuse previous descriptor settings */
        HW_DESC_SET_STATE_DIN_PARAM(&desc, xcbcKeyK3, CC_AES_128_BIT_KEY_SIZE);
        HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_STATE2);
        AddHWDescSequence(&desc);
    }

    return CC_RET_OK;
}

/*!
 * Revert operation of the last MAC block processing
 * This function is used for AES-XCBC-MAC and AES-CMAC when finalize
 * has not data. It reverts the last block operation in order to allow
 * redoing it as final.
 *
 * \param qid
 * \param ctxAddr
 * \param pCipherContext
 *
 * \return int One of DX_SYM_* error codes defined in cc_sym_error.h.
 */
static int RevertLastMacBlock(CCSramAddr_t ctxAddr, struct drv_ctx_cipher *pCipherContext)
{
    HwDesc_s desc;
    const CCSramAddr_t keyAddr = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_cipher, key);
    const CCSramAddr_t blockStateAddr = GET_CTX_FIELD_ADDR(ctxAddr,
                                                           struct drv_ctx_cipher,
                                                           block_state);
    const CCSramAddr_t xcbcKeyK1 = keyAddr + CC_AES_128_BIT_KEY_SIZE;
    const enum drv_crypto_key_type aesKeyType = pCipherContext->crypto_key_type;

    /* Relevant only for AES-CMAC and AES-XCBC-MAC */
    if ((pCipherContext->mode != DRV_CIPHER_XCBC_MAC)
                    && (pCipherContext->mode != DRV_CIPHER_CMAC)) {
        CC_PAL_LOG_ERR("Wrong mode for this function (mode %d)\n", pCipherContext->mode);
        return CC_RET_UNSUPP_ALG_MODE;
    }
    if (aesKeyType == DRV_ROOT_KEY) {
        CC_PAL_LOG_ERR("RKEK not allowed for XCBC-MAC/CMAC\n");
        return CC_RET_UNSUPP_ALG_MODE;
    }
    /* CMAC and XCBC must use 128b keys */
    if ((pCipherContext->mode == DRV_CIPHER_XCBC_MAC)
                    && (pCipherContext->key_size != CC_AES_128_BIT_KEY_SIZE)) {
        CC_PAL_LOG_ERR("Bad key for XCBC-MAC %x\n", (unsigned int)pCipherContext->key_size);
        return CC_RET_INVARG_KEY_SIZE;
    }

    /* Load key for ECB decryption */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_CIPHER_MODE(&desc, DRV_CIPHER_ECB);
    HW_DESC_SET_CIPHER_CONFIG0(&desc, DRV_CRYPTO_DIRECTION_DECRYPT);
    HW_DESC_SET_HW_CRYPTO_KEY(&desc, aesKeyType);

    if (pCipherContext->mode == DRV_CIPHER_XCBC_MAC) { /* XCBC K1 key is used (always 128b) */
        HW_DESC_SET_STATE_DIN_PARAM(&desc, xcbcKeyK1, CC_AES_128_BIT_KEY_SIZE);
        HW_DESC_SET_KEY_SIZE_AES(&desc, CC_AES_128_BIT_KEY_SIZE);
    } else {/* CMAC */
        HW_DESC_SET_KEY_SIZE_AES(&desc, pCipherContext->key_size);
        if (aesKeyType == DRV_USER_KEY) {
            HW_DESC_SET_STATE_DIN_PARAM(&desc, keyAddr, pCipherContext->key_size);
        }
    }
    HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_AES);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_KEY0);
    AddHWDescSequence(&desc);

    /* Initiate decryption of block state to previous block_state-XOR-M[n] */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_STATE_DIN_PARAM(&desc, blockStateAddr, CC_AES_BLOCK_SIZE);
    HW_DESC_SET_STATE_DOUT_PARAM(&desc, blockStateAddr, CC_AES_BLOCK_SIZE);
    HW_DESC_SET_FLOW_MODE(&desc, DIN_AES_DOUT);
    AddHWDescSequence(&desc);

    return CC_RET_OK;
}

static void CalcXcbcKeys(CCSramAddr_t ctxAddr, struct drv_ctx_cipher *pCipherContext)
{
    int i;
    HwDesc_s setup_desc, data_desc;

    const enum drv_crypto_key_type aesKeyType = pCipherContext->crypto_key_type;

    /* Overload key+xex_key fields with Xcbc keys */
    const CCSramAddr_t keyAddr = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_cipher, key);
    CCSramAddr_t derivedKey = keyAddr + CC_AES_128_BIT_KEY_SIZE;
    uint32_t constKey = 0x01010101;

    /* Prepare key setup descriptor (same for all XCBC-MAC keys) */
    HW_DESC_INIT(&setup_desc);
    HW_DESC_SET_CIPHER_MODE(&setup_desc, DRV_CIPHER_ECB);
    HW_DESC_SET_CIPHER_CONFIG0(&setup_desc, DRV_CRYPTO_DIRECTION_ENCRYPT);
    HW_DESC_SET_KEY_SIZE_AES(&setup_desc, CC_AES_128_BIT_KEY_SIZE);
    HW_DESC_SET_FLOW_MODE(&setup_desc, S_DIN_to_AES);
    HW_DESC_SET_SETUP_MODE(&setup_desc, SETUP_LOAD_KEY0);

    /* subkeys are derived according to keytype (user, hw) */
    HW_DESC_SET_HW_CRYPTO_KEY(&setup_desc, aesKeyType);
    if (aesKeyType == DRV_USER_KEY) {
        HW_DESC_SET_STATE_DIN_PARAM(&setup_desc, keyAddr, CC_AES_128_BIT_KEY_SIZE);
    }

    /* load user key */
    AddHWDescSequence(&setup_desc);

    HW_DESC_INIT(&data_desc);
    HW_DESC_SET_FLOW_MODE(&data_desc, DIN_AES_DOUT);

    for (i = 0; i < AES_XCBC_MAC_NUM_KEYS; i++) {
        /* encrypt each XCBC constant with the user given key to get K1, K2, K3 */
        HW_DESC_SET_DIN_CONST(&data_desc, (constKey * (i + 1)), CC_AES_128_BIT_KEY_SIZE);
        HW_DESC_SET_STATE_DOUT_PARAM(&data_desc, derivedKey, CC_AES_128_BIT_KEY_SIZE);
        AddHWDescSequence(&data_desc);
        /* Procede to next derived key calculation */
        derivedKey += CC_AES_128_BIT_KEY_SIZE;
    }

    /* All subkeys are loaded as user keys */
    pCipherContext->crypto_key_type = DRV_USER_KEY;
}

#ifdef CC_SUPPORT_FULL_PROJECT
static int ValidateCipherKey(struct drv_ctx_cipher *pCipherContext)
{
    uint32_t error, regVal = 0;

    switch (pCipherContext->crypto_key_type) {
        case DRV_ROOT_KEY:
            /* Check KDR error bit in LCS register */
            CC_UTIL_IS_OTP_KEY_ERROR(error, HUK);
            if (error != 0) {
                return CC_RET_KDR_INVALID_ERROR;
            }
            break;
        case DRV_SESSION_KEY:
            /* Check session key validity */
            CC_UTIL_IS_SESSION_KEY_VALID(error);
            if (error == CC_UTIL_SESSION_KEY_IS_UNSET) {
                return CC_RET_SESSION_KEY_ERROR;
            }
            break;
        case DRV_KCP_KEY:
            CC_UTIL_IS_OTP_KEY_LOCKED(regVal, KCP);
            if (regVal != 0) {
                return CC_RET_KCP_INVALID_ERROR;
            }

            CC_UTIL_IS_OTP_KEY_ERROR(regVal, PROV);
            if (regVal != 0) {
                return CC_RET_KCP_INVALID_ERROR;
            }

            CC_UTIL_IS_OTP_KEY_NOT_IN_USE(regVal, OTP_OEM_FLAG, KCP);
            if (regVal != 0) {
                return CC_RET_KCP_INVALID_ERROR;
            }
            break;
        case DRV_KPICV_KEY:
            CC_UTIL_IS_OTP_KEY_LOCKED(regVal, KPICV);
            if (regVal != 0) {
                return CC_RET_KPICV_INVALID_ERROR;
            }

            CC_UTIL_IS_OTP_KEY_ERROR(regVal, KPICV);
            if (regVal != 0) {
                return CC_RET_KPICV_INVALID_ERROR;
            }

            CC_UTIL_IS_OTP_KEY_NOT_IN_USE(regVal, OTP_FIRST_MANUFACTURE_FLAG, KPICV);
            if (regVal != 0) {
                return CC_RET_KPICV_INVALID_ERROR;
            }
            break;
        case DRV_USER_KEY:
        case DRV_CUSTOMER_KEY:
            break;
        default:
            return CC_RET_INVALID_KEY_TYPE;
    }

    return CC_RET_OK;
}
#endif

/******************************************************************************
 *                FUNCTIONS
 ******************************************************************************/

/*!
 * This function is used to initialize the AES machine to perform the AES
 * operations. This should be the first function called.
 *
 * \param ctxAddr A pointer to the context buffer in SRAM.
 * \param pCtx A pointer to the AES context buffer in Host memory.
 *
 * \return int One of DX_SYM_* error codes defined in cc_sym_error.h.
 */
int InitCipher(CCSramAddr_t ctxAddr, uint32_t *pCtx)
{

    const CCSramAddr_t keyAddr = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_cipher, key);
    const CCSramAddr_t blockStateAddr = GET_CTX_FIELD_ADDR(ctxAddr,
                                                           struct drv_ctx_cipher,
                                                           block_state);
    struct drv_ctx_cipher *pCipherContext = (struct drv_ctx_cipher *) pCtx;

#ifdef CC_SUPPORT_FULL_PROJECT
    int rc;
    /* Need to validate HW keys only in full and not in slim configuration (as there are no HW keys loaded from the OTP)*/
    rc = ValidateCipherKey(pCipherContext);
    if (rc != CC_RET_OK) {
        return rc;
    }
#endif

    if (pCipherContext->alg == DRV_CRYPTO_ALG_DES) {
        /*in caes of double DES k1 = K3, copy k1-> K3*/
        if (pCipherContext->key_size == CC_DRV_DES_DOUBLE_KEY_SIZE) {
            /*temporary buffer to allow key coping, must be aligned to words*/
            uint32_t tKeybuff[CC_DRV_DES_ONE_KEY_SIZE / sizeof(uint32_t)];
            ReadContextField(keyAddr, tKeybuff, CC_DRV_DES_ONE_KEY_SIZE);
            WriteContextField((keyAddr + CC_DRV_DES_DOUBLE_KEY_SIZE),
                              tKeybuff,
                              CC_DRV_DES_ONE_KEY_SIZE);
            pCipherContext->key_size = CC_DRV_DES_TRIPLE_KEY_SIZE;

        }
        return CC_RET_OK;
    }

    switch (pCipherContext->mode) {
        case DRV_CIPHER_CMAC:
            ClearCtxField(blockStateAddr, CC_AES_BLOCK_SIZE);
            if (pCipherContext->crypto_key_type == DRV_ROOT_KEY) {
                    pCipherContext->key_size = CC_AES_256_BIT_KEY_SIZE;
            }
            break;
        case DRV_CIPHER_XCBC_MAC:
            if (pCipherContext->key_size != CC_AES_128_BIT_KEY_SIZE) {
                CC_PAL_LOG_ERR("Invalid key size\n");
                return CC_RET_INVARG;
            }
            ClearCtxField(blockStateAddr, CC_AES_BLOCK_SIZE);
            CalcXcbcKeys(ctxAddr, pCipherContext);
            break;
        default:
            break;
    }

    /* init private context */
    pCipherContext->engineCore = DRV_AES_ENGINE1;
    pCipherContext->isTunnelOp = TUNNEL_OFF;
    pCipherContext->dataBlockType = FIRST_BLOCK;

    return CC_RET_OK;
}

/*!
 * This function is used to process block(s) of data using the AES machine.
 *
 * \param ctxAddr A pointer to the AES context buffer in SRAM.
 * \param pCtx A pointer to the AES context buffer in Host memory.
 * \param pDmaInputBuffer A structure which represents the DMA input buffer.
 * \param pDmaOutputBuffer A structure which represents the DMA output buffer.
 *
 * \return int One of DX_SYM_* error codes defined in cc_sym_error.h.
 */
int ProcessCipher(CCSramAddr_t ctxAddr,
                  uint32_t *pCtx,
                  DmaBuffer_s *pDmaInputBuffer,
                  DmaBuffer_s *pDmaOutputBuffer)
{
    CCDmaAddr_t pInputData = 0, pOutputData = 0;
    uint32_t DataInSize = 0, DataOutSize = 0;
    uint32_t isNotLastDescriptor = 0;
    uint32_t flowMode;
    HwDesc_s desc;
    DmaMode_t dmaInMode = NO_DMA;
    DmaMode_t dmaOutMode = NO_DMA;
    uint8_t inAxiNs = pDmaInputBuffer->axiNs;
    uint8_t outAxiNs = pDmaOutputBuffer->axiNs;
    int drvRc = CC_RET_OK;
    struct drv_ctx_cipher *pCipherContext = (struct drv_ctx_cipher *) pCtx;

    const int isInplaceOp = (((pDmaInputBuffer->pData == pDmaOutputBuffer->pData)
                    && (pDmaInputBuffer->dmaBufType == pDmaOutputBuffer->dmaBufType))
                    || (pCipherContext->mode == DRV_CIPHER_CBC_MAC)
                    || (pCipherContext->mode == DRV_CIPHER_XCBC_MAC)
                    || (pCipherContext->mode == DRV_CIPHER_CMAC));

    if (pCipherContext->mode == DRV_CIPHER_CBC_CTS && pCipherContext->dataBlockType != LAST_BLOCK) {
        pCipherContext->mode = DRV_CIPHER_CBC;

        drvRc = LoadCipherKey(ctxAddr, pCipherContext);
        if (drvRc != CC_RET_OK) {
            goto EndWithErr;
        }
        drvRc = LoadCipherState(ctxAddr, 0, pCipherContext);
        if (drvRc != CC_RET_OK) {
            goto EndWithErr;
        }

        pCipherContext->mode = DRV_CIPHER_CBC_CTS;
    } else {

        drvRc = LoadCipherKey(ctxAddr, pCipherContext);
        if (drvRc != CC_RET_OK) {
            goto EndWithErr;
        }
        drvRc = LoadCipherState(ctxAddr, 0, pCipherContext);
        if (drvRc != CC_RET_OK) {
            goto EndWithErr;
        }

    }

    /* set the input/output pointers according to the DMA mode */
    dmaInMode = DMA_BUF_TYPE_TO_MODE(pDmaInputBuffer->dmaBufType);
    dmaOutMode = DMA_BUF_TYPE_TO_MODE(pDmaOutputBuffer->dmaBufType);

    if ((!isInplaceOp)
                    && (((dmaInMode == NO_DMA) && (dmaOutMode != NO_DMA))
                                    || ((dmaOutMode == NO_DMA) && (dmaInMode != NO_DMA)))) {
        CC_PAL_LOG_ERR("Inconsistent DMA mode for in/out buffers");
        drvRc = CC_RET_INVARG;
        goto EndWithErr;
    }

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
        case NO_DMA:
            pInputData = 0;
            /* data size is meaningless in DMA-MLLI mode */
            DataInSize = 0;
            break;
        default:
            CC_PAL_LOG_ERR("Invalid DMA Input mode\n");
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
            case NO_DMA:
                pOutputData = 0;
                /* data size is meaningless in DMA-MLLI mode */
                DataOutSize = 0;
                break;
            default:
                CC_PAL_LOG_ERR("Invalid DMA Output mode\n");
                drvRc = CC_RET_INVARG;
                goto EndWithErr;
        }
    }

    if ((pCipherContext->mode == DRV_CIPHER_CMAC)
                    || (pCipherContext->mode == DRV_CIPHER_XCBC_MAC)) {
        isNotLastDescriptor = 1;
    }

    /* process the AES flow */
    HW_DESC_INIT(&desc);

    if (pCipherContext->isSm4Ofb == true) {
        // for SM4 OFB - use CBC with const zero DIN
        HW_DESC_SET_DIN_CONST(&desc, 0, DataInSize);
    } else {
        HW_DESC_SET_DIN_TYPE(&desc, dmaInMode, pInputData, DataInSize, inAxiNs);
    }

    if (isNotLastDescriptor) {
        HW_DESC_SET_DIN_NOT_LAST_INDICATION(&desc);
    }

    switch (pCipherContext->mode) {
        case DRV_CIPHER_CBC_MAC:
        case DRV_CIPHER_CMAC:
        case DRV_CIPHER_XCBC_MAC:
            break;
        default:
            HW_DESC_SET_DOUT_TYPE(&desc, dmaOutMode, pOutputData, DataOutSize, outAxiNs);
    }

    switch (pCipherContext->alg) {
        case DRV_CRYPTO_ALG_AES:
            flowMode = DIN_AES_DOUT;
            break;
        case DRV_CRYPTO_ALG_SM4:
            flowMode = DIN_SM4_DOUT;
            break;
        case DRV_CRYPTO_ALG_DES:
            flowMode = DIN_DES_DOUT;
            break;
        default:
            CC_PAL_LOG_ERR("Invalid alg type\n");
            drvRc = CC_RET_UNSUPP_ALG;
            goto EndWithErr;
    }

    HW_DESC_SET_FLOW_MODE(&desc, flowMode);

    AddHWDescSequence(&desc);

    /* at least one block of data processed */
    pCipherContext->dataBlockType = MIDDLE_BLOCK;

    /* get machine state */
    drvRc = StoreCipherState(ctxAddr, pCipherContext);

EndWithErr:

    return drvRc;
}

/*!
 * This function is used as finish operation of AES on XCBC, CMAC, CBC
 * and other modes besides XTS mode.
 * The function may either be called after "InitCipher" or "ProcessCipher".
 *
 * \param ctxAddr A pointer to the AES context buffer in SRAM.
 * \param pCtx A pointer to the AES context buffer in Host memory.
 * \param pDmaInputBuffer A structure which represents the DMA input buffer.
 * \param pDmaOutputBuffer A structure which represents the DMA output buffer.
 *
 * \return int One of DX_SYM_* error codes defined in cc_sym_error.h.
 */
int FinalizeCipher(CCSramAddr_t ctxAddr,
                   uint32_t *pCtx,
                   DmaBuffer_s *pDmaInputBuffer,
                   DmaBuffer_s *pDmaOutputBuffer)
{
    uint32_t isRemainingData = 0;
    uint32_t DataInSize = 0;
    CCDmaAddr_t pInputData = 0;
    HwDesc_s desc;
    DmaMode_t dmaMode = NO_DMA;
    uint8_t inAxiNs = pDmaInputBuffer->axiNs;
    int drvRc = CC_RET_OK;
    struct drv_ctx_cipher *pCipherContext = (struct drv_ctx_cipher *) pCtx;

    HW_DESC_INIT(&desc);

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

    switch (pCipherContext->mode) {
        case DRV_CIPHER_CMAC:
        case DRV_CIPHER_XCBC_MAC: {
            if (isRemainingData == 1) {
                if (dmaMode == DMA_MLLI) {
                    MLLI_loadTableToSRAM(pDmaInputBuffer->pData,
                                         pDmaInputBuffer->size,
                                         pDmaInputBuffer->axiNs,
                                         MLLI_INPUT_TABLE);
                    pInputData = MLLI_getFirstLLIPtr(MLLI_INPUT_TABLE);
                    /* data size should hold the number of LLIs */
                    DataInSize = (pDmaInputBuffer->size) / LLI_ENTRY_BYTE_SIZE;
                } else {
                    pInputData = pDmaInputBuffer->pData;
                    DataInSize = pDmaInputBuffer->size;
                }
            }

            /* Prepare processing descriptor to be pushed after loading state+key */
            HW_DESC_INIT(&desc);
            if (isRemainingData == 0) {
                if (pCipherContext->dataBlockType == FIRST_BLOCK) {
                    /* MAC for 0 bytes */
                    HW_DESC_SET_CIPHER_MODE(&desc, pCipherContext->mode);
                    HW_DESC_SET_KEY_SIZE_AES(&desc, pCipherContext->key_size);
                    HW_DESC_SET_CMAC_SIZE0_MODE(&desc);
                    HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_AES);
                } else {
                    /* final with 0 data but MAC total data size > 0 */
                    drvRc = RevertLastMacBlock(ctxAddr, pCipherContext); /* Get C[n-1]-xor-M[n] */
                    if (drvRc != CC_RET_OK) {
                        goto EndWithErr;
                    }
                    /* Finish with data==0 is identical to "final"
                     op. on the last (prev.) block (XOR with 0) */
                    HW_DESC_SET_DIN_CONST(&desc, 0, CC_AES_BLOCK_SIZE);
                    HW_DESC_SET_FLOW_MODE(&desc, DIN_AES_DOUT);
                }
            } else {
                HW_DESC_SET_DIN_TYPE(&desc, dmaMode, pInputData, DataInSize, inAxiNs);
                HW_DESC_SET_FLOW_MODE(&desc, DIN_AES_DOUT);
            }

            /* load AES key and iv length and digest */
            drvRc = LoadCipherKey(ctxAddr, pCipherContext);
            if (drvRc != CC_RET_OK) {
                goto EndWithErr;
            }

            drvRc = LoadCipherState(ctxAddr, 0, pCipherContext);
            if (drvRc != CC_RET_OK) {
                goto EndWithErr;
            }

            /* Process last block */
            AddHWDescSequence(&desc);

            /* get machine state */
            drvRc = StoreCipherState(ctxAddr, pCipherContext);
            if (drvRc != CC_RET_OK) {
                goto EndWithErr;
            }

            break;
        }
        case DRV_CIPHER_CBC_CTS: {
            /*In case of data size = CC_AES_BLOCK_SIZE check that no blocks were processed before*/
            if ((pDmaInputBuffer->size == CC_AES_BLOCK_SIZE)
                            && (pCipherContext->dataBlockType == MIDDLE_BLOCK)) {
                CC_PAL_LOG_ERR("Invalid dataIn size\n");
                drvRc = CC_RET_INVARG;
                goto EndWithErr;
            }
            /*Call ProcessCTSFinalizeCipher to process AES CTS finalize operation */
            pCipherContext->dataBlockType = LAST_BLOCK;
        } /* Falls through. */
        default:
            if (isRemainingData) {
                /* process all tables and get state from the AES machine */
                drvRc = ProcessCipher(ctxAddr,
                                      (uint32_t *) pCipherContext,
                                      pDmaInputBuffer,
                                      pDmaOutputBuffer);
                if (drvRc != CC_RET_OK) {
                    goto EndWithErr;
                }
            } else if (pCipherContext->mode == DRV_CIPHER_CBC_MAC) {
                /* in-case ZERO data has processed the output would be the encrypted IV */
                if (pCipherContext->dataBlockType == FIRST_BLOCK) {
                    /* load AES key and iv length and digest */
                    drvRc = LoadCipherKey(ctxAddr, pCipherContext);
                    if (drvRc != CC_RET_OK) {
                        goto EndWithErr;
                    }

                    drvRc = LoadCipherState(ctxAddr, 0, pCipherContext);
                    if (drvRc != CC_RET_OK) {
                        goto EndWithErr;
                    }

                    HW_DESC_INIT(&desc);
                    HW_DESC_SET_DIN_CONST(&desc, 0, CC_AES_BLOCK_SIZE);
                    HW_DESC_SET_FLOW_MODE(&desc, DIN_AES_DOUT);
                    AddHWDescSequence(&desc);

                    /* get mac result */
                    drvRc = StoreCipherState(ctxAddr, pCipherContext);
                }
            }
    }

EndWithErr:

    return drvRc;
}

