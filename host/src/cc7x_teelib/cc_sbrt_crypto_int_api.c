/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


/************* Include Files ****************/
#include "cc_sbrt_crypto_int_api.h"
#include "cc_sbrt_crypto_driver.h"
#include "cc_sbrt_crypto_int_defs.h"
#include "cc_pal_mutex.h"
#include "cc_pal_log.h"
#include "dma_buffer.h"
#include "sym_adaptor_util.h"
#include "mlli.h"
#include "completion.h"
#include "cc_hw_queue_defs.h"
#include "cc_hal.h"
#include "cc_hash.h"
#include "cc_sec_defs.h"
#include "cc_otp_defs.h"
#include "cc_hash_defs.h"
#include "bsv_hw_defs.h"
#include "bsv_crypto_defs.h"
#include "bsv_error.h"
#include "bsv_rsa_driver.h"

#ifdef BIG__ENDIAN
#define SBRT_SHA256_VAL 0x19CDE05B, 0xABD9831F, 0x8C68059B, 0x7F520E51, 0x3AF54FA5, 0x72F36E3C, 0x85AE67BB, 0x67E6096A
#else
#define SBRT_SHA256_VAL 0x5BE0CD19, 0x1F83D9AB, 0x9B05688C, 0x510E527F, 0xA54FF53A, 0x3C6EF372, 0xBB67AE85, 0x6A09E667
#endif

extern CC_PalMutex CCSymCryptoMutex;
extern CC_PalMutex CCAsymCryptoMutex;

static CCError_t SbrtVerifyKeyValidity(unsigned long hwBaseAddress, CCBsvKeyType_t keyType)
{
    CCError_t error = CC_OK;
    uint32_t isKeyInUse = 0;
    uint32_t isTci = 0;
    uint32_t isPci = 0;

    /* Check key type */
    if (keyType != CC_BSV_CE_KEY && keyType != CC_BSV_ICV_CE_KEY) {
        return CC_SBRT_ILLIGAL_KEY_ERROR;
    }

    /* verify PCI or TCI is set prperly before using HW keys.
     * only one bit should be set among them.
     * in CM both can be 0 */
    CC_CHIP_INDICATION_GET(hwBaseAddress, isTci, isPci);
    if ((isTci & isPci) != 0) {
        return CC_SBRT_CHIP_INDICATION_ERROR;
    }

    /* check if fatal error bit is set to ON */
    CC_BSV_IS_FATAL_ERR_ON(hwBaseAddress, error);
    if (error == CC_TRUE ) {
        return CC_SBRT_FATAL_ERROR_ERROR;
    }

    /* in case Secure Disable signal is set, any usage of HW key shall result an error */
    CC_BSV_IS_SD_FLAG_SET(hwBaseAddress, error);
    if (error == CC_TRUE) {
        return CC_SBRT_SECURE_DISABLE_ERROR;
    }

    switch (keyType) {

        case CC_BSV_CE_KEY:
            /* validate OEM code encryption key */
            CC_BSV_IS_KEY_IN_USE(hwBaseAddress, OEM, KCE, isKeyInUse, error);
            if ( (error) || (isKeyInUse != CC_TRUE) ) {
                error = CC_SBRT_ILLIGAL_KCE_ERROR;
                break;
            }

            CC_BSV_IS_KEY_ERROR(hwBaseAddress, KCE, error);
            if (error) {
                error = CC_SBRT_ILLIGAL_KCE_ERROR;
                break;
            }

            CC_BSV_IS_KEY_LOCKED(hwBaseAddress, KCE, error);
            if (error) {
                error = CC_SBRT_ILLIGAL_KCE_ERROR;
                break;
            }
            break;

        case CC_BSV_ICV_CE_KEY:
            /* validate ICV code encryption key */
            CC_BSV_IS_KEY_IN_USE(hwBaseAddress, FIRST_MANUFACTURE, KCEICV, isKeyInUse, error);
            if ( (error) || (isKeyInUse != CC_TRUE) ) {
                error = CC_SBRT_ILLIGAL_KCEICV_ERROR;
                break;
            }

            CC_BSV_IS_KEY_ERROR(hwBaseAddress, KCEICV, error);
            if (error) {
                error = CC_SBRT_ILLIGAL_KCEICV_ERROR;
                break;
            }

            CC_BSV_IS_KEY_LOCKED(hwBaseAddress, KCEICV, error);
            if (error) {
                error = CC_SBRT_ILLIGAL_KCEICV_ERROR;
                break;
            }
            break;

       default:
            error = CC_SBRT_ILLIGAL_KEY_ERROR;
    }

    return error;
}

CCError_t SbrtCryptoImageInit(unsigned long hwBaseAddress,
                              CCSbrtFlow_t flow,
                              CCBsvKeyType_t keyType,
                              uint8_t *pNonce)
{
    CCError_t error = CC_OK;

    uint32_t pInitialHashIv[CC_SBRT_IV_SIZE_IN_BYTES  / CC_32BIT_WORD_SIZE] = { SBRT_SHA256_VAL };
    uint32_t pAlignedNonceBuff[CC_SBRT_NONCE_SIZE_IN_BYTES / CC_32BIT_WORD_SIZE];

    const CCSramAddr_t ivSramAddr = CC_SBRT_IV_SRAM_OFFSET;
    const CCSramAddr_t nonceSramAddr = CC_SBRT_NONCE_SRAM_OFFSET;

    uint32_t key = DRV_END_OF_KEYS;

    /* verify tunneling mode */
    if ((flow != CC_SBRT_FLOW_HASH_MODE) && (flow != CC_SBRT_FLOW_AES_AND_HASH_MODE)
                    && (flow != CC_SBRT_FLOW_AES_TO_HASH_MODE)) {
        return CC_SBRT_ILLIGAL_FLOW_ERROR;
    }

    /* If we are in HASH & AES mode, verify the keys before starting the flow. */
    if (flow != CC_SBRT_FLOW_HASH_MODE) {

        switch (keyType) {
            case CC_BSV_CE_KEY:
                key = DRV_KCE_KEY;
                break;
            case CC_BSV_ICV_CE_KEY:
                key = DRV_KCEICV_KEY;
                break;
            default:
                error = CC_SBRT_ILLIGAL_KEY_ERROR;
                CC_PAL_LOG_ERR("invalid key\n");
                goto bail;
        }

        error = SbrtVerifyKeyValidity(hwBaseAddress, keyType);
        if (error != CC_OK) {
            CC_PAL_LOG_ERR("SbrtVerifyKeyValidity fail\n");
            goto bail;
        }
    }

    /* initiate HW engines */
    WriteContextField(ivSramAddr, pInitialHashIv, CC_SBRT_IV_SIZE_IN_BYTES);

    error = SbrtHashDrvInit(ivSramAddr);
    if (error != CC_OK) {
        CC_PAL_LOG_ERR("CCSbrtHashInit fail\n");
        goto bail;
    }

    if (flow != CC_SBRT_FLOW_HASH_MODE) {

        /* copy nonce to word aligned buffer */
        CC_PalMemCopy(pAlignedNonceBuff, pNonce, CC_SBRT_NONCE_SIZE_IN_BYTES);
        WriteContextField(nonceSramAddr, pAlignedNonceBuff, CC_SBRT_NONCE_SIZE_IN_BYTES);

        error = SbrtAesDrvInit(key, nonceSramAddr);
        if (error != CC_OK) {
            CC_PAL_LOG_ERR("CCSbrtAesInit fail\n");
            goto bail;
        }
    }

    WaitForSequenceCompletion(CC_FALSE);

bail:

    return error;
}

CCError_t SbrtCryptoImageProcess(CCSbrtFlow_t flow,
                                 CCSbrtCompletionMode_t completionMode,
                                 DmaBuffer_s *pDataIn,
                                 DmaBuffer_s *pDataOut)
{
    CCError_t error = CC_OK;

    /* check data in pointer */
    if (pDataIn == NULL || pDataIn->size == 0 || pDataIn->pData == 0) {
        CC_PAL_LOG_ERR("pDataIn is NULL\n");
        error = CC_SBRT_INVALID_DATA_IN_POINTER_ERROR;
        goto bail;
    }

    /* check data put pointer */
    if ((flow == CC_SBRT_FLOW_AES_AND_HASH_MODE)
                    || (flow == CC_SBRT_FLOW_AES_TO_HASH_MODE)) {
        if (pDataOut == NULL || pDataOut->size == 0 || pDataOut->pData == 0) {
            CC_PAL_LOG_ERR("pDataOut is NULL or size 0\n");
            error = CC_SBRT_INVALID_DATA_OUT_POINTER_ERROR;
            goto bail;
        }
    }

    /* Waiting on start allows to sync to a point that all buffers were processed before
     * the trigerring the next block processing, allowing the next flash read to be done simultanously
     * using an already available buffer */
    if (completionMode == CC_SBRT_COMPLETION_WAIT_UPON_START) {
        WaitForSequenceCompletion(CC_FALSE);
    }

    /* activate data descriptors */
    switch (flow) {
        case CC_SBRT_FLOW_HASH_MODE:
            error = SbrtHashDrvProcess(pDataIn);
            break;
        case CC_SBRT_FLOW_AES_AND_HASH_MODE:
            error = SbrtAesDrvProcess(AES_and_HASH, pDataIn, pDataOut);
            break;
        case CC_SBRT_FLOW_AES_TO_HASH_MODE:
            error = SbrtAesDrvProcess(AES_to_HASH_and_DOUT, pDataIn, pDataOut);
            break;
        default:
            error = CC_SBRT_ILLIGAL_FLOW_ERROR;
            goto bail;
    }

    /* if proccess function returned an error, it means that the aes/hash engine were not activated
     * and there is no point in waiting for interrupt */
    if (error != CC_OK) {
        CC_PAL_LOG_ERR("process failed for %u flow\n", flow);
        goto bail;
    }

    /* Skip waiting for interrupt to allow reading from flash while the engine is processing data */
    if (completionMode == CC_SBRT_COMPLETION_WAIT_UPON_END) {
        WaitForSequenceCompletion(CC_FALSE);
    }

bail:

    return error;
}

CCError_t SbrtCryptoImageFinish(CCHashResult_t hashResult)
{
    CCError_t error = CC_OK;

    const CCSramAddr_t digestSramAddr = CC_SBRT_HASH_SRAM_OFFSET;

    CC_PalMemSetZero(hashResult, sizeof(CCHashResult_t));
    WriteContextField(digestSramAddr, hashResult, CC_SBRT_HASH_SIZE_IN_BYTES);

    error = SbrtHashDrvFinish(digestSramAddr);

    WaitForSequenceCompletion(CC_TRUE);

    if (error == CC_OK) {
        ReadContextField(digestSramAddr, hashResult, CC_SBRT_HASH_SIZE_IN_BYTES);
    }

    return error;
}

void SbrtCryptoImageUnlock(void)
{
    if (CC_PalMutexUnlock(&CCSymCryptoMutex) != CC_OK) {
        CC_PalAbort("CCSymCryptoMutex unlock failed\n");
    }
}

void SbrtCryptoImageLock(void)
{
    if (CC_PalMutexLock(&CCSymCryptoMutex, CC_INFINITE) != CC_OK) {
        CC_PalAbort("CCSymCryptoMutex lock failed\n");
    }
}


CCError_t SbrtSHA256(unsigned long hwBaseAddress,
                     uint8_t *pDataIn,
                     size_t dataSize,
                     CCHashResult_t hashBuff)
{
    CCError_t error = CC_OK;
    CCHashResultBuf_t tempHashBuff;

    CC_UNUSED_PARAM(hwBaseAddress);

    error = CC_Hash(CC_HASH_SHA256_mode, pDataIn, dataSize, tempHashBuff);

    if (error == CC_OK) {
        CC_PalMemCopy(hashBuff, tempHashBuff, sizeof(CCHashResult_t));
    }

    return error;
}

CCError_t SbrtRsaPssVerify(unsigned long hwBaseAddress,
                           uint32_t *NBuff,
                           uint32_t *NpBuff,
                           uint32_t *signature,
                           CCHashResult_t hashedData,
                           uint32_t *pWorkSpace,
                           size_t workspaceSize)
{
    CCError_t error = CC_OK;

    if (CC_PalMutexLock(&CCAsymCryptoMutex, CC_INFINITE) != CC_OK) {
        CC_PalAbort("CCAsymCryptoMutex lock failed\n");
    }

    error = BsvRsaPssVerify(hwBaseAddress,
                            NBuff,
                            NpBuff,
                            signature,
                            hashedData,
                            pWorkSpace,
                            workspaceSize);

    if (CC_PalMutexUnlock(&CCAsymCryptoMutex) != CC_OK) {
        CC_PalAbort("CCAsymCryptoMutex unlock failed\n");
    }

    return error;

}

