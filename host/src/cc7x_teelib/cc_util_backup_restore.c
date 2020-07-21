/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


#define CC_PAL_LOG_CUR_COMPONENT CC_LOG_MASK_UTILS

/************* Include Files ****************/
#include "cc_pal_log.h"
#include "cc_pal_types.h"
#include "cc_pal_mutex.h"
#include "cc_pal_abort.h"
#include "cc_pal_mem.h"
#include "cc_util_int_defs.h"
#include "cc_common.h"
#include "cc_util_key_derivation.h"
#include "cc_util_error.h"
#include "cc_fips_defs.h"
#include "cc_aesccm.h"
#include "cc_aes.h"
#include "cc_aes_defs.h"
#include "cc_util_cmac.h"

#define BURE_KEY_DERIVATION_LABEL    0x41,0x52,0x4D,0x20                                     // "ARM "
#define BURE_KEY_DERIVATION_CONTEXT  0x52,0x41,0x4D,0x20,0x42,0x41,0x43,0x4B,0x55,0x50       // "RAM backup"

#define UTIL_BACKUP_RESTORE_CCM_NONCE_SIZE  8
#define UTIL_BACKUP_RESTORE_CCM_TAG_SIZE    16

#define BLOCK_SIZE_LIMIT 0xFFFF
#define MAX_OF_UNSIGN_TYPE(t) (0x1ULL << ((sizeof(t) * 8ULL))) - 1ULL

extern CC_PalMutex CCSymCryptoMutex;


/*!
 * This function backup/restore on-chip secure RAM to/from external DRAM:
 * It encrypts/decrypts the provided block (using the always-on state counter to construct the AES-CCM nonce);
 * Also, computes AES-CCM signature, and appends/verifies the signature.
 *
 * @param[in] pSrcBuff      - input Host memory buffer.
 * @param[in] pDstBuff      - output Host memory buffer.
 * @param[in] blockSize     - number of bytes to process, not including ccm tag
 * @param[in] isSramBackup  - if TRUE, SRAM backup; else, SRAM restore
 *
 *
 * @return CCError_t        - On success: the value CC_OK is returned,
 *                            On failure: a value from cc_util_error.h
 *
 */


CCError_t CC_UtilBackupAndRestore(uint8_t *pSrcBuff,
                                  uint8_t *pDstBuff,
                                  size_t blockSize,
                                  CCBool_t isSramBackup)
{
    CCError_t rc;
    uint32_t stateCtr;
    uint8_t nonceBuff[UTIL_BACKUP_RESTORE_CCM_NONCE_SIZE] = {0x0};
    CCAesEncryptMode_t direction;
    uint8_t *pMacData;

    uint8_t drvKey[CC_UTIL_AES_CMAC_RESULT_SIZE_IN_BYTES];         // 128bit
    uint8_t dataIn[CC_UTIL_MAX_KDF_SIZE_IN_BYTES] = {0};
    uint8_t label[] = {BURE_KEY_DERIVATION_LABEL};
    uint8_t context[] = {BURE_KEY_DERIVATION_CONTEXT};
    uint32_t dataSize, i;

#ifdef CC_SUPPORT_FIPS
    CCFipsError_t fipsError;
#endif

    if (isSramBackup == CC_TRUE) { /* Only in case of backup need to verify FIPS state */
        CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();
    }

    /* Check input parameters: in case of partial/full overlapping - exit with error */
    if ((blockSize <= 0) ||
        (pSrcBuff == pDstBuff) ||
        ((pSrcBuff < pDstBuff) && (pSrcBuff + blockSize) > pDstBuff) ||
        ((CC_FALSE == isSramBackup) && ((pDstBuff < pSrcBuff) && (pDstBuff + blockSize) > pSrcBuff)) ||
        ((CC_TRUE == isSramBackup) && ((pDstBuff < pSrcBuff) && (pDstBuff + blockSize + UTIL_BACKUP_RESTORE_CCM_TAG_SIZE) > pSrcBuff)) ||
        (blockSize > BLOCK_SIZE_LIMIT)) {
            return CC_UTIL_ILLEGAL_PARAMS_ERROR;
        }

    /* Compute derived key for RAM backup/restore based on session key. */

    /* Generate dataIn buffer for CMAC: 0x01 || Label || 0x00 || context || length */
    i = 0;

    dataIn[i++] = 0x01;
    CC_PalMemCopy((uint8_t*)&dataIn[i], label, sizeof(label));
    i += sizeof(label);

    dataIn[i++] = 0x00;

    CC_PalMemCopy((uint8_t*)&dataIn[i], context, sizeof(context));
    i += sizeof(context);

    /* Note! length represents num of bits of derived key, and should match the size of drvKey buffer */
    dataIn[i] = CC_UTIL_AES_CMAC_RESULT_SIZE_IN_BYTES*8;

    dataSize = CC_UTIL_FIX_DATA_MIN_SIZE_IN_BYTES + sizeof(label) + sizeof(context);

    rc = UtilCmacDeriveKey(UTIL_SESSION_KEY, NULL, dataIn, dataSize, drvKey);
    if (rc != CC_OK) {
        return rc;
    }

    /* Protect HOST_CC_AO_STATE_COUNTER_INC access with mutex*/
    rc = CC_PalMutexLock(&CCSymCryptoMutex, CC_INFINITE);
    if (rc != CC_SUCCESS) {
        CC_PalAbort("Fail to acquire mutex\n");
    }

    /* Case of Backup: change parameters and incremnet state counter */
    if(isSramBackup == CC_TRUE) {
        /* Increment the AO state counter for backup operation only */
        CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_CC_AO_STATE_COUNTER_INC), 0x1);
        direction = CC_AES_ENCRYPT;
        pMacData = pDstBuff+blockSize;
        /* protect counter from overflow */
        stateCtr = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_AO_CC_STATE_COUNTER));
        if (stateCtr == MAX_OF_UNSIGN_TYPE(stateCtr)) {
            /* erase drvKey - BURE-UTIL-3.2 */
            CC_PalMemSetZero(drvKey, sizeof(drvKey));
            /* Release the mutex */
            if(CC_PalMutexUnlock(&CCSymCryptoMutex) != CC_SUCCESS) {
                    CC_PalAbort("Fail to release mutex\n");
            }
            return CC_UTIL_FATAL_ERROR;
        }
    } else {
        direction = CC_AES_DECRYPT;
        pMacData = pSrcBuff+blockSize;
    }

    /* Generates IV from state counter and src address */
    stateCtr = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_AO_CC_STATE_COUNTER));

    /* Release the mutex */
    if(CC_PalMutexUnlock(&CCSymCryptoMutex) != CC_SUCCESS) {
        CC_PalAbort("Fail to release mutex\n");
    }

    CC_PAL_LOG_DEBUG("stateCtr = %d \n", stateCtr);
    CC_CommonReverseMemcpy((uint8_t*)nonceBuff, (uint8_t*)&stateCtr, sizeof(stateCtr));
    nonceBuff[4] = 0x1;
    nonceBuff[5] = 0x2;
    nonceBuff[6] = 0x3;
    nonceBuff[7] = 0x4;

    /* encrypts/decrypts the block */
    rc = CC_AesCcm(direction,
            drvKey, CC_AES_Key128BitSize,
            nonceBuff, UTIL_BACKUP_RESTORE_CCM_NONCE_SIZE,
            NULL, 0,
            pSrcBuff, blockSize,
            pDstBuff,
            UTIL_BACKUP_RESTORE_CCM_TAG_SIZE,
            pMacData,
            CC_AES_MODE_CCM);

    /* if verification fails, clear output buffer, and return the error */
    if (rc != CC_OK){
        if (isSramBackup == CC_FALSE){
            CC_PalMemSetZero(pDstBuff, blockSize);
        }
        return rc;
    }

#ifdef CC_SUPPORT_FIPS
    /* get the status and send to REE */
    rc = CC_FipsErrorGet(&fipsError);
    if (rc != CC_OK) {
        return rc;
    }
    rc = FipsNotifyUponTeeStatus(fipsError);
    if (rc != CC_OK) {
        return rc;
    }
#endif

    return rc;
}
