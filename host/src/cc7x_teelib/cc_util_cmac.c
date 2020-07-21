/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

/************* Include Files ****************/
#include "cc_pal_types.h"
#include "cc_pal_mem.h"
#include "cc_util_int_defs.h"
#include "cc_util_defs.h"
#include "cc_pal_mutex.h"
#include "cc_pal_abort.h"
#include "sym_adaptor_driver.h"
#include "cc_util_error.h"
#include "cc_sym_error.h"
#include "cc_context_relocation.h"
#include "cc_common.h"
#include "cc_common_math.h"
#include "cc_rnd_common.h"
#include "cc_rnd_error.h"
#include "cc_hal.h"
#include "cc_util_cmac.h"
#include "cc_otp_defs.h"
#include "cc_aes_defs.h"

/*!
 * Converts Symmetric Adaptor return code to CC error code.
 *
 * \param symRetCode Symmetric Adaptor return error.
 * \param errorInfo Ignored.
 *
 * \return CCError_t one of CC_* error codes defined in cc_error.h
 */
static CCUtilError_t SymAdaptor2CmacDeriveKeyErr(int symRetCode)
{
    switch (symRetCode) {
        case CC_RET_INVARG:
            return CC_UTIL_ILLEGAL_PARAMS_ERROR;
        case CC_RET_INVARG_BAD_ADDR:
            return CC_UTIL_BAD_ADDR_ERROR;
        case CC_RET_KDR_INVALID_ERROR:
            return CC_UTIL_KDR_INVALID_ERROR;
        case CC_RET_SESSION_KEY_ERROR:
            return CC_UTIL_SESSION_KEY_ERROR;
        case CC_RET_KCP_INVALID_ERROR:
            return CC_UTIL_KCP_INVALID_ERROR;
        case CC_RET_KPICV_INVALID_ERROR:
            return CC_UTIL_KPICV_INVALID_ERROR;
        case CC_RET_INVALID_USER_KEY_SIZE:
            return CC_UTIL_INVALID_USER_KEY_SIZE;
        case CC_RET_INVALID_KEY_TYPE:
            return CC_UTIL_INVALID_KEY_TYPE;
        case CC_RET_INVARG_CTX:
        case CC_RET_UNSUPP_ALG:
        default:
            return CC_UTIL_FATAL_ERROR;
    }
}

/************************************************************************************/
/****************         CMAC key derivation    ************************************/
/************************************************************************************/

CCUtilError_t UtilCmacBuildDataForDerivation(const uint8_t *pLabel,
                                             size_t labelSize,
                                             const uint8_t *pContextData,
                                             size_t contextSize,
                                             uint8_t *pDataOut,
                                             size_t *pDataOutSize,
                                             size_t derivedKeySize)
{
    uint32_t length = 0;
    uint32_t lengthReverse = 0;
    uint32_t i = 0;

    /* Check Label, Context, DerivedKey sizes */
    if (derivedKeySize > CC_UTIL_MAX_DERIVED_KEY_SIZE_IN_BYTES) {
        return CC_UTIL_ILLEGAL_PARAMS_ERROR;
    }

    if (derivedKeySize % CC_AES_BLOCK_SIZE_IN_BYTES != 0) {
        return CC_UTIL_ILLEGAL_PARAMS_ERROR;
    }

    if (derivedKeySize == 0) {
        return CC_UTIL_ILLEGAL_PARAMS_ERROR;
    }

    if (derivedKeySize * CC_BITS_IN_BYTE > 0xFF) {
        length = CC_UTIL_FIX_DATA_MAX_SIZE_IN_BYTES;
    } else {
        length = CC_UTIL_FIX_DATA_MIN_SIZE_IN_BYTES;
    }

    if ((pLabel == NULL) ||
                    (labelSize == 0) ||
                    (labelSize > CC_UTIL_MAX_LABEL_LENGTH_IN_BYTES)) {
        return CC_UTIL_ILLEGAL_PARAMS_ERROR;
    }

    if ((pContextData == NULL) ||
                    (contextSize == 0) ||
                    (contextSize > CC_UTIL_MAX_CONTEXT_LENGTH_IN_BYTES)) {
        return CC_UTIL_ILLEGAL_PARAMS_ERROR;
    }

    if ((pDataOut == NULL) ||
                    (*pDataOutSize == 0) ||
                    (*pDataOutSize < (contextSize + labelSize + length))) {
        return CC_UTIL_ILLEGAL_PARAMS_ERROR;
    }

    i = 1;

    CC_PalMemCopy((pDataOut + i), pLabel, labelSize);
    i += labelSize;

    pDataOut[i++] = 0x00;

    CC_PalMemCopy((pDataOut + i), pContextData, contextSize);
    i += contextSize;

    length = derivedKeySize * CC_BITS_IN_BYTE;
    if (length > 0xFF) {
        /* Reverse words order and bytes in each word */
        lengthReverse = ((length & 0xFF00) >> 8) | ((length & 0xFF) << 8);
        CC_PalMemCopy((pDataOut + i), (uint8_t* )&lengthReverse, 2);
        i += 2;
    } else {
        CC_PalMemCopy((pDataOut + i), (uint8_t* )&length, 1);
        i += 1;
    }
    *pDataOutSize = i;

    return CC_OK;
}

CCUtilError_t UtilCmacDeriveKey(UtilKeyType_t keyType,
                                CCAesUserKeyData_t *pUserKey,
                                uint8_t *pDataIn,
                                size_t dataInSize,
                                CCUtilAesCmacResult_t pCmacResult)
{
    int symRc;
    uint32_t ctxBuff[CC_UTIL_BUFF_IN_WORDS];
    uint32_t isSet;

    struct drv_ctx_cipher *pAesContext = (struct drv_ctx_cipher *) RcInitUserCtxLocation(ctxBuff,
                                                                                         CC_UTIL_BUFF_IN_BYTES,
                                                                                         sizeof(struct drv_ctx_cipher));
    if (pAesContext == NULL) {
        return CC_UTIL_ILLEGAL_PARAMS_ERROR;
    }

    /* Check inputs */
    if (NULL == pDataIn) {
        return CC_UTIL_DATA_IN_POINTER_INVALID_ERROR;
    }
    if (NULL == pCmacResult) {
        return CC_UTIL_DATA_OUT_POINTER_INVALID_ERROR;
    }
    if ((dataInSize < CC_UTIL_CMAC_DERV_MIN_DATA_IN_SIZE)
                    || (dataInSize > CC_UTIL_CMAC_DERV_MAX_DATA_IN_SIZE)) {
        return CC_UTIL_DATA_IN_SIZE_INVALID_ERROR;
    }

    switch (keyType) {
        case UTIL_ROOT_KEY:
            /* Set AES key to ROOT KEY */
            pAesContext->crypto_key_type = DRV_ROOT_KEY;
            pAesContext->key_size = CC_AES_256_BIT_KEY_SIZE;
            break;

        case UTIL_SESSION_KEY:
            /* Set AES key to SESSION KEY */
            pAesContext->crypto_key_type = DRV_SESSION_KEY;
            pAesContext->key_size = CC_AES_128_BIT_KEY_SIZE;
            break;
        case UTIL_KCP_KEY:
            /* Set AES key to KCP KEY */
            pAesContext->crypto_key_type = DRV_KCP_KEY;
            pAesContext->key_size = CC_AES_128_BIT_KEY_SIZE;
            break;
        case UTIL_KPICV_KEY:
            /* Set AES key to KPICV KEY */
            pAesContext->crypto_key_type = DRV_KPICV_KEY;
            pAesContext->key_size = CC_AES_128_BIT_KEY_SIZE;
            break;
        case UTIL_USER_KEY:
            if ((pUserKey->keySize != CC_AES_128_BIT_KEY_SIZE)
                            && (pUserKey->keySize != CC_AES_256_BIT_KEY_SIZE)) {
                return CC_UTIL_INVALID_USER_KEY_SIZE;
            }
            /* Set AES key to USER KEY, and copy the key to the context */
            pAesContext->crypto_key_type = DRV_USER_KEY;
            pAesContext->key_size = pUserKey->keySize;
            CC_PalMemCopy(pAesContext->key, pUserKey->pKey, pUserKey->keySize);
            break;
        default:
            return CC_UTIL_INVALID_KEY_TYPE;
    }

    if (keyType != UTIL_USER_KEY) {

        CC_UTIL_IS_SECURE_DISABLE_FLAG_SET(isSet);
        if (isSet == SECURE_DISABLE_FLAG_SET) {
            CC_PAL_LOG_ERR("security disabled bit is asserted\n");
            return CC_UTIL_SD_IS_SET_ERROR;
        }

        /* check if fatal error bit is set to ON */
        CC_UTIL_IS_FATAL_ERROR_SET(isSet);
        if (isSet == FATAL_ERROR_FLAG_SET) {
            CC_PAL_LOG_ERR("Fatal Error bit is set to ON\n");
            return CC_UTIL_FATAL_ERR_IS_LOCKED_ERR;
        }
    }

    pAesContext->alg = DRV_CRYPTO_ALG_AES;
    pAesContext->mode = DRV_CIPHER_CMAC;
    pAesContext->direction = DRV_CRYPTO_DIRECTION_ENCRYPT;
    CC_PalMemSetZero(pAesContext->block_state, CC_AES_BLOCK_SIZE);

    symRc = SymDriverAdaptorInit((uint32_t *) pAesContext, pAesContext->alg, pAesContext->mode);
    if (symRc != 0) {
        return SymAdaptor2CmacDeriveKeyErr(symRc);
    }

    /* call SymDriverAdaptorFinalize with CMAC:  set the data unit size if first block */
    pAesContext->data_unit_size = dataInSize;
    symRc = SymDriverAdaptorFinalize((uint32_t *) pAesContext,
                                     pDataIn,
                                     (void *) pCmacResult,
                                     dataInSize,
                                     pAesContext->alg);

    if (symRc != 0) {
        return SymAdaptor2CmacDeriveKeyErr(symRc);
    }

    return CC_UTIL_OK;
}

