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
#include "cc_sym_error.h"
#include "cc_aes.h"
#include "cc_aes_defs.h"
#include "cc_util_defs.h"
#include "cc_util_error.h"
#include "cc_util_key_derivation.h"
#include "cc_hal_plat.h"
#include "cc_regs.h"
#include "cc_pal_mutex.h"
#include "cc_pal_abort.h"
#include "cc_util_cmac.h"
#include "cc_fips_defs.h"
#include "cc_hash.h"
#include "cc_hmac.h"
#include "cc_general_defs.h"


CCUtilError_t CC_UtilKeyDerivation( CCUtilKeyType_t             keyType,
                                    CCKeyData_t                 *pUserKey,
                                    CCUtilPrfType_t             prfType,
                                    CCHashOperationMode_t       hashMode,
                                    const uint8_t               *pLabel,
                                    size_t                      labelSize,
                                    const uint8_t               *pContextData,
                                    size_t                      contextSize,
                                    uint8_t                     *pDerivedKey,
                                    size_t                      derivedKeySize)
{
        uint32_t                rc = 0;
        uint32_t                dataSize, i, iterationNum, numIteration, bytesToCopy;
        uint8_t                 dataIn[CC_UTIL_MAX_KDF_SIZE_IN_BYTES] = {0};
        uint8_t                 tmp[CC_UTIL_AES_CMAC_RESULT_SIZE_IN_BYTES];
        CCHashResultBuf_t       hmacResultBuff;
        size_t                  length, lengthReverse, prfUpperLimit;
        UtilKeyType_t           utilKeyType;
        uint8_t*                srcToCopy;
        size_t origDerivedKeySize;
        uint32_t                isSet;
        CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

        /* Check PRF type */
        if ((CC_UTIL_PRF_CMAC != prfType) && (CC_UTIL_PRF_HMAC != prfType)) {
                return CC_UTIL_INVALID_PRF_TYPE;
        }

        if ((CC_UTIL_PRF_HMAC == prfType) && (hashMode >= CC_HASH_MD5_mode)){
                return CC_UTIL_INVALID_HASH_MODE;
        }
        origDerivedKeySize = derivedKeySize;

        /* Check key type */
        if (CC_UTIL_PRF_HMAC == prfType) {
            if (keyType != CC_UTIL_USER_KEY) {
                return CC_UTIL_INVALID_PRF_TYPE;
            }
            utilKeyType = UTIL_USER_KEY;
        } else {
            switch (keyType) {
            case CC_UTIL_ROOT_KEY:
                utilKeyType = UTIL_ROOT_KEY;
                break;
            case CC_UTIL_KCP_KEY:
                utilKeyType = UTIL_KCP_KEY;
                break;
            case CC_UTIL_KPICV_KEY:
                utilKeyType = UTIL_KPICV_KEY;
                break;
            case CC_UTIL_USER_KEY:
                utilKeyType = UTIL_USER_KEY;
                break;
            default:
                return CC_UTIL_INVALID_KEY_TYPE;
            }
        }

        if (keyType == CC_UTIL_USER_KEY) {
            if (!pUserKey) {
                    return CC_UTIL_INVALID_KEY_TYPE;
            }
            if (!pUserKey->pKey) {
                    return CC_UTIL_INVALID_KEY_TYPE;
            }
        } else {
            /* check if secure disable bit is set to ON */
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

        /* Check Label, Context, DerivedKey sizes */
        if ((pLabel == NULL) || (labelSize == 0) ||
            (labelSize > CC_UTIL_MAX_LABEL_LENGTH_IN_BYTES) ) {
                return CC_UTIL_ILLEGAL_PARAMS_ERROR;
        }

        if ((pContextData== NULL) || (contextSize == 0) ||
            (contextSize > CC_UTIL_MAX_CONTEXT_LENGTH_IN_BYTES) ) {
                return CC_UTIL_ILLEGAL_PARAMS_ERROR;
        }

        if ((pDerivedKey == NULL) || (derivedKeySize == 0)) {
            return CC_UTIL_ILLEGAL_PARAMS_ERROR;
        }

        /* Generate dataIn buffer for CMAC: iteration || Label || 0x00 || context || length */

        if(CC_UTIL_PRF_CMAC == prfType) {
                prfUpperLimit = CC_UTIL_AES_CMAC_RESULT_SIZE_IN_BYTES;
        } else { /* CC_UTIL_PRF_HMAC */
                if (CC_TRUE == HmacSupportedHashModes_t[hashMode]) {
                        prfUpperLimit = HmacHashInfo_t[hashMode].hashResultSize;
                } else {
                        return CC_UTIL_UNSUPPORTED_HASH_MODE;
                }
        }

        /* the derivation key size is limited to the internal counter size -
         * 1 Byte = 0xFF and result size
         */
        if (derivedKeySize > (prfUpperLimit * 0xFF))
                return CC_UTIL_ILLEGAL_PARAMS_ERROR;


        i = 1;
        numIteration = (derivedKeySize + prfUpperLimit - 1) / prfUpperLimit;
        length = derivedKeySize*8;
        if (length > 0xFF){
                dataSize = CC_UTIL_FIX_DATA_MAX_SIZE_IN_BYTES;
        } else {
                dataSize = CC_UTIL_FIX_DATA_MIN_SIZE_IN_BYTES;
        }

        dataSize += labelSize+contextSize;

        if (labelSize!=0) {
                CC_PalMemCopy((uint8_t*)&dataIn[i], pLabel, labelSize);
                i+=labelSize;
        }

        dataIn[i++] = 0x00;

        if (contextSize!=0) {
                CC_PalMemCopy((uint8_t*)&dataIn[i], pContextData, contextSize);
                i+=contextSize;
        }

        if (length > 0xFF) {
                /* Reverse words order and bytes in each word */
                lengthReverse = ((length & 0xFF00)>>8) | ((length & 0xFF)<<8);
                CC_PalMemCopy((uint8_t*)&dataIn[i], (uint8_t*)&lengthReverse, 2);
        } else {
                CC_PalMemCopy((uint8_t*)&dataIn[i], (uint8_t*)&length, 1);
        }

        srcToCopy = ((CC_UTIL_PRF_CMAC == prfType) ? tmp : (uint8_t*)&hmacResultBuff);
        for (iterationNum = 0; iterationNum < numIteration; iterationNum++) {
                dataIn[0] = iterationNum+1;
                if(CC_UTIL_PRF_CMAC == prfType) {
                        rc = UtilCmacDeriveKey(utilKeyType, (CCAesUserKeyData_t*)pUserKey, dataIn, dataSize, tmp);
                }
                else { /* CC_UTIL_PRF_HMAC */
                        rc = CC_Hmac(hashMode, pUserKey->pKey, pUserKey->keySize, dataIn, dataSize, hmacResultBuff);
                }

                if (rc != CC_SUCCESS)
                        return rc;

                /* concatenate the latest PRF result */
                /* copy only number of bits that required... */
                if (derivedKeySize > prfUpperLimit) {
                        bytesToCopy = prfUpperLimit;
                        derivedKeySize -= prfUpperLimit;
                } else{
                	bytesToCopy = derivedKeySize;
                }

                if(bytesToCopy<=(origDerivedKeySize-iterationNum*prfUpperLimit) /*to avoid memory corruption*/&&
                		( bytesToCopy<=CC_HASH_RESULT_SIZE_IN_WORDS*sizeof(uint32_t) ) /*to remove static analyzer warnings*/)
                {
                	CC_PalMemCopy((uint8_t*)&pDerivedKey[iterationNum*prfUpperLimit], srcToCopy, bytesToCopy);
                }else{
                	return CC_UTIL_DATA_OUT_SIZE_INVALID_ERROR;
                }
        }

        return rc;
}

