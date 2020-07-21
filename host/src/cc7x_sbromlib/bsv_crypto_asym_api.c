/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


#include "bsv_error.h"
#include "cc_bitops.h"
#include "bsv_crypto_asym_api.h"
#include "bootimagesverifier_def.h"
#include "bsv_rsa_driver.h"
#include "bsv_hw_defs.h"
#include "rsa_bsv.h"
#include "util.h"

#ifdef BIG__ENDIAN
#define IS_WORD_MSBIT_ON(word) (word & (1<<31))
#else
#define IS_WORD_MSBIT_ON(word) (word & (1<<7))
#endif


static CCError_t RsaCalcExponentBE(unsigned long hwBaseAddress,
                                   CCBsvNBuff_t NBuff,
                                   CCBsvNpBuff_t NpBuff,
                                   uint32_t *pInBuff,
                                   size_t inBuffSize,
                                   CCBsvSignature_t pOutBuff,
                                   BsvRsaExponentWorkspace_t *pWorkStruct)
{
    uint32_t error = CC_OK;

    if ((NBuff == NULL) ||
            (pInBuff == NULL) ||
            (inBuffSize != BSV_CERT_RSA_KEY_SIZE_IN_BYTES) ||
            (pOutBuff == NULL) ||
            (pWorkStruct == NULL)) {
        return CC_BSV_ILLEGAL_INPUT_PARAM_ERR;
    }

    /* reverse the provided buffer from BE format to LE format */
    UTIL_ReverseMemCopy((uint8_t *)pWorkStruct->pNparams.N, (uint8_t *)NBuff, BSV_CERT_RSA_KEY_SIZE_IN_BYTES);
    UTIL_ReverseMemCopy((uint8_t *)pWorkStruct->pDataIn,
                        (uint8_t *)pInBuff, BSV_CERT_RSA_KEY_SIZE_IN_BYTES);

    /* If Np is not provided, Calculate it; otherwise reverse it */
    if (NpBuff == NULL) {
        error = BsvRsaCalcNp(hwBaseAddress, pWorkStruct->pNparams.N, pWorkStruct->pNparams.Np); /* result is LE format */
        if (error != CC_OK) {
            goto end;
        }
    } else {
        UTIL_ReverseMemCopy((uint8_t *)pWorkStruct->pNparams.Np, (uint8_t *)NpBuff, RSA_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_BYTES);
    }

    error = BsvRsaCalcExponent(hwBaseAddress, pWorkStruct->pDataIn, pWorkStruct->pNparams.N, pWorkStruct->pNparams.Np, pOutBuff);
    if (error != CC_OK) {
        goto end;
    }

    /* Reverse the result to BE format */
    UTIL_ReverseMemCopy((uint8_t *)pOutBuff, (uint8_t *)pOutBuff, BSV_CERT_RSA_KEY_SIZE_IN_BYTES);
end:
    if (error != CC_OK) {
        UTIL_MemSet((uint8_t*)pWorkStruct, 0, sizeof(BsvRsaExponentWorkspace_t));
    }
    return error;
}

static int32_t CmpUserBuffers (uint8_t *pBuff1 , uint8_t *pBuff2 , uint32_t buffSize)
{
    uint32_t i = 0;

    /* No need to compare all bytes, since we compare user inputs which are not secrets */
    while ((i < buffSize) &&
           (pBuff1[i] == pBuff2[i])) {
        i++;
    }
    if (i == buffSize) {
        return 0;
    }
    return ((pBuff1[i] < pBuff2[i]) ? -1 : 1);
}

/************************ Public Functions ******************************/

/* Trust in Soft annotations - __TRUSTINSOFT_ANALYZER__ */
/*@
    requires \valid((uint8_t*)hwBaseAddress + (0 .. CC_REG_AREA_SIZE - 1));
*/
CCError_t CC_BsvRsaPrimVerify (unsigned long hwBaseAddress,
                                CCBsvNBuff_t NBuff,
                                CCBsvNpBuff_t NpBuff,
                                uint32_t *pInBuff,
                                size_t inBuffSize,
                                CCBsvSignature_t pOutBuff,
                                uint32_t *pWorkSpace,
                                size_t  workBufferSize)
{
    uint32_t error = CC_OK;
    uint32_t isSDEnable;

    /* When security disable is on PKA is not functional */
    CC_BSV_IS_SD_FLAG_SET(hwBaseAddress, isSDEnable);
    if (isSDEnable == 1) {
        return CC_BSV_SECURE_DISABLE_ERROR;
    }

    /* Verify Inputs, In case Np is NULL it will be later calculated */
    if ((NBuff == NULL) ||
            (pInBuff == NULL) ||
            (inBuffSize != BSV_CERT_RSA_KEY_SIZE_IN_BYTES) ||
            (pOutBuff == NULL) ||
            (pWorkSpace == NULL) ||
            (workBufferSize < BSV_RSA_WORKSPACE_MIN_SIZE) ||
            (BSV_RSA_WORKSPACE_MIN_SIZE < sizeof(BsvRsaExponentWorkspace_t))) {
        return CC_BSV_ILLEGAL_INPUT_PARAM_ERR;
    }
    UTIL_MemSet((uint8_t*)pWorkSpace, 0, workBufferSize);

    /* DataIn buffer must be smaller than the modulus */
    if (CmpUserBuffers((uint8_t*)pInBuff, (uint8_t*)NBuff, BSV_CERT_RSA_KEY_SIZE_IN_BYTES) != (-1)) {
        return CC_BSV_ILLEGAL_INPUT_PARAM_ERR;
    }

    error = RsaCalcExponentBE(hwBaseAddress,
                              NBuff,
                              NpBuff,
                              pInBuff,
                              inBuffSize,
                              pOutBuff,
                              (BsvRsaExponentWorkspace_t *)pWorkSpace);

    UTIL_MemSet((uint8_t*)pWorkSpace, 0, workBufferSize);
    return error;
}

/* Trust in Soft annotations - __TRUSTINSOFT_ANALYZER__ */
/*@
    requires \valid((uint8_t*)hwBaseAddress + (0 .. CC_REG_AREA_SIZE - 1));
*/
CCError_t CC_BsvRsaPssVerify(unsigned long hwBaseAddress,
                             CCBsvNBuff_t NBuff,
                             CCBsvNpBuff_t NpBuff,
                             CCBsvSignature_t signature,
                             CCHashResult_t hashedData,
                             uint32_t *pWorkSpace,
                             size_t  workBufferSize,
                             CCBool_t    *pIsVerified)
{
    uint32_t error = CC_OK;
    BsvPssVerifyWorkspace_t *lPssWs;
    uint32_t isSDEnable;

    /* When security disable is on PKA is not functional */
    CC_BSV_IS_SD_FLAG_SET(hwBaseAddress, isSDEnable);
    if (isSDEnable == 1) {
        return CC_BSV_SECURE_DISABLE_ERROR;
    }

    /* Verify sizes - development phase */
    if ((BSV_RSA_WORKSPACE_MIN_SIZE < sizeof(BsvPssVerifyWorkspace_t)) ||
        (CC_BSV_PSS_WORKSPACE_SIZE_IN_BYTES != BSV_RSA_WORKSPACE_MIN_SIZE)) {
        return CC_BSV_ILLEGAL_INPUT_PARAM_ERR;
    }

    /* Verify Inputs, In case Np is NULL it will be later calculated */
    if ((NBuff == NULL) ||
            (signature == NULL) ||
            (hashedData == NULL) ||
            (pWorkSpace == NULL) ||
            (workBufferSize < BSV_RSA_WORKSPACE_MIN_SIZE) ||
            (pIsVerified == NULL)) {
         return CC_BSV_ILLEGAL_INPUT_PARAM_ERR;
    }
    UTIL_MemSet((uint8_t*)pWorkSpace, 0, workBufferSize);

    lPssWs = (BsvPssVerifyWorkspace_t *)pWorkSpace;

    *pIsVerified = CC_FALSE;


    /* execute the decryption */
    error =  RsaCalcExponentBE(hwBaseAddress,
                               NBuff,
                               NpBuff,
                               signature,
                               BSV_CERT_RSA_KEY_SIZE_IN_BYTES,
                               lPssWs->pssVerWs.ED,
                               &lPssWs->rsaExponentWs);
    if (error != CC_OK) {
        goto End;
    }

    error =  BsvRsaPssDecode(hwBaseAddress,
                             hashedData,
                             (uint8_t *)lPssWs->pssVerWs.ED,
                             (int32_t *)pIsVerified,
                             &lPssWs->pssVerWs.pssDecode);
    if (error != CC_OK) {
        goto End;
    }

    End:
    /* zeroing temp buffer */
    UTIL_MemSet((uint8_t*)pWorkSpace, 0, workBufferSize);
    return error;
}

