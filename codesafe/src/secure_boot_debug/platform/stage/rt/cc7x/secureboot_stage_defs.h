/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _SECURE_BOOT_STAGE_DEFS_H
#define _SECURE_BOOT_STAGE_DEFS_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "bsv_rsa_driver.h"
#include "bsv_hw_defs.h"
#include "bsv_defs.h"
#include "bsv_error.h"
#include "secureboot_defs.h"
#include "secureboot_parser_gen_defs.h"
#include "cc_hash.h"
#include "rsa_hwdefs.h"
#include "util.h"
#include "cc_sbrt_crypto_int_api.h"

/*! @file
@brief This file contains all of the definitions and structures used for the Secure Boot and Secure Debug in Boot stage.
*/
CCError_t SbrtPubKeyHashGet(unsigned long hwBaseAddress, CCSbPubKeyIndexType_t keyIndex, uint32_t *hashedPubKey, uint32_t hashResultSizeWords);
CCError_t SbrtLcsGet(unsigned long hwBaseAddress, uint32_t *pLcs);

#define _CCSbImageLoadAndVerify(preHashflashRead_func, preHashUserContext, hwBaseAddress, isLoadFromFlash, isVerifyImage, cryptoMode, keyType, AESIv, pSwRecSignedData, pSwRecNoneSignedData, workspace_ptr, workspaceSize, pVerifiedImageInfo) \
                SbrtImageLoadAndVerify(preHashflashRead_func, preHashUserContext, hwBaseAddress, isLoadFromFlash, isVerifyImage, cryptoMode, keyType, AESIv, pSwRecSignedData, pSwRecNoneSignedData, workspace_ptr, workspaceSize, pVerifiedImageInfo)

#define CC_BsvLcsGet(hwBaseAddress, pLcs) \
                SbrtLcsGet(hwBaseAddress, pLcs)

#define CC_BsvPubKeyHashGet(hwBaseAddress, keyIndex, hashedPubKey, hashResultSizeWords) \
                SbrtPubKeyHashGet(hwBaseAddress, keyIndex, hashedPubKey, hashResultSizeWords)

#define _BSV_SHA256(hwBaseAddress, pDataIn, dataSize, hashResult) \
                SbrtSHA256(hwBaseAddress, pDataIn, dataSize, hashResult)

#define _RSA_PSS_Verify(error, hwBaseAddress, mHash, pN, pNp, pSign, pWorkSpace, workspaceSize) \
                error = SbrtRsaPssVerify(hwBaseAddress,pN, pNp, pSign, mHash, pWorkSpace, workspaceSize)

#define CCSbVerifyNvCounter(hwBaseAddress, nvCounter, certPkgInfo) \
                SbrtVerifyNvCounter(hwBaseAddress, nvCounter, certPkgInfo)

#define CCSbUpdateNvCounter(hwBaseAddress, certPkgInfo) \
                SbrtUpdateNvCounter(hwBaseAddress, certPkgInfo)

#ifdef BIG__ENDIAN
#define UTIL_REVERT_UINT32_BYTES( val ) \
   ( ((val) >> 24) | (((val) & 0x00FF0000) >> 8) | (((val) & 0x0000FF00) << 8) | (((val) & 0x000000FF) << 24) )
#else
#define UTIL_REVERT_UINT32_BYTES( val ) (val)
#endif

#ifdef __cplusplus
}
#endif

#endif


