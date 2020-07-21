/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#define CC_PAL_LOG_CUR_COMPONENT CC_LOG_MASK_SECURE_BOOT

/************* Include Files ****************/
#include "cc_sbrt_api.h"
#include "bootimagesverifier_def.h"
#include "bootimagesverifier_api.h"
#include "cc_pal_log.h"
#include "secureboot_defs.h"
#include "secboot_cert_defs.h"
#include "cc_fips_defs.h"

/************************ Defines ******************************/

/************************ Enums ******************************/

/************************ Typedefs ******************************/

/************************ Global Data ******************************/

/************************ Private functions  ******************************/

/************************ Public functions  ******************************/
CCError_t CC_SbrtCertChainVerificationInit(CCSbCertInfo_t *certPkgInfo)
{
    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    return CC_SbCertChainVerificationInit(certPkgInfo);
}


CCError_t CC_SbrtCertVerifySingle(CCSbFlashReadFunc flashReadFunc,
                                  void *userContext,
                                  CCAddr_t certSrcAddress,
                                  CCSbCertInfo_t *pCertPkgInfo,
                                  CCSbX509TBSHeader_t *pX509Header,
                                  uint32_t *pWorkspace,
                                  uint32_t workspaceSize,
                                  CCSbImagesInfo_t *pImagesInfo,
                                  CCSbUserAddData_t *pUserData)
{

    extern unsigned long gCcRegBase;

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    return CC_SbCertVerifySingle(flashReadFunc,
                                 userContext,
                                 gCcRegBase,
                                 certSrcAddress,
                                 pCertPkgInfo,
                                 pX509Header,
                                 pWorkspace,
                                 workspaceSize,
                                 pImagesInfo,
                                 pUserData);
}

CCError_t CC_SbrtSwImageStoreAddrChange(uint32_t *pCert,
                                        uint32_t maxCertSizeWords,
                                        CCAddr_t address,
                                        uint32_t indexOfAddress)
{
    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    return CC_SbSwImageStoreAddrChange(pCert, maxCertSizeWords, address, indexOfAddress);
}

CCError_t CC_SbrtGetCertSize(CCSbCertChainType_t chainType,
                             uint32_t *pCert,
                             uint32_t *pCertSizeWords)
{
    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    return CC_SbGetCertSize(chainType, pCert, pCertSizeWords);
}


