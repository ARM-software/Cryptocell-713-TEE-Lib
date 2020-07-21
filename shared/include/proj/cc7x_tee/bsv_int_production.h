/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


#ifndef _BSV_INT_PRODUCTION_H
#define _BSV_INT_PRODUCTION_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "cc_pal_types.h"
#include "bsv_crypto_driver.h"
#include "cc_bitops.h"
#include "cc_otp_defs.h"

/* SRAM mapping */
#define CC_PROD_CONTEXT_SIZE                           16
#define CC_PROD_CONTEXT_SRAM_OFFSET                    0x30

#define CC_PROD_HMAC_SIZE                              16
#define CC_PROD_KEY_RTL_KEY_SIZE                       16
#define CC_PROD_DERIVED_KEY_SIZE                       16

#define CC_PROD_PKG_ASSET_CMPU_TOKEN                   "PrAI"
#define CC_PROD_PKG_ASSET_DMPU_TOKEN                   "PrAO"
#define CC_PROD_PKG_ASSET_UTIL_TOKEN_SIZE              4
#define CC_PROD_PKG_ASSET_VERSION                      0x1
#define CC_PROD_PKG_HEADER_CMPU_TOKEN                  "PrIH"
#define CC_PROD_PKG_HEADER_DMPU_TOKEN                  "PrOH"
#define CC_PROD_PKG_HEADER_VERSION                     0x1

#define CC_PROD_PKG_MASTER_KEY_IMAGE_CMPU_LABEL        "CMPU KEY"
#define CC_PROD_PKG_MASTER_KEY_IMAGE_DMPU_LABEL        "DMPU KEY"
#define CC_PROD_PKG_MASTER_KEY_IMAGE_LABEL_SIZE        8

#define CC_PROD_PKG_MASTER_KEY_ASSETS_CMPU_LABEL       "ICV KEY"
#define CC_PROD_PKG_MASTER_KEY_ASSETS_DMPU_LABEL       "OEM KEY"
#define CC_PROD_PKG_MASTER_KEY_ASSETS_LABEL_SIZE       7

#define CC_PROD_PKG_KPLT_KEY_LABEL                     "KEY PLAT"
#define CC_PROD_PKG_KPLT_KEY_LABEL_SIZE                8

#define CC_PROD_PKG_HEADER_KEY_LABEL                   "HEADER KEY"
#define CC_PROD_PKG_HEADER_KEY_LABEL_SIZE              10
#define CC_PROD_PKG_BODY_KEY_LABEL                     "BLOB KEY"
#define CC_PROD_PKG_BODY_KEY_LABEL_SIZE                8

#define CC_PROD_PKG_HEADER_SIZE                        sizeof(CCProdPkgHeader_t) - sizeof(CCBsvProdHmacResult_t)
#define CC_PROD_PKG_HEADER_PADDED_KEY_SIZE             64 /* bytes */

/* These values are the size of the CCProdPkgAssetsAssets_t and CCProdPkgAssetsKeys_t structs.
 * these values should be the same on all compilers */
#define CC_PROD_ASSETS_ASSETS_SIZE                     48
#define CC_PROD_ASSETS_KEYS_SIZE                       48

typedef uint8_t CCBsvProductionConext_t[CC_PROD_CONTEXT_SIZE];
typedef uint8_t CCBsvProdHmacResult_t[CC_PROD_HMAC_SIZE];
typedef uint8_t CCBsvProductionKey_t[CC_PROD_DERIVED_KEY_SIZE];

typedef enum CCProdUtility_t {
    PROD_UTIL_CMPU 	= 1,
    PROD_UTIL_DMPU 	= 2,
    PROD_UTIL_RESERVED 	= 0x7FFFFFFF,
}CCProdUtility_t;

typedef union {
    struct {
        uint32_t     pciState:8;
        uint32_t     reserved:24;
    }flagsBits;
    uint32_t      flagsWord;
}CCProdPkgHeaderFlags_t;

/*! The Production package blob header definition .*/
typedef struct {
    uint32_t                    token;
    uint32_t                    version;
    uint32_t                    bodySize;
    CCProdPkgHeaderFlags_t      flags;
    CCBsvCcmNonce_t             ccmNonce;
    CCBsvProductionConext_t     master_context;
    CCBsvProdHmacResult_t       hmacRes;
}CCProdPkgHeader_t;

/*! The Production package blob definition .*/
typedef struct {
    /*! Package header. */
    CCProdPkgHeader_t header;
} CCProdPkg_t;

/*********************************************************************
 *                      Assets
 *********************************************************************/
typedef union CCProdHbkBuff_t {
    /*! HBK1 buffer if used by device. */
    uint32_t    halfHbk[CC_OTP_HBK1_SIZE_IN_WORDS];
    /*!  HBK buffer - full 256 bits. */
    uint32_t    fullHbk[CC_OTP_HBK_SIZE_IN_WORDS];
} CCProdHbkBuff_t;

typedef union CCProdPkgAssetsKeys_t {
    struct {
        uint32_t                Kpicv[CC_OTP_KPICV_SIZE_IN_WORDS];
        uint32_t                Kceicv[CC_OTP_KCEICV_SIZE_IN_WORDS];
    } icv;
    struct {
        uint32_t                Kcp[CC_OTP_KCP_SIZE_IN_WORDS];
        uint32_t                Kce[CC_OTP_KCE_SIZE_IN_WORDS];
        uint32_t                EKcst[CC_OTP_EKCST_SIZE_IN_WORDS];
    } oem;
} CCProdPkgAssetsKeys_t;

typedef union CCProdPkgAssetsAssets_t {
    struct {
        uint32_t                icvGpio;
        uint32_t                secureGuard;
        uint32_t                dcuLock[CC_OTP_DCU_SIZE_IN_WORDS];
        uint32_t                halfHbk[CC_OTP_HBK0_SIZE_IN_WORDS];
    } icv;
    struct {
        uint32_t                dcuLock[CC_OTP_DCU_SIZE_IN_WORDS];
        CCProdHbkBuff_t         hbk;
    } oem;
} CCProdPkgAssetsAssets_t;

typedef union CCProdAssetHeaderFlags_t {
    struct {
        uint32_t      isHalfHbk:1;
        uint32_t      isKpicvValid:1;
        uint32_t      isKceicvValid:1;
        uint32_t      isIcvGpioValid:1;
        uint32_t      isSecureGuardValid:1;
        uint32_t      isDcuLockValid:1;
        uint32_t      isSecureDisableValid:1;
        uint32_t      reserved:25;
    }icv;
    struct {
        uint32_t      isHalfHbk:1;
        uint32_t      isKcpValid:1;
        uint32_t      isKceValid:1;
        uint32_t      isEKcstValid:1;
        uint32_t      isDcuLockValid:1;
        uint32_t      reserved:27;
    }oem;
    uint32_t        flagsWord;
} CCProdAssetHeaderFlags_t;

typedef struct CCProdPkgAssetsHeaders_t {
    uint32_t                    token;
    uint32_t                    version;
    CCBsvCcmNonce_t             ccmNonce;
    CCProdAssetHeaderFlags_t    assetFlags;
} CCProdPkgAssetsHeaders_t;

typedef struct CCProdPkgAssetsAddData_t {
    CCProdPkgAssetsHeaders_t    header;
    CCProdPkgAssetsAssets_t     assets;
} CCProdPkgAssetsAddData_t;

typedef struct CCProdPkgAssets_t {
    CCProdPkgAssetsAddData_t    addData;
    CCProdPkgAssetsKeys_t       keys;
    uint8_t                     mac[CC_BSV_CMAC_RESULT_SIZE_IN_BYTES];
} CCProdPkgAssets_t;

#ifdef __cplusplus
}
#endif

#endif



