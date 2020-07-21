/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include <stdio.h>
#include <stdint.h>

#include "test_engine.h"
#include "cc_asset_prov.h"
#include "cc_asset_provisioning.h"
#include "test_proj_otp_plat.h"
#include "test_proj_otp.h"
#include "test_proj_defs.h"
#include "test_proj_cclib.h"
#include "te_asset_prov.h"

/******************************************************************
 * Defines
 ******************************************************************/
#define ASSET_PROV_MAX_DATA_SIZE    500

/******************************************************************
 * Types
 ******************************************************************/
typedef struct AssetprovVector_t {
    CCAssetProvKeyType_t keyType;
    uint32_t pAssetPkgBuff[ASSET_PROV_MAX_DATA_SIZE];
    size_t assetPackageLen;
    uint32_t pAssetData[ASSET_PROV_MAX_DATA_SIZE];
    size_t assetDataLen;
    size_t expOutputDataLen;
    uint32_t expOutputData[ASSET_PROV_MAX_DATA_SIZE];
    TE_rc_t expResult;
} AssetprovVector_t;

/******************************************************************
 * Externs
 ******************************************************************/

/******************************************************************
 * Globals
 ******************************************************************/
static AssetprovVector_t vector1 = { .keyType = ASSET_PROV_KEY_TYPE_KCP,
        .pAssetPkgBuff = {
                0x20052001, 0x2, 0x53, 0x1069d6c8, 0x64e30be1, 0x3763540a, 0x172747a2, 0xd784491e, 0x36eb441f, 0xc785599a,
                0x9e3337b4, 0xdaa1d84c, 0x6ac24b59, 0xf20331b3, 0xe36ba2cf, 0x864f4f4b, 0xdd3b911e, 0x4a19411a, 0x2dda62dd, 0x64052637,
                0xbe9af316, 0x6ecece57, 0x409ccbb6, 0xbca4af63, 0x328d7bf8, 0x3c52f1e8, 0x34226ba7, 0xab41dd54, 0x3feab3fc, 0x878b5c81,
                0x4cd5ca86, 0x9f6edc, 0x0, 0x59, 0xaa0f0a20, 0x86f21386, 0x7a315df1, 0x2f8507, 0xbff5423b, 0x31d2ace0,
                0xf940b8aa, 0x7ab89cfb, 0xad3046b6, 0x914d1ade, 0xa5685865, 0x3ec21429, 0x2cd44977, 0x859a97d7, 0x339cbdf6, 0xb66c5d22,
                0xefed7311, 0xd3b7eba5, 0x3b586372, 0x9ee846f8, 0x207b2f, 0x89, 0xaa0f0a20, 0x86f21386, 0x7a315df1, 0x2f8507,
                0xbff5423b, 0x31d2ace0, 0xf940b8aa, 0x7ab89cfb, 0xad3046b6, 0x914d1ade, 0xa5685865, 0x3ec21429, 0x2cd44977, 0x859a97d7,
                0x339cbdf6, 0xb66c5d22, 0xefed7311, 0xd3b7eba5, 0x3b586372, 0x9ee846f8, 0x207b2f, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x91,
                0xf, 0x0, 0x1, 0x0, 0xb5a35928, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x1f651, 0x0, 0x0, 0x0},
        .assetPackageLen = 127,
        .pAssetData = {},
        .assetDataLen = ASSET_PROV_MAX_DATA_SIZE,
        .expOutputDataLen = 83,
        .expOutputData = {0xaa0f0a20, 0x86f21386, 0x7a315df1, 0x2f8507, 0xbff5423b, 0x31d2ace0, 0xf940b8aa, 0x7ab89cfb, 0xad3046b6, 0x914d1ade,
                0xa5685865, 0x3ec21429, 0x2cd44977, 0x859a97d7, 0x339cbdf6, 0xb66c5d22, 0xefed7311, 0xd3b7eba5, 0x3b586372, 0x9ee846f8,
                0x207b2f, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x91, 0xf, 0x0, 0x1, 0x0, 0xb5a35928, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1f651,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
        .expResult = TE_RC_SUCCESS};

static TE_TestVec_t vectors[] = { { .name = "asset-prov", .pData = &vector1, }};

static TE_TestVecList_t testVecList = TE_TEST_VEC(vectors);

static uint32_t kcp_field[] = { 0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c};

/******************************************************************
 * Static Prototypes
 ******************************************************************/
static TE_rc_t asset_prov_prepare(void *pContext);
static TE_rc_t asset_prov_open_blob(TE_TestVec_t *pTestVec, TE_rc_t *result);
static TE_rc_t asset_prov_cleanup(void *pContext);

/******************************************************************
 * Static functions
 ******************************************************************/

static TE_rc_t asset_prov_prepare(void *pContext)
{
    uint32_t otpBuff[TEST_OTP_SIZE_IN_WORDS] = { 0 };
    TE_rc_t res = TE_RC_SUCCESS;
    TE_UNUSED(pContext);

    /* Finalise CC TEE runtime library */
    Test_Proj_CC_LibFini_Wrap();

    /* update OTP KCP key */
    TE_ASSERT_ERR(Test_ProjBuildDefaultOtp(otpBuff, TEST_OTP_SIZE_IN_WORDS, TEST_PROJ_LCS_SECURE,
            PROJ_OTP_CHIP_STATE_PRODUCTION, PROJ_OTP_RMA_NO, 0, 0), 0, 1);

    TE_ASSERT_ERR(Test_ProjSetOtpField(otpBuff, kcp_field, PROJ_OTP_KCP_FIELD, 0), 0, 1);
    TE_ASSERT_ERR(Test_ProjSetZeroBitsOtpBuff(otpBuff,
            PROJ_OTP_KCP_FIELD, 0, 0), 0, 1);

    TE_ASSERT_ERR(Test_ProjBurnOtp(otpBuff, TEST_PROJ_LCS_SECURE), 0, 1);

    /* ReInitiate CC TEE runtime library */
    TE_ASSERT(Test_Proj_CC_LibInit_Wrap() == 0);

    goto bail;
bail:
    return res;
}

static TE_rc_t asset_prov_open_blob(TE_TestVec_t *pTestVec, TE_rc_t *result)
{
    TE_rc_t res = TE_RC_SUCCESS;

    AssetprovVector_t *vec = (AssetprovVector_t *) pTestVec->pData;

    TE_perfIndex_t cookie = TE_perfOpenNewEntry("asset_prov", "open");

    res = CC_UtilAssetProvisioningOpen(vec->keyType, vec->pAssetPkgBuff, vec->assetPackageLen,
            vec->pAssetData, &vec->assetDataLen);

    TE_ASSERT(res == vec->expResult);

    if (res == TE_RC_SUCCESS) {
        TE_ASSERT(vec->expOutputDataLen == vec->assetDataLen);
        TE_ASSERT(memcmp(vec->pAssetData, vec->expOutputData, vec->assetDataLen) == 0);
    }

    TE_perfCloseEntry(cookie);

bail:
    *result = res;
    return *result;
}

static TE_rc_t asset_prov_cleanup(void *pContext)
{
    TE_rc_t res = TE_RC_SUCCESS;
    TE_UNUSED(pContext);

    goto bail;
bail:
    return res;
}

/******************************************************************
 * Public
 ******************************************************************/
int TE_init_asset_prov_test(void)
{
    TE_rc_t res = TE_RC_SUCCESS;


    TE_perfEntryInit("asset_prov", "open");

    TE_ASSERT(TE_registerSuite("asset_prov",
                               "open",
                               "pass",
                               asset_prov_prepare,
                               asset_prov_open_blob,
                               asset_prov_cleanup,
                               &testVecList) == TE_RC_SUCCESS);
    goto bail;

bail:
	return res;
}
