/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include <stdio.h>
#include <stdint.h>

#include "test_engine.h"
#include "cc_util_rpmb.h"
#include "test_proj_cclib.h"
#include "test_proj_otp.h"
#include "test_proj_defs.h"
#include "te_rpmb.h"

/******************************************************************
 * Defines
 ******************************************************************/

#define TE_RPMB_DATA_FRAMES_LIST_SIZE                  3

/******************************************************************
 * Types
 ******************************************************************/

/******************************************************************
 * Externs
 ******************************************************************/

/******************************************************************
 * Globals
 ******************************************************************/

/******************************************************************
 * Static Prototypes
 ******************************************************************/

static TE_rc_t rpmb_prepare(void* pContext);

static TE_rc_t rpmb_key_derivation(void* pContext);

static TE_rc_t rpmb_sign_frames(void* pContext);

/******************************************************************
 * Static functions
 ******************************************************************/

static TE_rc_t rpmb_prepare(void* pContext)
{
    TE_rc_t res = TE_RC_SUCCESS;
    unsigned int otpBuff[TEST_OTP_SIZE_IN_WORDS] = { 0 };
    TE_UNUSED(pContext);

    /* library was inited in common functions in wrappers.c, so we need to unmap it first */
    Test_Proj_CC_LibFini_Wrap();

    /* burn OTP with secure lcs */
    TE_ASSERT(Test_ProjBuildAndBurnOtp(otpBuff,
                                       TEST_PROJ_LCS_SECURE,
                                       PROJ_OTP_CHIP_STATE_PRODUCTION,
                                       NOT_SD_ENABLE,
                                       NOT_FULL_HBK) == 0);

    /* implicit reboot */

    /* init library again */
    TE_ASSERT(Test_Proj_CC_LibInit_Wrap() == 0);

bail:
    return res;
}

static TE_rc_t rpmb_key_derivation(void* pContext)
{
    TE_rc_t res = TE_RC_SUCCESS;
    TE_perfIndex_t cookie = 0;
    CCUtilRpmbKey_t pRpmbKey;
    TE_UNUSED(pContext);

    /* rpmb key derivation */
    /*---------------------*/
    cookie = TE_perfOpenNewEntry("rpmb", "key-derivation");
    TE_ASSERT(CC_UtilDeriveRPMBKey(pRpmbKey) == CC_OK);
    TE_perfCloseEntry(cookie);

bail:
    return res;
}

static TE_rc_t rpmb_sign_frames(void* pContext)
{
    TE_rc_t res = TE_RC_SUCCESS;
    TE_perfIndex_t cookie = 0;
    unsigned long pListOfDataFrames[TE_RPMB_DATA_FRAMES_LIST_SIZE];
    uint8_t data1[CC_UTIL_RPMB_DATA_FRAME_SIZE_IN_BYTES] = { 0 };
    uint8_t data2[CC_UTIL_RPMB_DATA_FRAME_SIZE_IN_BYTES] = { 0 };
    uint8_t data3[CC_UTIL_RPMB_DATA_FRAME_SIZE_IN_BYTES] = { 0 };
    pListOfDataFrames[0] = (unsigned long) data1;
    pListOfDataFrames[1] = (unsigned long) data2;
    pListOfDataFrames[2] = (unsigned long) data3;
    CCUtilHmacResult_t pHmacResult = { 0 };
    TE_UNUSED(pContext);

    /* Signing frames */
    /*----------------*/
    cookie = TE_perfOpenNewEntry("rpmb", "sign-frames");
    TE_ASSERT(CC_UtilSignRPMBFrames(pListOfDataFrames,
                                    TE_RPMB_DATA_FRAMES_LIST_SIZE,
                                    pHmacResult) == CC_OK);
    TE_perfCloseEntry(cookie);

bail:
    return res;
}

/******************************************************************
 * Public
 ******************************************************************/

int TE_init_rpmb_test(void)
{
    TE_rc_t res = TE_RC_SUCCESS;

    TE_perfEntryInit("rpmb", "key-derivation");
    TE_perfEntryInit("rpmb", "sign-frames");

    TE_ASSERT(TE_registerFlow("rpmb",
                               "key-derivation",
                               "",
                               rpmb_prepare,
                               rpmb_key_derivation,
                               NULL,
                               NULL,
                               NULL) == TE_RC_SUCCESS);

    TE_ASSERT(TE_registerFlow("rpmb",
                              "sign-frames",
                              "",
                              rpmb_prepare,
                              rpmb_sign_frames,
                              NULL,
                              NULL,
                              NULL) == TE_RC_SUCCESS);

bail:
	return res;
}
