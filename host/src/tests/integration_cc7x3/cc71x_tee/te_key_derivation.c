/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include <stdio.h>
#include <stdint.h>

#include "test_engine.h"
#include "cc_util_defs.h"
#include "cc_util_key_derivation.h"
#include "test_proj_otp.h"
#include "test_proj_cclib.h"
#include "cc_aes.h"
#include "cc_aes_defs.h"
#include "cc_aes_error.h"
#include "test_proj_defs.h"
#include "te_key_derivation.h"

/******************************************************************
 * Defines
 ******************************************************************/

/******************************************************************
 * Types
 ******************************************************************/

typedef struct key_derivation_vec_t {
    uint8_t             *pContextData;
    size_t              contextSize;
    uint8_t             *pLabel;
    size_t              labelSize;
    uint8_t             *pUserKeyDataOut;
    size_t              userKeyDataOutSize;
    uint8_t             *pUserKeyData;
    size_t              userKeyDataSize;
} key_derivation_vec_t;

/******************************************************************
 * Externs
 ******************************************************************/

/******************************************************************
 * Globals
 ******************************************************************/

static uint8_t test1ContextData[] = { 0x54, 0x45, 0x53, 0x54 };

static uint8_t test1Label[] = { 0x55, 0x53, 0x45, 0x52, 0xF2, 0x4B, 0x45, 0x59 };

static uint8_t test1UserKeyData[] = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                      0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
                                      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                      0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, };

static uint32_t huk[] = { 0x00010203, 0x04050607, 0x08090A0B, 0x0C0D0E0F,
                          0x10111213, 0x14151617, 0x18191A1B, 0x1C1D1E1F, };


static uint8_t test1UserKeyDataOut[] = { 0x2B, 0x05, 0xE1, 0xF8, 0xF0, 0x58, 0x78, 0xAC,
                                         0x41, 0xB0, 0xB5, 0x5D, 0xB0, 0x42, 0x9E, 0x5C, };

static uint8_t HukExpectedDerivation[] = { 0x48, 0x39, 0xb8, 0x68, 0xa2, 0xba, 0x91, 0x08,
                                           0x76, 0x9c, 0x46, 0x92, 0x61, 0xf0, 0x82, 0xe1, };

static key_derivation_vec_t KeyDerTestVec = {
                                             .pContextData = test1ContextData,
                                             .contextSize = sizeof(test1ContextData),
                                             .pLabel = test1Label,
                                             .labelSize = sizeof(test1Label),
                                             .pUserKeyData = test1UserKeyData,
                                             .userKeyDataSize = sizeof(test1UserKeyData),
                                             .pUserKeyDataOut = test1UserKeyDataOut,
                                             .userKeyDataOutSize = sizeof(test1UserKeyDataOut),
};

static key_derivation_vec_t KeyDerWithHukTestVec = {
                                                    .pContextData = test1ContextData,
                                                    .contextSize = sizeof(test1ContextData),
                                                    .pLabel = test1Label,
                                                    .labelSize = sizeof(test1Label),
                                                    .pUserKeyData = (uint8_t *)huk,
                                                    .userKeyDataSize = sizeof(huk),
                                                    .pUserKeyDataOut = HukExpectedDerivation,
                                                    .userKeyDataOutSize = sizeof(HukExpectedDerivation),
};

/******************************************************************
 * Static Prototypes
 ******************************************************************/

static TE_rc_t key_derivation_cmac(void* pContext);

static TE_rc_t key_derivation_with_huk(void* pContext);

/******************************************************************
 * Static functions
 ******************************************************************/

static TE_rc_t key_derivation_cmac(void* pContext)
{
    TE_rc_t res = TE_RC_SUCCESS;
    TE_perfIndex_t cookie = 0;
    CCKeyData_t userKey;
    size_t derivedKeySize;
    key_derivation_vec_t *testVec = NULL;
    uint8_t *pDerivedKey = NULL;
    TE_ASSERT(pContext != NULL);
    testVec = (key_derivation_vec_t *) pContext;

    derivedKeySize = testVec->userKeyDataOutSize;
    TE_ALLOC(pDerivedKey, derivedKeySize);

    /* User's key init */
    /*-----------------*/
    userKey.keySize = testVec->userKeyDataSize;
    userKey.pKey = testVec->pUserKeyData;

    /* Key Derivation */
    /*----------------*/
    cookie = TE_perfOpenNewEntry("key-derivation", "key-derivation-cmac");
    TE_ASSERT(CC_UtilKeyDerivationCMAC(CC_UTIL_USER_KEY,
                                       &userKey,
                                       testVec->pLabel,
                                       testVec->labelSize,
                                       testVec->pContextData,
                                       testVec->contextSize,
                                       pDerivedKey,
                                       derivedKeySize) == CC_OK);
    TE_perfCloseEntry(cookie);

    /* Comparing derived key and expected key data */
    /*---------------------------------------------*/
    TE_ASSERT(memcmp(pDerivedKey, testVec->pUserKeyDataOut, derivedKeySize) == 0);

bail:
    TE_FREE(pDerivedKey);
    return res;
}


static TE_rc_t key_derivation_with_huk(void* pContext)
{
    TE_rc_t res = TE_RC_SUCCESS;
    TE_perfIndex_t cookie = 0;
    key_derivation_vec_t *testVec = NULL;
    uint8_t *derivedKey = NULL;
    uint32_t otpBuff[TEST_OTP_SIZE_IN_WORDS] = { 0 };
    size_t derivedKeySize = 0;
    TE_ASSERT(pContext != NULL);
    testVec = (key_derivation_vec_t *) pContext;

    derivedKeySize = testVec->userKeyDataOutSize;
    TE_ALLOC(derivedKey, derivedKeySize);

    /* Library was initialized in common functions in wrappers.c, so we need to unmap it first */
    Test_Proj_CC_LibFini_Wrap();

    /* Burn OTP with secure lcs */
    TE_ASSERT(Test_ProjBuildAndBurnOtp(otpBuff,
                                       TEST_PROJ_LCS_SECURE,
                                       PROJ_OTP_CHIP_STATE_TEST,
                                       NOT_SD_ENABLE,
                                       FULL_HBK) == 0);

    /* Implicit reboot */

    /* Init library again */
    TE_ASSERT(Test_Proj_CC_LibInit_Wrap() == 0);

    /* Key Derivation with huk*/
    /*------------------------*/
    cookie = TE_perfOpenNewEntry("key-derivation", "key-derivation-huk");
    TE_ASSERT(CC_UtilKeyDerivationCMAC(CC_UTIL_ROOT_KEY,
                                       NULL,
                                       testVec->pLabel,
                                       testVec->labelSize,
                                       testVec->pContextData,
                                       testVec->contextSize,
                                       derivedKey,
                                       derivedKeySize) == CC_OK);
    TE_perfCloseEntry(cookie);

    /* Comparing derived huk and expected key data */
    /*---------------------------------------------*/
    TE_ASSERT(memcmp(derivedKey, testVec->pUserKeyDataOut, derivedKeySize) == 0);

bail:
    TE_FREE(derivedKey);
    return res;
}

/******************************************************************
 * Public
 ******************************************************************/

int TE_init_key_derivation_test(void)
{
    TE_rc_t res = TE_RC_SUCCESS;

    TE_perfEntryInit("key-derivation", "key-derivation-cmac");
    TE_perfEntryInit("key-derivation", "key-derivation-huk");

    TE_ASSERT(TE_registerFlow("key-derivation",
                              "key-derivation-cmac",
                              "",
                              NULL,
                              key_derivation_cmac,
                              NULL,
                              NULL,
                              &KeyDerTestVec) == TE_RC_SUCCESS);

    TE_ASSERT(TE_registerFlow("key-derivation",
                              "key-derivation-huk",
                              "",
                              NULL,
                              key_derivation_with_huk,
                              NULL,
                              NULL,
                              &KeyDerWithHukTestVec) == TE_RC_SUCCESS);

bail:
    return res;
}
