/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include <stdio.h>
#include <stdint.h>
#include "test_engine.h"
#include "cc_aesgcm.h"
#include "te_gcm.h"

/******************************************************************
 * Defines
 ******************************************************************/
#define GCM_TV_MAX_DATA_SIZE    64
#define GCM_TV_MAX_TAG_SIZE    16

/******************************************************************
 * Types
 ******************************************************************/
typedef struct GcmVector_zero_key_iv_no_adata_no_data_t{
    CCAesGcmKey_t GCM_Key;
    CCAesGcmKeySize_t keySize;
    uint8_t pIV[GCM_TV_MAX_DATA_SIZE];
    size_t ivSize;
    uint8_t AdataIn[GCM_TV_MAX_DATA_SIZE];
    size_t AdataSize;
    uint8_t dataIn[GCM_TV_MAX_DATA_SIZE];
    size_t dataSize;
    uint8_t tagSize;
    uint8_t dataRef[GCM_TV_MAX_DATA_SIZE];
    uint8_t dataOutEncrypt[GCM_TV_MAX_DATA_SIZE];
    uint8_t dataOutDecrypt[GCM_TV_MAX_DATA_SIZE];
    uint8_t tagRef[GCM_TV_MAX_TAG_SIZE];
    uint8_t tagInOut[GCM_TV_MAX_TAG_SIZE];
} GcmVector_t;


/******************************************************************
 * Externs
 ******************************************************************/

/******************************************************************
 * Globals
 ******************************************************************/

/* The Galois/Counter Mode of Operation (GCM) David A. McGrew, John Viega
 * - AES test vectors - test case 18 */
static GcmVector_t gcm_testcase_vector = {
    /* CCAesGcmKey_t */
    .GCM_Key = {0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
            0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08},
    .keySize = CC_AESGCM_Key256BitSize,
    /* ivSize */
    .pIV = {0x93, 0x13, 0x22, 0x5d, 0xf8, 0x84, 0x06, 0xe5, 0x55, 0x90, 0x9c, 0x5a, 0xff, 0x52, 0x69, 0xaa,
            0x6a, 0x7a, 0x95, 0x38, 0x53, 0x4f, 0x7d, 0xa1, 0xe4, 0xc3, 0x03, 0xd2, 0xa3, 0x18, 0xa7, 0x28,
            0xc3, 0xc0, 0xc9, 0x51, 0x56, 0x80, 0x95, 0x39, 0xfc, 0xf0, 0xe2, 0x42, 0x9a, 0x6b, 0x52, 0x54,
            0x16, 0xae, 0xdb, 0xf5, 0xa0, 0xde, 0x6a, 0x57, 0xa6, 0x37, 0xb3, 0x9b},
    .ivSize = 60,
    /* AData */
    .AdataIn = {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
            0xab, 0xad, 0xda, 0xd2},
    .AdataSize = 20,
    /* Data */
    .dataIn = {0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
               0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
               0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
               0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39},
    .dataSize = 60,
    .tagSize = 16,
    /* Expected results */
    .dataRef = {0x5a, 0x8d, 0xef, 0x2f, 0x0c, 0x9e, 0x53, 0xf1, 0xf7, 0x5d, 0x78, 0x53, 0x65, 0x9e, 0x2a, 0x20,
            0xee, 0xb2, 0xb2, 0x2a, 0xaf, 0xde, 0x64, 0x19, 0xa0, 0x58, 0xab, 0x4f, 0x6f, 0x74, 0x6b, 0xf4,
            0x0f, 0xc0, 0xc3, 0xb7, 0x80, 0xf2, 0x44, 0x45, 0x2d, 0xa3, 0xeb, 0xf1, 0xc5, 0xd8, 0x2c, 0xde,
            0xa2, 0x41, 0x89, 0x97, 0x20, 0x0e, 0xf8, 0x2e, 0x44, 0xae, 0x7e, 0x3f},
    /* Output */
    .dataOutEncrypt = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
    .dataOutDecrypt = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
    /* Expected tag */
    .tagRef = {0xa4, 0x4a, 0x82, 0x66, 0xee, 0x1c, 0x8e, 0xb0, 0xc8, 0xb5, 0xd4, 0xcf, 0x5a, 0xe9, 0xf1, 0x9a},
    /* output tag */
    .tagInOut = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
};


/******************************************************************
 * Static Prototypes
 ******************************************************************/
static TE_rc_t gcm_prepare(void *pContext);
static TE_rc_t gcm_execute(void *pContext);
static TE_rc_t gcm_verify(void *pContext);
static TE_rc_t gcm_clean(void *pContext);

/******************************************************************
 * Static functions
 ******************************************************************/
static TE_rc_t gcm_prepare(void *pContext)
{
    TE_rc_t res = TE_RC_SUCCESS;
    TE_UNUSED(pContext);

    goto bail;
bail:
    return res;
}

static TE_rc_t gcm_execute(void *pContext)
{
    TE_rc_t res = TE_RC_SUCCESS;
    TE_perfIndex_t cookie;
    GcmVector_t *gcm_vec = (GcmVector_t *)pContext;

    cookie = TE_perfOpenNewEntry("gcm", "encrpyt");
    /* test GCM integrated API encrypt */
    TE_ASSERT( CC_AesGcm(CC_AES_ENCRYPT,
                gcm_vec->GCM_Key,
                gcm_vec->keySize,
                gcm_vec->pIV,
                gcm_vec->ivSize,
                gcm_vec->AdataIn,
                gcm_vec->AdataSize,
                gcm_vec->dataIn,
                gcm_vec->dataSize,
                gcm_vec->dataOutEncrypt,
                gcm_vec->tagSize,
                gcm_vec->tagInOut) == CC_OK);

    TE_perfCloseEntry(cookie);

    cookie = TE_perfOpenNewEntry("gcm", "decrypt");
    /* test GCM integrated API decrypt */
    TE_ASSERT( CC_AesGcm(CC_AES_DECRYPT,
                gcm_vec->GCM_Key,
                gcm_vec->keySize,
                gcm_vec->pIV,
                gcm_vec->ivSize,
                gcm_vec->AdataIn,
                gcm_vec->AdataSize,
                gcm_vec->dataOutEncrypt,
                gcm_vec->dataSize,
                gcm_vec->dataOutDecrypt,
                gcm_vec->tagSize,
                gcm_vec->tagRef) == CC_OK);


    TE_perfCloseEntry(cookie);

    goto bail;

bail:
    return res;
}

static TE_rc_t gcm_verify(void *pContext)
{
    TE_rc_t res = TE_RC_SUCCESS;
    GcmVector_t *gcm_vec = (GcmVector_t *)pContext;

    if (gcm_vec->dataSize != 0) {
        TE_ASSERT( memcmp((uint8_t *)&(gcm_vec->dataOutDecrypt), (uint8_t *)&(gcm_vec->dataIn), gcm_vec->dataSize) == 0);
        TE_ASSERT( memcmp((uint8_t *)&(gcm_vec->dataOutEncrypt), (uint8_t *)&(gcm_vec->dataRef), gcm_vec->dataSize) == 0);
    }

    TE_ASSERT( memcmp((uint8_t *)&(gcm_vec->tagInOut), (uint8_t *)&(gcm_vec->tagRef), gcm_vec->tagSize) == 0);

    goto bail;
bail:
    return res;
}

static TE_rc_t gcm_clean(void *pContext)
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
int TE_init_gcm_test(void)
{
    TE_rc_t res = TE_RC_SUCCESS;

    TE_perfEntryInit("gcm", "encrpyt");
    TE_perfEntryInit("gcm", "decrypt");

    TE_ASSERT(TE_registerFlow("gcm",
                               "gcm_testcase",
                               "encrypt_decrypt",
                               gcm_prepare,
                               gcm_execute,
                               gcm_verify,
                               gcm_clean,
                               &gcm_testcase_vector) == TE_RC_SUCCESS);

    goto bail;

bail:
	return res;
}

