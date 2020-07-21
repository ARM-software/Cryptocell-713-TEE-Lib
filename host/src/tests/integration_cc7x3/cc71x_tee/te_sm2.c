/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include <stdio.h>
#include <stdint.h>

/* Test engine and testAL headers*/
#include "test_engine.h"
#include "test_pal_mem.h"

/* CryptoCell headers*/
#include "cc_sm2.h"
#include "cc_ecpki_domain_sm2.h"
#include "cc_ecpki_build.h"
#include "te_sm2.h"


/******************************************************************
 * Defines
 ******************************************************************/
#define SM2_TV_MAX_DATA_SIZE    14
#define SM2_TV_DIGEST_SIZE      32

/******************************************************************
 * Enums
 ******************************************************************/

/******************************************************************
 * Types
 ******************************************************************/

typedef struct Sm2SignVector_t{
    /* Input */
    const char* id;
    size_t      idSize;
    uint8_t     privateKeyInBytes[CC_SM2_MODULE_LENGTH_IN_BYTES];
    uint8_t     publicKeyInBytesX[CC_SM2_MODULE_LENGTH_IN_BYTES];
    uint8_t     publicKeyInBytesY[CC_SM2_MODULE_LENGTH_IN_BYTES];
    uint8_t     randomSeed[SM2_TV_DIGEST_SIZE];
    uint8_t     dataIn[SM2_TV_MAX_DATA_SIZE];
    /* Intermediate results and their sizes */
    CCEcpkiUserPrivKey_t    privKey;
    CCEcpkiUserPublKey_t    pubKey;
    size_t      privateKeySize;
    size_t      pubKeySize;
    uint32_t    msgDigest[CC_SM3_RESULT_SIZE_IN_WORDS];
    size_t      msgDigestSizeW;

    /* Output */
    uint8_t     dataOut[2 * SM2_TV_DIGEST_SIZE];
    size_t      dataInSize;
    /* Reference */
    uint32_t    msgDigestRef[CC_SM3_RESULT_SIZE_IN_WORDS];
    size_t      msgDigestRefSizeW;
    uint8_t     dataRef[2 * SM2_TV_DIGEST_SIZE];
    size_t      dataRefSize;
}Sm2SignVector_t;
/******************************************************************
 * Externs
 ******************************************************************/

/******************************************************************
 * Globals
 ******************************************************************/


static Sm2SignVector_t sm2_vector = {
    /* Input */
    .id = "1234567812345678",
    .idSize = 16,
    .privateKeyInBytes = { /*3945208F 7B2144B1 3F36E38A C6D39F95 88939369 2860B51A 42FB81EF 4DF7C5B8 */
            0x39, 0x45, 0x20, 0x8F, 0x7B, 0x21, 0x44, 0xB1,
            0x3F, 0x36, 0xE3, 0x8A, 0xC6, 0xD3, 0x9F, 0x95,
            0x88, 0x93, 0x93, 0x69, 0x28, 0x60, 0xB5, 0x1A,
            0x42, 0xFB, 0x81, 0xEF, 0x4D, 0xF7, 0xC5, 0xB8
    },
    .privateKeySize = 32,
    .publicKeyInBytesX = { /*09F9DF31 1E5421A1 50DD7D16 1E4BC5C6 72179FAD 1833FC07 6BB08FF3 56F35020*/
            0x09, 0xF9, 0xDF, 0x31, 0x1E, 0x54, 0x21, 0xA1,
            0x50, 0xDD, 0x7D, 0x16, 0x1E, 0x4B, 0xC5, 0xC6,
            0x72, 0x17, 0x9F, 0xAD, 0x18, 0x33, 0xFC, 0x07,
            0x6B, 0xB0, 0x8F, 0xF3, 0x56, 0xF3, 0x50, 0x20
    },
    .publicKeyInBytesY = { /*CCEA490C E26775A5 2DC6EA71 8CC1AA60 0AED05FB F35E084A 6632F607 2DA9AD13*/
            0xCC, 0xEA, 0x49, 0x0C, 0xE2, 0x67, 0x75, 0xA5,
            0x2D, 0xC6, 0xEA, 0x71, 0x8C, 0xC1, 0xAA, 0x60,
            0x0A, 0xED, 0x05, 0xFB, 0xF3, 0x5E, 0x08, 0x4A,
            0x66, 0x32, 0xF6, 0x07, 0x2D, 0xA9, 0xAD, 0x13
    },
    .pubKeySize = 65, /* 32 bytes for x, 32 bytes for y, 1 byte for compression flag */
    .dataIn = { /*6D65737361676520646967657374*/
            0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20,
            0x64, 0x69, 0x67, 0x65, 0x73, 0x74
    },
    .dataInSize = 14,
    .msgDigestSizeW = CC_SM3_RESULT_SIZE_IN_WORDS,
    .randomSeed ={ /*59276E27 D506861A 16680F3A D9C02DCC EF3CC1FA 3CDBE4CE 6D54B80D EAC1BC21*/
            0x59, 0x27, 0x6E, 0x27, 0xD5, 0x06, 0x86, 0x1A,
            0x16, 0x68, 0x0F, 0x3A, 0xD9, 0xC0, 0x2D, 0xCC,
            0xEF, 0x3C, 0xC1, 0xFA, 0x3C, 0xDB, 0xE4, 0xCE,
            0x6D, 0x54, 0xB8, 0x0D, 0xEA, 0xC1, 0xBC, 0x21
    },

    /* Expected intermediate results */
    .msgDigestRef = { /*F0B43E94 BA45ACCA ACE692ED 534382EB 17E6AB5A 19CE7B31 F4486FDF C0D28640 - big endian*/
            0x943EB4F0, 0xCAAC45BA, 0xED92E6AC, 0xEB824353,
            0x5AABE617, 0x317BCE19, 0xDF6F48F4, 0x4086D2C0
    },
    .msgDigestRefSizeW = CC_SM3_RESULT_SIZE_IN_WORDS,

    /* Expected results */
    .dataRef = { /* R - F5A03B06 48D2C463 0EEAC513 E1BB81A1 5944DA38 27D5B741 43AC7EAC EEE720B3*/
            0xF5, 0xA0, 0x3B, 0x06, 0x48, 0xD2, 0xC4, 0x63,
            0x0E, 0xEA, 0xC5, 0x13, 0xE1, 0xBB, 0x81, 0xA1,
            0x59, 0x44, 0xDA, 0x38, 0x27, 0xD5, 0xB7, 0x41,
            0x43, 0xAC, 0x7E, 0xAC, 0xEE, 0xE7, 0x20, 0xB3,
            /* S - B1B6AA29 DF212FD8 763182BC 0D421CA1 BB9038FD 1F7F42D4 840B69C4 85BBC1AA*/
            0xB1, 0xB6, 0xAA, 0x29, 0xDF, 0x21, 0x2F, 0xD8,
            0x76, 0x31, 0x82, 0xBC, 0x0D, 0x42, 0x1C, 0xA1,
            0xBB, 0x90, 0x38, 0xFD, 0x1F, 0x7F, 0x42, 0xD4,
            0x84, 0x0B, 0x69, 0xC4, 0x85, 0xBB, 0xC1, 0xAA
    },
    .dataRefSize = 2 * SM2_TV_DIGEST_SIZE,
};

/******************************************************************
 * Static Prototypes
 ******************************************************************/
static TE_rc_t sm2_prepare(void *pContext);
static TE_rc_t sm2_execute_sign(void *pContext);
static TE_rc_t sm2_verify_sign(void *pContext);
static TE_rc_t sm2_clean(void *pContext);

/******************************************************************
 * Static functions
 ******************************************************************/
static CCError_t Tests_RndGenerateVectorConst( void           *rngState_vptr,    /*in*/
                                      uint8_t        *out_ptr,          /*out*/
                                      size_t         outSizeBytes)      /*in*/
{
    CCError_t  error = CC_OK;
    uint8_t* pData = (uint8_t*)rngState_vptr;

    if (outSizeBytes != 32)
        return 1;

    memcpy (out_ptr, pData, outSizeBytes);
    return error;
}


static TE_rc_t sm2_prepare(void *pContext)
{
    CCEcpkiBuildTempData_t tmpData;
    TE_rc_t res = TE_RC_SUCCESS;
    const CCEcpkiDomain_t* pSm2Domain = CC_EcpkiGetSm2Domain();
    Sm2SignVector_t *sm2_vec = (Sm2SignVector_t *)pContext;
    uint8_t publicKeyInBytes[ 2 * CC_SM2_MODULE_LENGTH_IN_BYTES + 1 /*1 bit for compression flag*/];

    /* Set the public key data in 1 array:  compression flag || x || y */
    publicKeyInBytes[0] = CC_EC_PointUncompressed;
    memcpy(publicKeyInBytes + 1, sm2_vec->publicKeyInBytesX, sm2_vec->pubKeySize/2);
    memcpy(publicKeyInBytes + 1 + sm2_vec->pubKeySize/2,
                  sm2_vec->publicKeyInBytesY, sm2_vec->pubKeySize/2);


    /*
     * Build public and private keys -
     * input the keys as bytes array (public key:  compression flag || x || y)
     * output the keys as structures, which are used as inputs to all SM2 or ECC operations.
     * The public key is needed for both SIGN and VERIFY operations.
     * The private key is needed only for SIGN operations.
     * */
    TE_ASSERT_PASS(CC_EcpkiPublKeyBuildAndCheck (pSm2Domain, publicKeyInBytes, sm2_vec->pubKeySize,
                                        0/*CheckPointersAndSizesOnly*/, &sm2_vec->pubKey, &tmpData) , CC_OK);

    TE_ASSERT_PASS(CC_EcpkiPrivKeyBuild(pSm2Domain, sm2_vec->privateKeyInBytes,  sm2_vec->privateKeySize, &sm2_vec->privKey) , CC_OK);

    goto bail;
bail:
    return res;
}

static TE_rc_t sm2_execute_sign(void *pContext)
{
    TE_rc_t res = TE_RC_SUCCESS;
    TE_perfIndex_t cookie;
    Sm2SignVector_t *sm2_vec = (Sm2SignVector_t *)pContext;
    uint8_t *workBuff = NULL;
    size_t workBuffSize;

    /* Start performance measurement */
    cookie = TE_perfOpenNewEntry("sm2", "sign");

    workBuffSize = 2 + CC_SM2_MODULE_LENGTH_IN_BYTES*4 + CC_SM2_ORDER_LENGTH_IN_BYTES*2 +
            sm2_vec->idSize + sm2_vec->dataInSize;
    workBuff = Test_PalMalloc(workBuffSize);
    TE_ASSERT(workBuff);

    /* Test SM2 signature integrated API */
    TE_ASSERT_PASS( CC_Sm2ComputeMessageDigest(&sm2_vec->pubKey,
                                          sm2_vec->id, sm2_vec->idSize,
                                          sm2_vec->dataIn, sm2_vec->dataInSize,
                                          workBuff, workBuffSize,
                                          sm2_vec->msgDigest, &(sm2_vec->msgDigestSizeW) ) , CC_OK);


    TE_ASSERT_PASS( CC_Sm2Sign ( Tests_RndGenerateVectorConst,
                            (void *)sm2_vec->randomSeed,
                            &sm2_vec->privKey,
                            sm2_vec->msgDigest,
                            sm2_vec->msgDigestSizeW,
                            sm2_vec->dataOut,
                            &sm2_vec->dataRefSize), CC_OK);

    /* Finish performance measurement */
    TE_perfCloseEntry(cookie);

bail:
    if (workBuff != NULL) {
        Test_PalFree(workBuff);
        workBuff = NULL;
    }

    return res;
}

static TE_rc_t sm2_verify_sign(void *pContext)
{
    TE_rc_t res = TE_RC_SUCCESS;
    Sm2SignVector_t *sm2_vec = (Sm2SignVector_t *)pContext;

    /* Verify intermediate result */
    TE_ASSERT( sm2_vec->msgDigestSizeW == sm2_vec->msgDigestRefSizeW);
    TE_ASSERT( memcmp((uint8_t *)&(sm2_vec->msgDigest), (uint8_t *)&(sm2_vec->msgDigestRef), sizeof(uint32_t)*sm2_vec->msgDigestRefSizeW) == 0);

    /* Verify result */
    TE_ASSERT( memcmp((uint8_t *)&(sm2_vec->dataOut), (uint8_t *)&(sm2_vec->dataRef), sm2_vec->dataRefSize) == 0);

    goto bail;
bail:
    return res;
}

static TE_rc_t sm2_execute_verify(void *pContext)
{
    TE_rc_t res = TE_RC_SUCCESS;
    TE_perfIndex_t cookie;
    Sm2SignVector_t *sm2_vec = (Sm2SignVector_t *)pContext;
    uint8_t *workBuff = NULL;
    size_t workBuffSize;

    /* Start performance measurement */
    cookie = TE_perfOpenNewEntry("sm2", "verify");

    workBuffSize = 2 + CC_SM2_MODULE_LENGTH_IN_BYTES*4 + CC_SM2_ORDER_LENGTH_IN_BYTES*2 +
            sm2_vec->idSize + sm2_vec->dataInSize;
    workBuff = Test_PalMalloc(workBuffSize);
    TE_ASSERT(workBuff);

    /* Test SM2 verification integrated API */
    TE_ASSERT_PASS( CC_Sm2ComputeMessageDigest(&sm2_vec->pubKey,
                                          sm2_vec->id, sm2_vec->idSize,
                                          sm2_vec->dataIn, sm2_vec->dataInSize,
                                          workBuff, workBuffSize,
                                          sm2_vec->msgDigest /* output */, &(sm2_vec->msgDigestSizeW) ) , CC_OK);


    TE_ASSERT_PASS( CC_Sm2Verify(&sm2_vec->pubKey,
                                 sm2_vec->dataRef,
                                 sm2_vec->dataRefSize,
                                 sm2_vec->msgDigest,
                                 sm2_vec->msgDigestRefSizeW), CC_OK);

    /* Finish performance measurement */
    TE_perfCloseEntry(cookie);

bail:
    if (workBuff != NULL) {
        Test_PalFree(workBuff);
        workBuff = NULL;
    }

    return res;
}
static TE_rc_t sm2_clean(void *pContext)
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
int TE_init_sm2_test(void)
{
    TE_rc_t res = TE_RC_SUCCESS;

    TE_perfEntryInit("sm2", "sign");
    TE_perfEntryInit("sm2", "verify");

    TE_ASSERT(TE_registerFlow("sm2",
                              "sign",
                              "none",
                              sm2_prepare,
                              sm2_execute_sign,
                              sm2_verify_sign,
                              sm2_clean,
                              &sm2_vector) == TE_RC_SUCCESS);

    TE_ASSERT(TE_registerFlow("sm2",
                              "verify",
                              "none",
                              sm2_prepare,
                              sm2_execute_verify,
                              sm2_clean, /* No results to verify */
                              sm2_clean,
                              &sm2_vector) == TE_RC_SUCCESS);
    goto bail;

bail:
    return res;
}

