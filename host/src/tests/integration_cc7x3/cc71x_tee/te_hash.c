/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include <stdio.h>
#include <stdint.h>
#include "test_engine.h"
#include "cc_hash.h"
#include "te_hash.h"

/******************************************************************
 * Defines
 ******************************************************************/

/******************************************************************
 * Types
 ******************************************************************/

typedef struct hashVector_t {
    CCHashOperationMode_t           hashMode;
    uint8_t                         *expectedOutput;
    size_t                          outputSize;
} hashVector_t;

/******************************************************************
 * Externs
 ******************************************************************/

/******************************************************************
 * Globals
 ******************************************************************/

/******************************************************************
 * Static Prototypes
 ******************************************************************/

/* taken from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf */
static uint8_t plaintext1[] = { 0x61, 0x62, 0x63, 0x64, 0x62, 0x63, 0x64, 0x65, 0x63, 0x64, 0x65, 0x66, 0x64, 0x65,
                                0x66, 0x67, 0x65, 0x66, 0x67, 0x68, 0x66, 0x67, 0x68, 0x69, 0x67, 0x68, 0x69, 0x6a,
                                0x68, 0x69, 0x6a, 0x6b, 0x69, 0x6a, 0x6b, 0x6c, 0x6a, 0x6b, 0x6c, 0x6d, 0x6b, 0x6c,
                                0x6d, 0x6e, 0x6c, 0x6d, 0x6e, 0x6f, 0x6d, 0x6e, 0x6f, 0x70, 0x6e, 0x6f, 0x70, 0x71, };

/* taken from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512.pdf */
static uint8_t plaintext2[] = { 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
                                0x68, 0x69, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x64, 0x65, 0x66, 0x67,
                                0x68, 0x69, 0x6a, 0x6b, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x66, 0x67,
                                0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e,
                                0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e,
                                0x6f, 0x70, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x6b, 0x6c, 0x6d, 0x6e,
                                0x6f, 0x70, 0x71, 0x72, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x6d, 0x6e,
                                0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, };

/* SHA1 Data */
/*-----------*/
static uint8_t sha1ExpectedOutput[] = { 0x84, 0x98, 0x3E, 0x44, 0x1C,
                                        0x3B, 0xD2, 0x6E, 0xBA, 0xAE,
                                        0x4A, 0xA1, 0xF9, 0x51, 0x29,
                                        0xE5, 0xE5, 0x46, 0x70, 0xF1, };

static hashVector_t sha1Vector = {
                                  .hashMode = CC_HASH_SHA1_mode,
                                  .expectedOutput = sha1ExpectedOutput,
                                  .outputSize = CC_HASH_SHA1_DIGEST_SIZE_IN_BYTES,
};

/* SHA224 Data */
/*-------------*/
static uint8_t sha224ExpectedOutput[] = { 0x75, 0x38, 0x8B, 0x16, 0x51, 0x27, 0x76,
                                          0xCC, 0x5D, 0xBA, 0x5D, 0xA1, 0xFD, 0x89,
                                          0x01, 0x50, 0xB0, 0xC6, 0x45, 0x5C, 0xB4,
                                          0xF5, 0x8B, 0x19, 0x52, 0x52, 0x25, 0x25, };

static hashVector_t sha224Vector = {
                                    .hashMode = CC_HASH_SHA224_mode,
                                    .expectedOutput = sha224ExpectedOutput,
                                    .outputSize = CC_HASH_SHA224_DIGEST_SIZE_IN_BYTES,
};

/* SHA256 Data */
/*-------------*/
static uint8_t sha256ExpectedOutput[] = { 0x24, 0x8D, 0x6A, 0x61, 0xD2, 0x06, 0x38, 0xB8,
                                          0xE5, 0xC0, 0x26, 0x93, 0x0C, 0x3E, 0x60, 0x39,
                                          0xA3, 0x3C, 0xE4, 0x59, 0x64, 0xFF, 0x21, 0x67,
                                          0xF6, 0xEC, 0xED, 0xD4, 0x19, 0xDB, 0x06, 0xC1, };

static hashVector_t sha256Vector = {
                                    .hashMode = CC_HASH_SHA256_mode,
                                    .expectedOutput = sha256ExpectedOutput,
                                    .outputSize = CC_HASH_SHA256_DIGEST_SIZE_IN_BYTES,
};

/* SHA384 Data */
/*-------------*/
static uint8_t sha384ExpectedOutput[] = { 0x09, 0x33, 0x0C, 0x33, 0xF7, 0x11, 0x47, 0xE8, 0x3D, 0x19, 0x2F, 0xC7,
                                          0x82, 0xCD, 0x1B, 0x47, 0x53, 0x11, 0x1B, 0x17, 0x3B, 0x3B, 0x05, 0xD2,
                                          0x2F, 0xA0, 0x80, 0x86, 0xE3, 0xB0, 0xF7, 0x12, 0xFC, 0xC7, 0xC7, 0x1A,
                                          0x55, 0x7E, 0x2D, 0xB9, 0x66, 0xC3, 0xE9, 0xFA, 0x91, 0x74, 0x60, 0x39, };

static hashVector_t sha384Vector = {
                                    .hashMode = CC_HASH_SHA384_mode,
                                    .expectedOutput = sha384ExpectedOutput,
                                    .outputSize = CC_HASH_SHA384_DIGEST_SIZE_IN_BYTES,
};

/* SHA512 Data */
/*-------------*/
static uint8_t sha512ExpectedOutput[] = { 0x8E, 0x95, 0x9B, 0x75, 0xDA, 0xE3, 0x13, 0xDA, 0x8C, 0xF4, 0xF7, 0x28, 0x14, 0xFC, 0x14, 0x3F,
                                          0x8F, 0x77, 0x79, 0xC6, 0xEB, 0x9F, 0x7F, 0xA1, 0x72, 0x99, 0xAE, 0xAD, 0xB6, 0x88, 0x90, 0x18,
                                          0x50, 0x1D, 0x28, 0x9E, 0x49, 0x00, 0xF7, 0xE4, 0x33, 0x1B, 0x99, 0xDE, 0xC4, 0xB5, 0x43, 0x3A,
                                          0xC7, 0xD3, 0x29, 0xEE, 0xB6, 0xDD, 0x26, 0x54, 0x5E, 0x96, 0xE5, 0x5B, 0x87, 0x4B, 0xE9, 0x09, };

static hashVector_t sha512Vector = {
                                    .hashMode = CC_HASH_SHA512_mode,
                                    .expectedOutput = sha512ExpectedOutput,
                                    .outputSize = CC_HASH_SHA512_DIGEST_SIZE_IN_BYTES,
};

/* MD5 Data */
/*----------*/
static uint8_t md5ExpectedOutput[] = { 0x03, 0xdd, 0x88, 0x07, 0xa9, 0x31, 0x75, 0xfb,
                                       0x06, 0x2d, 0xfb, 0x55, 0xdc, 0x7d, 0x35, 0x9c, };

static hashVector_t md5Vector = {
                                 .hashMode = CC_HASH_MD5_mode,
                                 .expectedOutput = md5ExpectedOutput,
                                 .outputSize = CC_HASH_MD5_DIGEST_SIZE_IN_BYTES,
};

static TE_TestVec_t vectorsHASH[] = { { .name = "sha1-20bytes-digest", .pData = &sha1Vector, },
                                      { .name = "sha224-28bytes-digest", .pData = &sha224Vector, },
                                      { .name = "sha256-32bytes-digest", .pData = &sha256Vector, },
                                      { .name = "sha384-48bytes-digest", .pData = &sha384Vector, },
                                      { .name = "sha512-64bytes-digest", .pData = &sha512Vector, },
                                      { .name = "md5-16bytes-digest", .pData = &md5Vector, },
};

static TE_TestVecList_t testVecListHASH = TE_TEST_VEC(vectorsHASH);

/******************************************************************
 * Static functions
 ******************************************************************/

static TE_rc_t hash_execute(TE_TestVec_t *pTestVec, TE_rc_t *pTestResult);

/******************************************************************
 * Public
 ******************************************************************/
static TE_rc_t hash_execute(TE_TestVec_t *pTestVec, TE_rc_t *pTestResult)
{
    TE_rc_t res = TE_RC_SUCCESS;
    TE_perfIndex_t cookie = 0;
    hashVector_t* testVec = NULL;
    uint8_t* pPlaintext = NULL;
    size_t plaintextSize = 0;
    CCHashOperationMode_t hashMode = 0;
    CCHashResultBuf_t resBuff = { 0 };

    if (pTestResult == NULL) {
        res = TE_RC_FAIL;
        TE_LOG_ERROR("Invalid params! (pTestResult == NULL)\n");
        return res;
    }
    TE_ASSERT(pTestVec != NULL);

    testVec = pTestVec->pData;
    hashMode = testVec->hashMode;

    if ((hashMode == CC_HASH_SHA1_mode) || (hashMode == CC_HASH_SHA224_mode)
                    || (hashMode == CC_HASH_SHA256_mode)) {
        pPlaintext = plaintext1;
        plaintextSize = sizeof(plaintext1);
    } else if ((hashMode == CC_HASH_SHA384_mode) || (hashMode == CC_HASH_SHA512_mode)
                    || (hashMode == CC_HASH_MD5_mode)) {
        pPlaintext = plaintext2;
        plaintextSize = sizeof(plaintext2);
    } else {
        TE_LOG_ERROR("Invalid hash mode!");
        res = TE_RC_FAIL;
        goto bail;
    }

    /* Hashing */
    /*---------*/
    cookie = TE_perfOpenNewEntry("hash", "hash");
    TE_ASSERT(CC_Hash(hashMode, pPlaintext, plaintextSize, resBuff) == CC_OK);
    TE_perfCloseEntry(cookie);

    /* Verifying hashed data is as expected */
    /*--------------------------------------*/
    TE_ASSERT(memcmp(resBuff, testVec->expectedOutput, testVec->outputSize) == 0);

bail:
    *pTestResult = res;
    return res;
}

int TE_init_hash_test(void)
{
    TE_rc_t res = TE_RC_SUCCESS;

    TE_perfEntryInit("hash", "hash");

    TE_ASSERT(TE_registerSuite("hash",
                              "hash&verify",
                              "",
                              NULL,
                              hash_execute,
                              NULL,
                              &testVecListHASH) == TE_RC_SUCCESS);

bail:
    return res;
}
