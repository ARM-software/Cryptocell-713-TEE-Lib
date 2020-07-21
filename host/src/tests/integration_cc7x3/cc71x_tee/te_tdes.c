/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include <stdio.h>
#include <stdint.h>
#include "test_engine.h"
#include "cc_des.h"
#include "te_tdes.h"

/******************************************************************
 * Defines
 ******************************************************************/

#define TE_TDES_MAX_OUTPUT_BUFF_SIZE_IN_BYTES           32

/******************************************************************
 * Types
 ******************************************************************/

typedef struct tdesDataVec_t {
    CCDesIv_t                   IV;
    CCDesKey_t                  key;
    CCDesOperationMode_t        operationMode;
    uint8_t                     *pDataIn;
    size_t                      dataInSize;
    uint8_t                     *cipherText;
} tdesDataVec_t;

/******************************************************************
 * Externs
 ******************************************************************/

/******************************************************************
 * Globals
 ******************************************************************/

static uint8_t ecbModePlaintext[] = { 0x54, 0x68, 0x65, 0x20, 0x71, 0x75, 0x66, 0x63 };

static uint8_t ecbModeCiphertext[] = { 0xa8, 0x26, 0xfd, 0x8c, 0xe5, 0x3b, 0x85, 0x5f };

static uint8_t cbcModePlaintext[] = { 0x3b, 0xb7, 0xa7, 0xdb, 0xa3, 0xd5, 0x92, 0x91 };

static uint8_t cbcModeCiphertext[] = { 0x5b, 0x84, 0x24, 0xd2, 0x39, 0x3e, 0x55, 0xa2 };

static tdesDataVec_t tdesEcbTestVec = {
                                       .IV = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },       /* not used in ecb mode */
                                       .key = { { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef },
                                                { 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01 },
                                                { 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23 }, },
                                       .operationMode = CC_DES_ECB_mode,
                                       .pDataIn = ecbModePlaintext,
                                       .dataInSize = sizeof(ecbModePlaintext),
                                       .cipherText = ecbModeCiphertext,
};

static tdesDataVec_t tdesCbcTestVec = {
                                       .IV = { 0xf8, 0xee, 0xe1, 0x35, 0x9c, 0x6e, 0x54, 0x40 },
                                       .key = { { 0xe9, 0xda, 0x37, 0xf8, 0xdc, 0x97, 0x6d, 0x5b },
                                                { 0xb6, 0x8c, 0x04, 0xe3, 0xec, 0x98, 0x20, 0x15 },
                                                { 0xf4, 0x0e, 0x08, 0xb5, 0x97, 0x29, 0xf2, 0x8f }, },
                                       .operationMode = CC_DES_CBC_mode,
                                       .pDataIn = cbcModePlaintext,
                                       .dataInSize = sizeof(cbcModePlaintext),
                                       .cipherText = cbcModeCiphertext,
};

static TE_TestVec_t tdesTestVectors[] = {
                                         { .name = "tdes-ecbmode", .pData = &tdesEcbTestVec, },
                                         { .name = "tdes-cbcmode", .pData = &tdesCbcTestVec, },
};

static TE_TestVecList_t tdesTestVectorList = TE_TEST_VEC(tdesTestVectors);

/******************************************************************
 * Static Prototypes
 ******************************************************************/

/******************************************************************
 * Static functions
 ******************************************************************/

static TE_rc_t tdes_integral_exec(TE_TestVec_t *pTestVec, TE_rc_t *pTestResult);

static TE_rc_t tdes_non_integral_exec(TE_TestVec_t *pTestVec, TE_rc_t *pTestResult);

/******************************************************************
 * Public
 ******************************************************************/
static TE_rc_t tdes_integral_exec(TE_TestVec_t *pTestVec, TE_rc_t *pTestResult)
{
    TE_rc_t res = TE_RC_SUCCESS;
    TE_perfIndex_t cookie = 0;
    tdesDataVec_t* pTdesVec = NULL;
    uint8_t pEncryptDataOut[TE_TDES_MAX_OUTPUT_BUFF_SIZE_IN_BYTES] = { 0 };
    uint8_t pDecryptDataOut[TE_TDES_MAX_OUTPUT_BUFF_SIZE_IN_BYTES] = { 0 };

    if (pTestResult == NULL) {
        res = TE_RC_FAIL;
        TE_LOG_ERROR("Invalid params! (pTestResult == NULL)\n");
        return res;
    }
    TE_ASSERT(pTestVec != NULL);

    pTdesVec = pTestVec->pData;

    ///* Encryption *///
    ///*------------*///
    cookie = TE_perfOpenNewEntry("tdes", "encrypt");
    TE_ASSERT(CC_Des(pTdesVec->IV,
                     &(pTdesVec->key),
                     CC_DES_3_KeysInUse,
                     CC_DES_Encrypt,
                     pTdesVec->operationMode,
                     pTdesVec->pDataIn,
                     pTdesVec->dataInSize,
                     pEncryptDataOut) == CC_OK);
    TE_perfCloseEntry(cookie);

    /* Comparing expected ciphertext and encrypted data */
    /*--------------------------------------------------*/
    TE_ASSERT(memcmp(pEncryptDataOut, pTdesVec->cipherText, pTdesVec->dataInSize) == 0);

    ///* Decryption *///
    ///*------------*///
    cookie = TE_perfOpenNewEntry("tdes", "decrypt");
    TE_ASSERT(CC_Des(pTdesVec->IV,
                     &(pTdesVec->key),
                     CC_DES_3_KeysInUse,
                     CC_DES_Decrypt,
                     pTdesVec->operationMode,
                     pEncryptDataOut,
                     pTdesVec->dataInSize,
                     pDecryptDataOut) == CC_OK);
    TE_perfCloseEntry(cookie);

    /* Comparing planetext and decrypted data */
    /*----------------------------------------*/
    TE_ASSERT(memcmp(pDecryptDataOut, pTdesVec->pDataIn, pTdesVec->dataInSize) == 0);

bail:
    *pTestResult = res;
    return res;
}

static TE_rc_t tdes_non_integral_exec(TE_TestVec_t *pTestVec, TE_rc_t *pTestResult)
{
    TE_rc_t res = TE_RC_SUCCESS;
    TE_perfIndex_t cookie = 0;
    tdesDataVec_t* pTdesVec = NULL;
    uint8_t pEncryptDataOut[TE_TDES_MAX_OUTPUT_BUFF_SIZE_IN_BYTES] = { 0 };
    uint8_t pDecryptDataOut[TE_TDES_MAX_OUTPUT_BUFF_SIZE_IN_BYTES] = { 0 };
    CCDesUserContext_t userContext;

    if (pTestResult == NULL) {
        res = TE_RC_FAIL;
        TE_LOG_ERROR("Invalid params! (pTestResult == NULL)\n");
        return res;
    }
    TE_ASSERT(pTestVec != NULL);

    pTdesVec = pTestVec->pData;

    ///* Encryption *///
    ///*------------*///

    /* Init */
    /*------*/
    cookie = TE_perfOpenNewEntry("tdes", "init");
    CC_DesInit(&userContext,
               pTdesVec->IV,
               &(pTdesVec->key),
               CC_DES_3_KeysInUse,
               CC_DES_Encrypt,
               pTdesVec->operationMode);
    TE_perfCloseEntry(cookie);

    /* Block */
    /*-------*/
    cookie = TE_perfOpenNewEntry("tdes", "block");
    CC_DesBlock(&userContext,
                pTdesVec->pDataIn,
                pTdesVec->dataInSize,
                pEncryptDataOut);
    TE_perfCloseEntry(cookie);

    /* Free */
    /*------*/
    cookie = TE_perfOpenNewEntry("tdes", "free");
    CC_DesFree(&userContext);
    TE_perfCloseEntry(cookie);

    /* Comparing expected ciphertext and encrypted data */
    /*--------------------------------------------------*/
    TE_ASSERT(memcmp(pEncryptDataOut, pTdesVec->cipherText, pTdesVec->dataInSize) == 0);

    ///* Decryption *///
    ///*------------*///

    /* Init */
    /*------*/
    cookie = TE_perfOpenNewEntry("tdes", "init");
    CC_DesInit(&userContext,
               pTdesVec->IV,
               &(pTdesVec->key),
               CC_DES_3_KeysInUse,
               CC_DES_Decrypt,
               pTdesVec->operationMode);
    TE_perfCloseEntry(cookie);

    /* Block */
    /*-------*/
    cookie = TE_perfOpenNewEntry("tdes", "block");
    CC_DesBlock(&userContext,
                pEncryptDataOut,
                pTdesVec->dataInSize,
                pDecryptDataOut);
    TE_perfCloseEntry(cookie);

    /* Free */
    /*------*/
    cookie = TE_perfOpenNewEntry("tdes", "free");
    CC_DesFree(&userContext);
    TE_perfCloseEntry(cookie);

    /* Comparing planetext and decrypted data */
    /*----------------------------------------*/
    TE_ASSERT(memcmp(pDecryptDataOut, pTdesVec->pDataIn, pTdesVec->dataInSize) == 0);

bail:
    *pTestResult = res;
    return res;
}

int TE_init_tdes_test(void)
{
    TE_rc_t res = TE_RC_SUCCESS;

    TE_perfEntryInit("tdes", "encrypt");
    TE_perfEntryInit("tdes", "decrypt");
    TE_perfEntryInit("tdes", "init");
    TE_perfEntryInit("tdes", "block");
    TE_perfEntryInit("tdes", "free");

    /* Tdes integrated test */
    /*----------------------*/
    TE_ASSERT(TE_registerSuite("tdes",
                              "encrypt&decrypt",
                              "integrated",
                              NULL,
                              tdes_integral_exec,
                              NULL,
                              &tdesTestVectorList) == TE_RC_SUCCESS);

    /* Tdes non-integrated test */
    /*--------------------------*/
    TE_ASSERT(TE_registerSuite("tdes",
                               "encrypt&decrypt",
                               "non-integrated",
                               NULL,
                               tdes_non_integral_exec,
                               NULL,
                               &tdesTestVectorList) == TE_RC_SUCCESS);

bail:
    return res;
}
