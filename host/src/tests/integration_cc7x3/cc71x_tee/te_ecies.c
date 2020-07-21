/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include <stdio.h>
#include <stdint.h>
#include "test_engine.h"
#include "cc_ecpki_domain.h"
#include "cc_ecpki_ecies.h"
#include "cc_ecpki_kg.h"
#include "te_ecies.h"

/******************************************************************
 * Defines
 ******************************************************************/

#define TE_ECIES_KEY_DATA_MAX_LEN_BYTES                200
#define TE_ECIES_KEY_DATA_LEN_IN_BYTES                 128

/******************************************************************
 * Types
 ******************************************************************/

typedef struct eciesDataVector_t {
    CCEcpkiDomainID_t                domainId;
    CCKdfDerivFuncMode_t             kDerivFuncMode;
    CCKdfHashOpMode_t                kdfHashMode;
    uint32_t                         isSingleHashMode;
} eciesDataVector_t;

/******************************************************************
 * Externs
 ******************************************************************/

extern CCRndState_t *pRndState_proj;
extern CCRndGenerateVectWorkFunc_t pRndFunc_proj;

/******************************************************************
 * Globals
 ******************************************************************/

static eciesDataVector_t teEciesTestVec = {
                                           .domainId = CC_ECPKI_DomainID_secp256r1,
                                           .kDerivFuncMode = CC_KDF_ISO18033_KDF2_DerivMode,
                                           .kdfHashMode = CC_KDF_HASH_SHA1_mode,
                                           .isSingleHashMode = CC_FALSE,
};

/******************************************************************
 * Static Prototypes
 ******************************************************************/

static TE_rc_t ecies_exec(void* pContext);

/******************************************************************
 * Static functions
 ******************************************************************/

static TE_rc_t ecies_exec(void* pContext)
{
    TE_perfIndex_t cookie = 0;
    TE_rc_t res = TE_RC_SUCCESS;
    eciesDataVector_t* pEciesTestVec = NULL;
    const CCEcpkiDomain_t *pDomain;
    CCEcpkiUserPrivKey_t userPrivKey;
    CCEcpkiUserPublKey_t userPublKey;
    CCEcpkiKgTempData_t tempBuff;
    CCEciesTempData_t eciesTempBuff;
    uint8_t pSecretKeyIn[TE_ECIES_KEY_DATA_MAX_LEN_BYTES] = { 0 };
    uint8_t pSecretKeyOut[TE_ECIES_KEY_DATA_MAX_LEN_BYTES] = { 0 };
    uint32_t pCipherData[2 * CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 1] = { 0 };
    size_t cipherDataSize = sizeof(pCipherData);

    TE_ASSERT(pContext != NULL);

    pEciesTestVec = (eciesDataVector_t *)pContext;

    /* Obtain domain pointer */
    /*-----------------------*/
    cookie = TE_perfOpenNewEntry("ecies", "get-domain");
    pDomain = CC_EcpkiGetEcDomain(pEciesTestVec->domainId);
    TE_perfCloseEntry(cookie);

    TE_ASSERT(pDomain != NULL);

    /* Generating users public and private keys */
    /*------------------------------------------*/
    cookie = TE_perfOpenNewEntry("ecies", "key-pair-gen");
    TE_ASSERT(CC_EcpkiKeyPairGenerate(pRndFunc_proj,
                                      pRndState_proj,
                                      pDomain,
                                      &userPrivKey,
                                      &userPublKey,
                                      &tempBuff,
                                      NULL) == CC_OK);
    TE_perfCloseEntry(cookie);

    /* Encrypting */
    /*------------*/
    cookie = TE_perfOpenNewEntry("ecies", "encrypt");
    TE_ASSERT(EciesKemEncrypt(&userPublKey,
                              pEciesTestVec->kDerivFuncMode,
                              pEciesTestVec->kdfHashMode,
                              pEciesTestVec->isSingleHashMode,
                              NULL,
                              NULL,
                              pSecretKeyIn,
                              sizeof(pSecretKeyIn),
                              (uint8_t*)pCipherData,
                              &cipherDataSize,
                              &eciesTempBuff,
                              pRndFunc_proj,
                              pRndState_proj,
                              NULL) == CC_OK);
    TE_perfCloseEntry(cookie);

    /* Decrypting */
    /*------------*/
    cookie = TE_perfOpenNewEntry("ecies", "decrypt");
    TE_ASSERT(CC_EciesKemDecrypt(&userPrivKey,
                                 pEciesTestVec->kDerivFuncMode,
                                 pEciesTestVec->kdfHashMode,
                                 pEciesTestVec->isSingleHashMode,
                                 (uint8_t*)pCipherData,
                                 cipherDataSize,
                                 pSecretKeyOut,
                                 sizeof(pSecretKeyOut),
                                 &eciesTempBuff) == CC_OK);
    TE_perfCloseEntry(cookie);

    /* Comparing secret keys */
    /*-----------------------*/
    TE_ASSERT(memcmp(pSecretKeyIn, pSecretKeyOut, TE_ECIES_KEY_DATA_LEN_IN_BYTES) == 0);

    bail:
    return res;
}

/******************************************************************
 * Public
 ******************************************************************/

int TE_init_ecies_test(void)
{
    TE_rc_t res = TE_RC_SUCCESS;

    TE_perfEntryInit("ecies", "get-domain");
    TE_perfEntryInit("ecies", "key-pair-gen");
    TE_perfEntryInit("ecies", "encrypt");
    TE_perfEntryInit("ecies", "decrypt");

    TE_ASSERT(TE_registerFlow("ecies",
                              "encrypt&decrypt",
                              "",
                              NULL,
                              ecies_exec,
                              NULL,
                              NULL,
                              &teEciesTestVec) == TE_RC_SUCCESS);

bail:
    return res;
}
