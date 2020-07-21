/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include <stdio.h>
#include <stdint.h>

#include "test_engine.h"
#include "cc_ecpki_kg.h"
#include "cc_ecpki_domain.h"
#include "cc_ecpki_dh.h"
#include "te_ecdh.h"


/******************************************************************
 * Defines
 ******************************************************************/

#define TE_ECDH_DOMAIN           CC_ECPKI_DomainID_secp256r1

/******************************************************************
 * Types
 ******************************************************************/

typedef struct EcdhVector_t {
    CCEcpkiUserPrivKey_t            userPrivKey1;
    CCEcpkiUserPublKey_t            userPublKey1;
    CCEcpkiUserPrivKey_t            userPrivKey2;
    CCEcpkiUserPublKey_t            userPublKey2;
    CCEcpkiDomainID_t               domain;
    CCEcdhTempData_t                tempBuff;
    CCEcpkiKgTempData_t             tempBuffGenKey;
} EcdhVector_t;

/******************************************************************
 * Externs
 ******************************************************************/

extern CCRndState_t *pRndState_proj;
extern CCRndGenerateVectWorkFunc_t pRndFunc_proj;

/******************************************************************
 * Globals
 ******************************************************************/

static EcdhVector_t ecdhDataVector = {
                               .domain = TE_ECDH_DOMAIN,
                               .userPrivKey1 = { 0x00 },
                               .userPrivKey2 = { 0x00 },
                               .userPublKey1 = { 0x00 },
                               .userPublKey2 = { 0x00 },
};

/******************************************************************
 * Static Prototypes
 ******************************************************************/

static TE_rc_t ecdh_shared_secret(void* pContext);

/******************************************************************
 * Static functions
 ******************************************************************/

static TE_rc_t ecdh_shared_secret(void* pContext)
{
    TE_rc_t res = TE_RC_SUCCESS;
    TE_perfIndex_t cookie = 0;
    EcdhVector_t* vecTest = NULL;
    uint8_t share_secret1[CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS*4];
    uint8_t share_secret2[CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS*4];
    size_t share_secret_size = CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS*4;
    vecTest = (EcdhVector_t *) &ecdhDataVector;
    TE_UNUSED(pContext);

    /* Building the ECC Keys for user 1 */
    cookie = TE_perfOpenNewEntry("ecdh", "key-pair-generate");
    TE_ASSERT(CC_EcpkiKeyPairGenerate(pRndFunc_proj,
                                      pRndState_proj,
                                      CC_EcpkiGetEcDomain(vecTest->domain),
                                      &vecTest->userPrivKey1,
                                      &vecTest->userPublKey1,
                                      &vecTest->tempBuffGenKey,
                                      NULL) == CC_OK);
    TE_perfCloseEntry(cookie);

    /* Building the ECC Keys for user 2 */
    cookie = TE_perfOpenNewEntry("ecdh", "key-pair-generate");
    TE_ASSERT(CC_EcpkiKeyPairGenerate(pRndFunc_proj,
                                      pRndState_proj,
                                      CC_EcpkiGetEcDomain(vecTest->domain),
                                      &vecTest->userPrivKey2,
                                      &vecTest->userPublKey2,
                                      &vecTest->tempBuffGenKey,
                                      NULL) == CC_OK);
    TE_perfCloseEntry(cookie);

    /* Verifying that the keys are different from each other */
    TE_ASSERT(memcmp(vecTest->userPrivKey1.PrivKeyDbBuff,
                     vecTest->userPrivKey2.PrivKeyDbBuff, sizeof(vecTest->userPrivKey2.PrivKeyDbBuff)) != 0);
    TE_ASSERT(memcmp(vecTest->userPublKey1.PublKeyDbBuff,
                     vecTest->userPublKey2.PublKeyDbBuff, sizeof(vecTest->userPublKey2.PublKeyDbBuff)) != 0);

    /* Generating the Secret for user 1 */
    /*----------------------------------*/
    cookie = TE_perfOpenNewEntry("ecdh", "generate-secret(svdpdh)");
    TE_ASSERT(CC_EcdhSvdpDh(&vecTest->userPublKey2, &vecTest->userPrivKey1,
                            share_secret1, &share_secret_size, &vecTest->tempBuff) == CC_OK);
    TE_perfCloseEntry(cookie);

    /* Generating the Secret for user 2 */
    /*----------------------------------*/
    cookie = TE_perfOpenNewEntry("ecdh", "generate-secret(svdpdh)");
    TE_ASSERT(CC_EcdhSvdpDh(&vecTest->userPublKey1, &vecTest->userPrivKey2,
                            share_secret2, &share_secret_size, &vecTest->tempBuff) == CC_OK);
    TE_perfCloseEntry(cookie);

    /* Verifying we have the same Secret Key both for client & Server */
    /*----------------------------------------------------------------*/
    TE_ASSERT(memcmp(share_secret2, share_secret1, share_secret_size) == 0);

bail:
    return res;
}

/******************************************************************
 * Public
 ******************************************************************/

int TE_init_ecdh_test(void)
{
    TE_rc_t res = TE_RC_SUCCESS;

    TE_perfEntryInit("ecdh", "key-pair-generate");
    TE_perfEntryInit("ecdh", "generate-secret(svdpdh)");

    TE_ASSERT(TE_registerFlow("ecdh-test-1",
                               "ECDH",
                               "shared secrets",
                               NULL,
                               ecdh_shared_secret,
                               NULL,
                               NULL,
                               NULL) == TE_RC_SUCCESS);

bail:
    return res;
}
