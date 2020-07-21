/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include <stdio.h>
#include <stdint.h>

#include "test_engine.h"
#include "cc_ecpki_ecdsa.h"
#include "cc_ecpki_kg.h"
#include "cc_ecpki_domain.h"
#include "cc_rnd.h"
#include "te_ecdsa.h"


/******************************************************************
 * Defines
 ******************************************************************/

#define TE_ECDSA_DOMAIN           CC_ECPKI_DomainID_secp256r1
#define TE_ECDSA_HASH             CC_ECPKI_HASH_SHA256_mode
#define RANDON_MSG_SIZE_IN_BYTES     64

/******************************************************************
 * Types
 ******************************************************************/

/******************************************************************
 * Externs
 ******************************************************************/

extern CCRndState_t *pRndState_proj;
extern CCRndGenerateVectWorkFunc_t pRndFunc_proj;

/******************************************************************
 * Globals
 ******************************************************************/

/******************************************************************
 * Static Prototypes
 ******************************************************************/

static TE_rc_t ecdsa_sign_verify(void* pContext);

static CCEcpkiUserPrivKey_t            userPrivKey;
static CCEcpkiUserPublKey_t            userPublKey;
static CCEcpkiKgTempData_t             tempBuff;
static CCEcdsaSignUserContext_t        signUserContext;
static CCEcdsaVerifyUserContext_t      verifyUserContext;

/******************************************************************
 * Static functions
 ******************************************************************/

static TE_rc_t ecdsa_sign_verify(void* pContext)
{
    TE_rc_t res = TE_RC_SUCCESS;
    TE_perfIndex_t cookie = 0;
    uint8_t signedData[CALC_WORDS_TO_BYTES(CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS) * 2];
    size_t signedDataLen = sizeof(signedData);
    uint8_t msgIn[RANDON_MSG_SIZE_IN_BYTES];
    size_t msgInSize = sizeof(msgIn);
    TE_UNUSED(pContext);

    /* Building the ECC Keys for user */
    /*--------------------------------*/
    cookie = TE_perfOpenNewEntry("ecdsa", "key-pair-generate");
    TE_ASSERT(CC_EcpkiKeyPairGenerate(pRndFunc_proj,
                                      pRndState_proj,
                                      CC_EcpkiGetEcDomain(TE_ECDSA_DOMAIN),
                                      &userPrivKey,
                                      &userPublKey,
                                      &tempBuff,
                                      NULL) == CC_OK);
    TE_perfCloseEntry(cookie);

    /* Generate random vector of data */
    /*--------------------------------*/
    TE_perfOpenNewEntry("ecdsa", "generate-rand-vec");
    TE_ASSERT(CC_RndGenerateVector(pRndState_proj, msgIn, msgInSize) == CC_OK);
    TE_perfCloseEntry(cookie);

    /* Performing the Sign operation */
    /*-------------------------------*/
    cookie = TE_perfOpenNewEntry("ecdsa", "sign");
    TE_ASSERT(CC_EcdsaSign(pRndFunc_proj,
                           pRndState_proj,
                           &signUserContext,
                           &userPrivKey,
                           TE_ECDSA_HASH,
                           msgIn,
                           msgInSize,
                           signedData,
                           &signedDataLen) == CC_OK);
    TE_perfCloseEntry(cookie);

    /* Verify the data using the public Key */
    /*--------------------------------------*/
    cookie = TE_perfOpenNewEntry("ecdsa", "verify");
    TE_ASSERT(CC_EcdsaVerify(&verifyUserContext,
                             &userPublKey,
                             TE_ECDSA_HASH,
                             signedData,
                             signedDataLen,
                             msgIn,
                             msgInSize) == CC_OK);
    TE_perfCloseEntry(cookie);

bail:
    return res;
}

/******************************************************************
 * Public
 ******************************************************************/

int TE_init_ecdsa_test(void)
{
    TE_rc_t res = TE_RC_SUCCESS;

    TE_perfEntryInit("ecdsa", "key-pair-generate");
    TE_perfEntryInit("ecdsa", "sign");
    TE_perfEntryInit("ecdsa", "verify");
    TE_perfEntryInit("ecdsa", "generate-rand-vec");

    TE_ASSERT(TE_registerFlow("ecdsa-test-1",
                               "ECDSA",
                               "sign&verify",
                               NULL,
                               ecdsa_sign_verify,
                               NULL,
                               NULL,
                               NULL) == TE_RC_SUCCESS);

bail:
	return res;
}
