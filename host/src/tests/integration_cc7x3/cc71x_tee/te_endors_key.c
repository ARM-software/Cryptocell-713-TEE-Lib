/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include <stdio.h>
#include <stdint.h>
#include "test_engine.h"
#include "cc_util.h"
#include "te_endors_key.h"

/******************************************************************
 * Defines
 ******************************************************************/

#define TE_KEY_ENDORS_DEFAULT_DOMAIN        CC_UTIL_EK_DomainID_secp256k1

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

static TE_rc_t endorsement_key(void* pContext);

/******************************************************************
 * Static functions
 ******************************************************************/

static TE_rc_t endorsement_key(void* pContext)
{
    TE_rc_t res = TE_RC_SUCCESS;
    TE_perfIndex_t cookie = 0;
    CCUtilEkPrivkey_t privKey, privKeySecond;
    CCUtilEkPubkey_t publKey, publKeySecond;
    CCUtilEkTempData_t tempDataBuff;
    CCRndGenerateVectWorkFunc_t pRndFunc = NULL;

    TE_UNUSED(pContext);

    /* Deriving endorsement keys*/
    /*--------------------------*/
    cookie = TE_perfOpenNewEntry("endorsement-key", "endorsement-key-pair-gen");
    TE_ASSERT(CC_UtilDeriveEndorsementKey(TE_KEY_ENDORS_DEFAULT_DOMAIN,
                                          &privKey,
                                          &publKey,
                                          &tempDataBuff,
                                          pRndFunc,
                                          NULL,
                                          NULL) == CC_OK);
    TE_perfCloseEntry(cookie);

    /* Zeroing data */
    /*--------------*/
    memset(&pRndFunc, 0, sizeof(CCRndGenerateVectWorkFunc_t));
    memset(&tempDataBuff, 0, sizeof(CCUtilEkTempData_t));

    /* Deriving endorsement keys for the second time */
    /*-----------------------------------------------*/
    cookie = TE_perfOpenNewEntry("endorsement-key", "endorsement-key-pair-gen");
    TE_ASSERT(CC_UtilDeriveEndorsementKey(TE_KEY_ENDORS_DEFAULT_DOMAIN,
                                          &privKeySecond,
                                          &publKeySecond,
                                          &tempDataBuff,
                                          pRndFunc,
                                          NULL,
                                          NULL) == CC_OK);
    TE_perfCloseEntry(cookie);

    /* Comparing first and second time public and private keys, should be similar */
    /*----------------------------------------------------------------------------*/
    TE_ASSERT(memcmp(privKey.PrivKey, privKeySecond.PrivKey,CC_UTIL_EK_BUFF_MAX_LENGTH) == 0);

    TE_ASSERT(memcmp(publKey.PublKeyX,publKeySecond.PublKeyX,CC_UTIL_EK_BUFF_MAX_LENGTH) == 0);

    TE_ASSERT(memcmp(publKey.PublKeyY,publKeySecond.PublKeyY,CC_UTIL_EK_BUFF_MAX_LENGTH) == 0);

bail:
    return res;
}

/******************************************************************
 * Public
 ******************************************************************/

int TE_init_endors_key_test(void)
{
    TE_rc_t res = TE_RC_SUCCESS;

    TE_perfEntryInit("endorsement-key", "endorsement-key-pair-gen");

    TE_ASSERT(TE_registerFlow("endorsement-key",
                              "key-pair-gen",
                              "",
                              NULL,
                              endorsement_key,
                              NULL,
                              NULL,
                              NULL) == TE_RC_SUCCESS);

bail:
	return res;
}
