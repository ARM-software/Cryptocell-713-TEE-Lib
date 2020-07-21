/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include <stdio.h>
#include <stdint.h>
#include "test_engine.h"
#include "cc_aesccm.h"
#include "te_aes_ccm.h"

/******************************************************************
 * Defines
 ******************************************************************/

#define TE_CCM_NONCE_SIZE_IN_BYTES                         13
#define TE_CCM_ASSOC_DATA_SIZE_IN_BYTES                    32
#define TE_CCM_PLAINTEXT_SIZE_IN_BYTES                     16
#define TE_CCM_CIPHERTEXT_SIZE_IN_BYTES                    16
#define TE_CCM_TAG_SIZE                                    16

/******************************************************************
 * Types
 ******************************************************************/

typedef struct ccmVector_t {
    CCAesCcmKey_t                       ccmKey;
    CCAesCcmKeySize_t                   keySize;
    uint8_t                             pNonce[TE_CCM_NONCE_SIZE_IN_BYTES];
    uint8_t                             pAssocData[TE_CCM_ASSOC_DATA_SIZE_IN_BYTES];
    uint8_t                             pPlainText[TE_CCM_PLAINTEXT_SIZE_IN_BYTES];
    uint8_t                             pCipherText[TE_CCM_CIPHERTEXT_SIZE_IN_BYTES];
} ccmVector_t;

/******************************************************************
 * Externs
 ******************************************************************/

/******************************************************************
 * Globals
 ******************************************************************/

static ccmVector_t ccmDataVector = {
                                    .ccmKey = { 0xee, 0x8c, 0xe1, 0x87, 0x16, 0x97, 0x79, 0xd1, 0x3e, 0x44, 0x3d, 0x64, 0x28, 0xe3, 0x8b, 0x38,
                                                0xb5, 0x5d, 0xfb, 0x90, 0xf0, 0x22, 0x8a, 0x8a, 0x4e, 0x62, 0xf8, 0xf5, 0x35, 0x80, 0x6e, 0x62, },
                                    .pNonce = { 0x12, 0x16, 0x42, 0xc4, 0x21, 0x8b, 0x39, 0x1c, 0x98, 0xe6, 0x26, 0x9c, 0x8a },
                                    .pAssocData = { 0x71, 0x8d, 0x13, 0xe4, 0x75, 0x22, 0xac, 0x4c, 0xdf, 0x3f, 0x82, 0x80, 0x63, 0x98, 0x0b, 0x6d,
                                                    0x45, 0x2f, 0xcd, 0xcd, 0x6e, 0x1a, 0x19, 0x04, 0xbf, 0x87, 0xf5, 0x48, 0xa5, 0xfd, 0x5a, 0x05, },
                                    .pPlainText = { 0xd1, 0x5f, 0x98, 0xf2, 0xc6, 0xd6, 0x70, 0xf5, 0x5c, 0x78, 0xa0, 0x66, 0x48, 0x33, 0x2b, 0xc9, },
                                    .keySize = CC_AES_Key256BitSize,
                                    .pCipherText = { 0xcc, 0x17, 0xbf, 0x87, 0x94, 0xc8, 0x43, 0x45, 0x7d, 0x89, 0x93, 0x91, 0x89, 0x8e, 0xd2, 0x2a, },
};

/******************************************************************
 * Static Prototypes
 ******************************************************************/

static TE_rc_t aes_ccm_execute(void *pContext);

/******************************************************************
 * Static functions
 ******************************************************************/

static TE_rc_t aes_ccm_execute(void *pContext)
{
    TE_rc_t res = TE_RC_SUCCESS;
    TE_perfIndex_t cookie;
    CCAesCcmMacRes_t resBuff;
    ccmVector_t *ccmTestVec = NULL;
    uint8_t dataOutEncrypt[TE_CCM_CIPHERTEXT_SIZE_IN_BYTES] = { 0 };
    uint8_t dataOutDecrypt[TE_CCM_PLAINTEXT_SIZE_IN_BYTES] = { 0 };
    TE_ASSERT(pContext != NULL);
    ccmTestVec = (ccmVector_t *) pContext;

    /* Encrypting */
    cookie = TE_perfOpenNewEntry("ccm", "encrpyt");
    TE_ASSERT(CC_AesCcm(CC_AES_ENCRYPT,
                        ccmTestVec->ccmKey,
                        ccmTestVec->keySize,
                        ccmTestVec->pNonce,
                        TE_CCM_NONCE_SIZE_IN_BYTES,
                        ccmTestVec->pAssocData,
                        TE_CCM_ASSOC_DATA_SIZE_IN_BYTES,
                        ccmTestVec->pPlainText,
                        TE_CCM_PLAINTEXT_SIZE_IN_BYTES,
                        dataOutEncrypt, TE_CCM_TAG_SIZE,
                        resBuff, CC_AES_MODE_CCM) == CC_OK);
    TE_perfCloseEntry(cookie);

    /* Verifying encrypted data */
    TE_ASSERT(memcmp(dataOutEncrypt, ccmTestVec->pCipherText, TE_CCM_CIPHERTEXT_SIZE_IN_BYTES) == 0);

    /* Decrypting */
    cookie = TE_perfOpenNewEntry("ccm", "decrypt");
    TE_ASSERT(CC_AesCcm(CC_AES_DECRYPT,
                        ccmTestVec->ccmKey,
                        ccmTestVec->keySize,
                        ccmTestVec->pNonce,
                        TE_CCM_NONCE_SIZE_IN_BYTES,
                        ccmTestVec->pAssocData,
                        TE_CCM_ASSOC_DATA_SIZE_IN_BYTES,
                        ccmTestVec->pCipherText,
                        TE_CCM_CIPHERTEXT_SIZE_IN_BYTES,
                        dataOutDecrypt, TE_CCM_TAG_SIZE,
                        resBuff, CC_AES_MODE_CCM) == CC_OK);
    TE_perfCloseEntry(cookie);

    /* Verifying decrypted data */
    TE_ASSERT(memcmp(dataOutDecrypt, ccmTestVec->pPlainText, TE_CCM_CIPHERTEXT_SIZE_IN_BYTES) == 0);

bail:
    return res;
}

/******************************************************************
 * Public
 ******************************************************************/

int TE_init_aes_ccm_test(void)
{
    TE_rc_t res = TE_RC_SUCCESS;

    TE_perfEntryInit("ccm", "encrpyt");
    TE_perfEntryInit("ccm", "decrypt");

    TE_ASSERT(TE_registerFlow("ccm",
                              "encrypt&decrypt",
                              "256bit-key",
                              NULL,
                              aes_ccm_execute,
                              NULL,
                              NULL,
                              &ccmDataVector) == TE_RC_SUCCESS);

bail:
	return res;
}
