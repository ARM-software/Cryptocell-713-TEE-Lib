/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include <stdio.h>
#include "test_engine.h"
#include "cc_rsa_schemes.h"
#include "cc_rsa_kg.h"
#include "cc_rnd.h"
#include "te_rsa.h"

/******************************************************************
 * Defines
 ******************************************************************/

#define KEY_SIZE_IN_BYTES               384
#define KEY_SIZE_IN_BITS                KEY_SIZE_IN_BYTES * 8
#define RANDON_MSG_SIZE_IN_BYTES        64
#define RSA_DEFAULT_HASH                CC_RSA_HASH_SHA256_mode

/******************************************************************
 * Types
 ******************************************************************/

typedef struct teRsaVector_t {
    CCPkcs1Version_t            version;
} teRsaVector_t;

/******************************************************************
 * Externs
 ******************************************************************/

/******************************************************************
 * Globals
 ******************************************************************/

extern CCRndState_t *pRndState_proj;
extern CCRndGenerateVectWorkFunc_t pRndFunc_proj;

static teRsaVector_t signVerifyVer15 = {
                                    .version = CC_PKCS1_VER15,
};

static teRsaVector_t signVerifyVer21 = {
                                    .version = CC_PKCS1_VER21,
};

static teRsaVector_t encryptDecryptVer15 = {
                                    .version = CC_PKCS1_VER15,
};

static teRsaVector_t encryptDecryptVer21 = {
                                    .version = CC_PKCS1_VER21,
};

/******************************************************************
 * Static Prototypes
 ******************************************************************/

TE_rc_t rsa_encrypt_decrypt(void *pContext);
TE_rc_t rsa_sign_verify(void *pContext);



/******************************************************************
 * Static functions
 ******************************************************************/

TE_rc_t rsa_sign_verify(void *pContext)
{
    TE_rc_t res = TE_RC_SUCCESS;
    TE_perfIndex_t cookie = 0;
    CCRsaKgData_t KeyGenData;
    CCRsaUserPrivKey_t userPrivateKey;
    CCRsaUserPubKey_t userPublicKey;
    CCRsaPrivUserContext_t privUserContext;
    CCRsaPubUserContext_t publUserContext;
    CCRsaKgData_t *KeyGenData_ptr = &KeyGenData;
    uint8_t sigBuff[CC_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS * sizeof(uint32_t)];
    uint8_t pubExp3[] = { 0x03 };
    uint8_t msgIn[RANDON_MSG_SIZE_IN_BYTES];
    uint32_t msgSize = sizeof(msgIn);
    size_t sigBuffSize = sizeof(sigBuff);
    CCPkcs1Version_t version = 0;
    CCPkcs1Mgf_t mgf = 0;

    if (pContext == NULL) {
        TE_LOG_ERROR("Invalid Params! (pContext == NULL)");
        res = TE_RC_FAIL;
        goto bail;
    }

    version = ((teRsaVector_t *) pContext)->version;
    mgf = (version == CC_PKCS1_VER15 ? CC_PKCS1_NO_MGF : CC_PKCS1_MGF1);


    /* Generate random vector of data */
    /*--------------------------------*/
    TE_perfOpenNewEntry("rsa", "generate-rand-vec");
    TE_ASSERT(CC_RndGenerateVector(pRndState_proj,
                                   msgIn, RANDON_MSG_SIZE_IN_BYTES) == CC_OK);
    TE_perfCloseEntry(cookie);

    /* Generates public and private key on non CRT mode */
    /*--------------------------------------------------*/
    TE_ASSERT(CC_RsaKgKeyPairGenerate(pRndFunc_proj,
                                      pRndState_proj, pubExp3,
                                      sizeof(pubExp3), KEY_SIZE_IN_BITS,
                                      &userPrivateKey, &userPublicKey,
                                      KeyGenData_ptr, NULL) == CC_OK);

    /* Performing the Sign operation */
    /*-------------------------------*/
    TE_ASSERT(CC_RsaSign(pRndFunc_proj,
                         pRndState_proj, &privUserContext,
                         &userPrivateKey, RSA_DEFAULT_HASH,
                         mgf, 0, msgIn, msgSize, sigBuff,
                         &sigBuffSize, version) == CC_OK);

    /* Verifying the data using the public Key */
    /*-----------------------------------------*/
    TE_ASSERT(CC_RsaVerify(&publUserContext, &userPublicKey,
                           RSA_DEFAULT_HASH, mgf, 0, msgIn,
                           msgSize, sigBuff, version) == CC_OK);

bail:
    return res;
}


TE_rc_t rsa_encrypt_decrypt(void *pContext)
{
    TE_rc_t res = TE_RC_SUCCESS;
    TE_perfIndex_t cookie = 0;
    CCRsaKgData_t KeyGenData;
    CCRsaKgData_t *KeyGenData_ptr = &KeyGenData;
    CCRsaUserPrivKey_t userPrivateKey;
    CCRsaUserPubKey_t userPublicKey;
    CCRsaPrimeData_t primeData;
    uint8_t sigBuff[CC_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS * sizeof(uint32_t)];
    uint8_t pubExp3[] = { 0x03 };
    uint8_t msgIn[RANDON_MSG_SIZE_IN_BYTES];
    uint8_t decBuff[CC_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS * sizeof(uint32_t)];
    size_t decBuffSize = sizeof(decBuff);
    CCPkcs1Version_t version = 0;
    CCPkcs1Mgf_t mgf = 0;

    if (pContext == NULL) {
        TE_LOG_ERROR("Invalid Params! (pContext == NULL)");
        res = TE_RC_FAIL;
        goto bail;
    }

    version = ((teRsaVector_t *) pContext)->version;
    mgf = version == CC_PKCS1_VER15 ? CC_PKCS1_NO_MGF : CC_PKCS1_MGF1;

    /* Generate random vector of data */
    /*--------------------------------*/
    TE_perfOpenNewEntry("rsa", "generate-rand-vec");
    TE_ASSERT(CC_RndGenerateVector(pRndState_proj, msgIn, RANDON_MSG_SIZE_IN_BYTES) == CC_OK);
    TE_perfCloseEntry(cookie);

    /* Generates public and private key on non CRT mode */
    /*--------------------------------------------------*/
    cookie = TE_perfOpenNewEntry("rsa", "key-pair-generate");
    TE_ASSERT(CC_RsaKgKeyPairGenerate(pRndFunc_proj, pRndState_proj, pubExp3, sizeof(pubExp3),
                                      KEY_SIZE_IN_BITS, &userPrivateKey, &userPublicKey, KeyGenData_ptr, NULL) == CC_OK);
    TE_perfCloseEntry(cookie);

    /* Encrypting */
    /*------------*/
    cookie = TE_perfOpenNewEntry("rsa", "encrypt");
    TE_ASSERT(CC_RsaSchemesEncrypt(pRndFunc_proj, pRndState_proj, &userPublicKey, &primeData,
                                   RSA_DEFAULT_HASH, NULL, 0, mgf, msgIn, sizeof(msgIn), sigBuff, version) == CC_OK );
    TE_perfCloseEntry(cookie);

    /* Decrypting */
    /*------------*/
    cookie = TE_perfOpenNewEntry("rsa", "decrypt");
    TE_ASSERT(CC_RsaSchemesDecrypt(&userPrivateKey, &primeData, RSA_DEFAULT_HASH, NULL, 0, mgf,
                                   sigBuff, KEY_SIZE_IN_BYTES, decBuff, &decBuffSize, version) == CC_OK);
    TE_perfCloseEntry(cookie);

    /* Comparing input message to decrypted data */
    /*-------------------------------------------*/
    TE_ASSERT(memcmp(msgIn, decBuff, decBuffSize) == 0);

bail:
    return res;
}

/******************************************************************
 * Public
 ******************************************************************/
int TE_init_rsa_test(void)
{
    TE_rc_t res = TE_RC_SUCCESS;

    TE_perfEntryInit("rsa", "generate-rand-vec");
    TE_perfEntryInit("rsa", "key-pair-generate");
    TE_perfEntryInit("rsa", "encrypt");
    TE_perfEntryInit("rsa", "decrypt");

    /* PKCS#1 Version 1.5 sign and verify */
    /*------------------------------------*/
    TE_ASSERT(TE_registerFlow("rsa pkcs#1-ver1.5",
                              "sign & verify",
                              "sha-256",
                              NULL,
                              rsa_sign_verify,
                              NULL,
                              NULL,
                              &signVerifyVer15) == TE_RC_SUCCESS);

    /* PKCS#1 Version 1.5 encrypt and decrypt */
    /*----------------------------------------*/
    TE_ASSERT(TE_registerFlow("rsa pkcs#1-ver1.5",
                              "encrypt & decrypt",
                              "sha-256",
                              NULL,
                              rsa_encrypt_decrypt,
                              NULL,
                              NULL,
                              &encryptDecryptVer15) == TE_RC_SUCCESS);

    /* PKCS#1 Version 2.1 sign and verify */
    /*------------------------------------*/
    TE_ASSERT(TE_registerFlow("rsa pkcs#1-ver2.1",
                              "sign & verify",
                              "sha-256",
                              NULL,
                              rsa_sign_verify,
                              NULL,
                              NULL,
                              &signVerifyVer21) == TE_RC_SUCCESS);

    /* PKCS#1 Version 1.5 encrypt and decrypt */
    /*----------------------------------------*/
    TE_ASSERT(TE_registerFlow("rsa pkcs#1-ver2.1",
                              "encrypt & decrypt",
                              "sha-256",
                              NULL,
                              rsa_encrypt_decrypt,
                              NULL,
                              NULL,
                              &encryptDecryptVer21) == TE_RC_SUCCESS);
bail:
	return res;
}
