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
#include "te_sm2_ke.h"


/******************************************************************
 * Defines
 ******************************************************************/
#define SM2_TV_RAND_SEED_SIZE           32
#define SM2_TV_MAX_KEY_SIZE_IN_BYTES    16

/******************************************************************
 * Enums
 ******************************************************************/

/******************************************************************
 * Types
 ******************************************************************/

typedef struct Sm2KeyExchangeVector_t{
    /* Input - User A */
    const char* id_UserA;
    size_t      idSize_UserA;
    uint8_t     privateKeyInBytes_UserA[CC_SM2_MODULE_LENGTH_IN_BYTES];
    uint8_t     publicKeyInBytesX_UserA[CC_SM2_MODULE_LENGTH_IN_BYTES];
    uint8_t     publicKeyInBytesY_UserA[CC_SM2_MODULE_LENGTH_IN_BYTES];
    uint8_t     confirmationrequired_UserA;
    uint8_t     randomSeed_UserA[SM2_TV_RAND_SEED_SIZE];

    /* Input - User B */
    const char* id_UserB;
    size_t      idSize_UserB;
    uint8_t     privateKeyInBytes_UserB[CC_SM2_MODULE_LENGTH_IN_BYTES];
    uint8_t     publicKeyInBytesX_UserB[CC_SM2_MODULE_LENGTH_IN_BYTES];
    uint8_t     publicKeyInBytesY_UserB[CC_SM2_MODULE_LENGTH_IN_BYTES];
    uint8_t     confirmationrequired_UserB;
    uint8_t     randomSeed_UserB[SM2_TV_RAND_SEED_SIZE];

    /* Input - common */
    size_t      privateKeySize;
    size_t      pubKeySize;
    size_t      requiredKeySizeInBits;

    /* Intermediate results and their sizes - User A */
    CCEcpkiUserPrivKey_t    privKey_UserA;
    CCEcpkiUserPublKey_t    pubKey_UserA;

    /* Intermediate results and their sizes - User B */
    CCEcpkiUserPrivKey_t    privKey_UserB;
    CCEcpkiUserPublKey_t    pubKey_UserB;


    /* Output */
    uint8_t     outputKey_UserA[SM2_TV_MAX_KEY_SIZE_IN_BYTES];
    size_t      outputKeySize_UserA; /* in/out */
    uint8_t     outputKey_UserB[SM2_TV_MAX_KEY_SIZE_IN_BYTES];
    size_t      outputKeySize_UserB; /* in/out */

    /* Reference */
    uint8_t     referenceKey[SM2_TV_MAX_KEY_SIZE_IN_BYTES];
    size_t      referenceKeySize;
}Sm2KeyExchangeVector_t;
/******************************************************************
 * Externs
 ******************************************************************/

/******************************************************************
 * Globals
 ******************************************************************/


static Sm2KeyExchangeVector_t sm2_vector = {
    /* Input - User A */
    .id_UserA = "1234567812345678",
    .idSize_UserA = 16,
    .privateKeyInBytes_UserA = { /* 81EB26E9 41BB5AF1 6DF11649 5F906952 72AE2CD6 3D6C4AE1 678418BE 48230029 */
            0x81, 0xEB, 0x26, 0xE9, 0x41, 0xBB, 0x5A, 0xF1,
            0x6D, 0xF1, 0x16, 0x49, 0x5F, 0x90, 0x69, 0x52,
            0x72, 0xAE, 0x2C, 0xD6, 0x3D, 0x6C, 0x4A, 0xE1,
            0x67, 0x84, 0x18, 0xBE, 0x48, 0x23, 0x00, 0x29
    },
    .publicKeyInBytesX_UserA = { /* 160E1289 7DF4EDB6 1DD812FE B96748FB D3CCF4FF E26AA6F6 DB9540AF 49C94232 */
            0x16, 0x0E, 0x12, 0x89, 0x7D, 0xF4, 0xED, 0xB6,
            0x1D, 0xD8, 0x12, 0xFE, 0xB9, 0x67, 0x48, 0xFB,
            0xD3, 0xCC, 0xF4, 0xFF, 0xE2, 0x6A, 0xA6, 0xF6,
            0xDB, 0x95, 0x40, 0xAF, 0x49, 0xC9, 0x42, 0x32
    },
    .publicKeyInBytesY_UserA = { /* 4A7DAD08 BB9A4595 31694BEB 20AA489D 6649975E 1BFCF8C4 741B78B4 B223007F */
            0x4A, 0x7D, 0xAD, 0x08, 0xBB, 0x9A, 0x45, 0x95,
            0x31, 0x69, 0x4B, 0xEB, 0x20, 0xAA, 0x48, 0x9D,
            0x66, 0x49, 0x97, 0x5E, 0x1B, 0xFC, 0xF8, 0xC4,
            0x74, 0x1B, 0x78, 0xB4, 0xB2, 0x23, 0x00, 0x7F
    },
    .randomSeed_UserA = {
            0xD4, 0xDE, 0x15, 0x47, 0x4D, 0xB7, 0x4D, 0x06,
            0x49, 0x1C, 0x44, 0x0D, 0x30, 0x5E, 0x01, 0x24,
            0x00, 0x99, 0x0F, 0x3E, 0x39, 0x0C, 0x7E, 0x87,
            0x15, 0x3C, 0x12, 0xDB, 0x2E, 0xA6, 0x0B, 0xB3
    },
    .outputKeySize_UserA = SM2_TV_MAX_KEY_SIZE_IN_BYTES, /* in/out */
    .confirmationrequired_UserA = 3U,


    /* Input - User B */
    .id_UserB = "1234567812345678",
    .idSize_UserB = 16,
    .privateKeyInBytes_UserB = { /* 78512991 7D45A9EA 5437A593 56B82338 EAADDA6C EB199088 F14AE10D EFA229B5 */
            0x78, 0x51, 0x29, 0x91, 0x7D, 0x45, 0xA9, 0xEA,
            0x54, 0x37, 0xA5, 0x93, 0x56, 0xB8, 0x23, 0x38,
            0xEA, 0xAD, 0xDA, 0x6C, 0xEB, 0x19, 0x90, 0x88,
            0xF1, 0x4A, 0xE1, 0x0D, 0xEF, 0xA2, 0x29, 0xB5
    },
    .publicKeyInBytesX_UserB = { /* 6AE848C5 7C53C7B1 B5FA99EB 2286AF07 8BA64C64 591B8B56 6F7357D5 76F16DFB */
            0x6A, 0xE8, 0x48, 0xC5, 0x7C, 0x53, 0xC7, 0xB1,
            0xB5, 0xFA, 0x99, 0xEB, 0x22, 0x86, 0xAF, 0x07,
            0x8B, 0xA6, 0x4C, 0x64, 0x59, 0x1B, 0x8B, 0x56,
            0x6F, 0x73, 0x57, 0xD5, 0x76, 0xF1, 0x6D, 0xFB
    },
    .publicKeyInBytesY_UserB = { /* EE489D77 1621A27B 36C5C799 2062E9CD 09A92643 86F3FBEA 54DFF693 05621C4D */
            0xEE, 0x48, 0x9D, 0x77, 0x16, 0x21, 0xA2, 0x7B,
            0x36, 0xC5, 0xC7, 0x99, 0x20, 0x62, 0xE9, 0xCD,
            0x09, 0xA9, 0x26, 0x43, 0x86, 0xF3, 0xFB, 0xEA,
            0x54, 0xDF, 0xF6, 0x93, 0x05, 0x62, 0x1C, 0x4D
    },
    .randomSeed_UserB = {
            0x7E, 0x07, 0x12, 0x48, 0x14, 0xB3, 0x09, 0x48,
            0x91, 0x25, 0xEA, 0xED, 0x10, 0x11, 0x13, 0x16,
            0x4E, 0xBF, 0x0F, 0x34, 0x58, 0xC5, 0xBD, 0x88,
            0x33, 0x5C, 0x1F, 0x9D, 0x59, 0x62, 0x43, 0xD6
    },
    .outputKeySize_UserB = SM2_TV_MAX_KEY_SIZE_IN_BYTES, /* in/out */
    .confirmationrequired_UserB = 3U,

    /* Input - common */
    .privateKeySize = 32,
    .pubKeySize = 65,
    .requiredKeySizeInBits = SM2_TV_MAX_KEY_SIZE_IN_BYTES * CC_BITS_IN_BYTE,

    /* Reference */
    .referenceKey = { /*shared secret key: 6C893473 54DE2484 C60B4AB1 FDE4C6E5 */
            0x6C, 0x89, 0x34, 0x73, 0x54, 0xDE, 0x24, 0x84, 0xC6, 0x0B, 0x4A, 0xB1, 0xFD, 0xE4, 0xC6, 0xE5
    },
    .referenceKeySize = SM2_TV_MAX_KEY_SIZE_IN_BYTES,
};

/******************************************************************
 * Static Prototypes
 ******************************************************************/
static TE_rc_t sm2_ke_prepare(void *pContext);
static TE_rc_t sm2_ke_execute_2_parties(void *pContext);
static TE_rc_t sm2_ke_verify(void *pContext);
static TE_rc_t sm2_ke_clean(void *pContext);

/******************************************************************
 * Static functions
 ******************************************************************/
static CCError_t Tests_RndGenerateVectorConst( void           *rngState_vptr,    /*in*/
                                         uint8_t        *out_ptr,          /*out*/
                                         size_t         outSizeBytes)      /*in*/
{
    CCError_t  error = CC_OK;
    uint8_t* pData = (uint8_t*)rngState_vptr;

    if (outSizeBytes != SM2_TV_RAND_SEED_SIZE)
        return 1;

    memcpy (out_ptr, pData, outSizeBytes);
    return error;
}


static TE_rc_t sm2_ke_prepare(void *pContext)
{
    CCEcpkiBuildTempData_t tmpData;
    TE_rc_t res = TE_RC_SUCCESS;
    const CCEcpkiDomain_t* pSm2Domain = CC_EcpkiGetSm2Domain();
    Sm2KeyExchangeVector_t *sm2_vec = (Sm2KeyExchangeVector_t *)pContext;
    uint8_t publicKeyInBytes[ 2 * CC_SM2_MODULE_LENGTH_IN_BYTES + 1 /*1 bit for compression flag*/];


    /* User A  - Set key data in a structure */
    /* Set the public key data in 1 array:  compression flag || x || y */
    publicKeyInBytes[0] = CC_EC_PointUncompressed;
    memcpy(publicKeyInBytes + 1, sm2_vec->publicKeyInBytesX_UserA, sm2_vec->pubKeySize/2);
    memcpy(publicKeyInBytes + 1 + sm2_vec->pubKeySize/2,
           sm2_vec->publicKeyInBytesY_UserA, sm2_vec->pubKeySize/2);


    /* User A -
     * Build public and private keys -
     * input the keys as bytes array (public key:  compression flag || x || y)
     * output the keys as structures, which are used as inputs to all SM2 or ECC operations.
     * */
    TE_ASSERT_PASS(CC_EcpkiPublKeyBuildAndCheck (pSm2Domain, publicKeyInBytes, sm2_vec->pubKeySize,
                                                 0/*CheckPointersAndSizesOnly*/, &sm2_vec->pubKey_UserA, &tmpData) , CC_OK);

    TE_ASSERT_PASS(CC_EcpkiPrivKeyBuild(pSm2Domain, sm2_vec->privateKeyInBytes_UserA,
                                        sm2_vec->privateKeySize, &sm2_vec->privKey_UserA) , CC_OK);

    /* User B  - Set key data in a structure */
    /* Set the public key data in 1 array:  compression flag || x || y */
    publicKeyInBytes[0] = CC_EC_PointUncompressed;
    memcpy(publicKeyInBytes + 1, sm2_vec->publicKeyInBytesX_UserB, sm2_vec->pubKeySize/2);
    memcpy(publicKeyInBytes + 1 + sm2_vec->pubKeySize/2,
           sm2_vec->publicKeyInBytesY_UserB, sm2_vec->pubKeySize/2);


    /* User B -
     * Build public and private keys -
     * input the keys as bytes array (public key:  compression flag || x || y)
     * output the keys as structures, which are used as inputs to all SM2 or ECC operations.
     * */
    TE_ASSERT_PASS(CC_EcpkiPublKeyBuildAndCheck (pSm2Domain, publicKeyInBytes, sm2_vec->pubKeySize,
                                                 0/*CheckPointersAndSizesOnly*/, &sm2_vec->pubKey_UserB, &tmpData) , CC_OK);

    TE_ASSERT_PASS(CC_EcpkiPrivKeyBuild(pSm2Domain, sm2_vec->privateKeyInBytes_UserB,
                                        sm2_vec->privateKeySize, &sm2_vec->privKey_UserB) , CC_OK);

    goto bail;
bail:
    return res;
}

static TE_rc_t sm2_ke_execute_2_parties(void *pContext)
{
    Sm2KeyExchangeVector_t  *sm2_vec = (Sm2KeyExchangeVector_t *)pContext;
    TE_rc_t         res = TE_RC_SUCCESS;
    TE_perfIndex_t  cookie;
    uint8_t*        workBuff = NULL;
    size_t          workBuffSize = 0;
    size_t          largestIdSize = 0;

    CCEcpkiUserPublKey_t    randomPoint_UserA;
    CCEcpkiUserPublKey_t    randomPoint_UserB;

    CC_Sm2KeContext_t       Sm2KeContext_a;
    CC_Sm2KeContext_t       Sm2KeContext_b;

    uint8_t outConfValue_UserA[CC_SM2_CONF_VALUE_LENGTH_IN_BYTES];
    uint8_t outConfValue_UserB[CC_SM2_CONF_VALUE_LENGTH_IN_BYTES];
    size_t  outConfValueSize_UserA = CC_SM2_CONF_VALUE_LENGTH_IN_BYTES;
    size_t  outConfValueSize_UserB = CC_SM2_CONF_VALUE_LENGTH_IN_BYTES;


    /* Start performance measurement */
    cookie = TE_perfOpenNewEntry("sm2", "key exchange - 2 parties");

    /* Allocate working buffer */
    largestIdSize = sm2_vec->idSize_UserA > sm2_vec->idSize_UserB ? sm2_vec->idSize_UserA : sm2_vec->idSize_UserB;
    workBuffSize = 2 + CC_SM2_MODULE_LENGTH_IN_BYTES*4 + CC_SM2_ORDER_LENGTH_IN_BYTES*2 + largestIdSize;
    workBuff = Test_PalMalloc(workBuffSize);
    TE_ASSERT(workBuff);


    /* User A -
     * Initialise context with:
     * user A's private and public keys,
     * user B's public key
     * ID's of both users.
     * The context needs to be saved until the common key is derived.
     * */
    TE_ASSERT_PASS( CC_Sm2KeyExchangeContext_init (&Sm2KeContext_a,
                                                   workBuff, workBuffSize,
                                                   &sm2_vec->pubKey_UserA, &sm2_vec->privKey_UserA,
                                                   &sm2_vec->pubKey_UserB,
                                                   sm2_vec->id_UserA, sm2_vec->idSize_UserA,
                                                   sm2_vec->id_UserB, sm2_vec->idSize_UserB,
                                                   1U, /* initiator */
                                                   sm2_vec->confirmationrequired_UserA) , CC_OK);

    /* User B -
     * Initialise context with:
     * user B's private and public keys,
     * user A's public key
     * ID's of both users
     * The context needs to be saved until the common key is derived.
     * */
    TE_ASSERT_PASS( CC_Sm2KeyExchangeContext_init (&Sm2KeContext_b,
                                                   workBuff, workBuffSize,
                                                   &sm2_vec->pubKey_UserB, &sm2_vec->privKey_UserB,
                                                   &sm2_vec->pubKey_UserA,
                                                   sm2_vec->id_UserB, sm2_vec->idSize_UserB,
                                                   sm2_vec->id_UserA, sm2_vec->idSize_UserA,
                                                   0U, /* not initiator */
                                                   sm2_vec->confirmationrequired_UserB) , CC_OK);

    /* User A -
     * Calculate a random point. */
    TE_ASSERT_PASS( CC_Sm2CalculateECPoint (Tests_RndGenerateVectorConst,
                                            (void *)sm2_vec->randomSeed_UserA,
                                            &Sm2KeContext_a,
                                            &randomPoint_UserA ) , CC_OK);

    /* User B-
     * Calculate a random point. */
    TE_ASSERT_PASS( CC_Sm2CalculateECPoint (Tests_RndGenerateVectorConst,
                                            (void *)sm2_vec->randomSeed_UserB,
                                            &Sm2KeContext_b,
                                            &randomPoint_UserB ) , CC_OK);
    /* User B-
     * Calculate the shared secret with the random point previously calculated by user B (saved in the context) and the
     * random point that was received from A. */
    TE_ASSERT_PASS( CC_Sm2CalculateSharedSecret(&Sm2KeContext_b,
                                                &randomPoint_UserA, /* received from A */
                                                outConfValue_UserB, &outConfValueSize_UserB) , CC_OK);
    /* User A-
     * Calculate the shared secret with the random point previously calculated by user A (saved in the context) and the
     * random point that was received from B. */
    TE_ASSERT_PASS( CC_Sm2CalculateSharedSecret(&Sm2KeContext_a,
                                                &randomPoint_UserB, /* received from B */
                                                outConfValue_UserA, &outConfValueSize_UserA) , CC_OK);

    /* Verify the confirmation value is correct */
    TE_ASSERT_PASS( CC_Sm2Confirmation (&Sm2KeContext_a, outConfValue_UserB, outConfValueSize_UserB) , CC_OK);
    TE_ASSERT_PASS( CC_Sm2Confirmation (&Sm2KeContext_b, outConfValue_UserA, outConfValueSize_UserA) , CC_OK);

    /* User A -
     * derive the common key */
    TE_ASSERT_PASS( CC_Sm2Kdf(&Sm2KeContext_a,
                              sm2_vec->requiredKeySizeInBits,
                              sm2_vec->outputKey_UserA, &sm2_vec->outputKeySize_UserA) , CC_OK);

    /* User B -
     * derive the common key */
    TE_ASSERT_PASS( CC_Sm2Kdf(&Sm2KeContext_b,
                              sm2_vec->requiredKeySizeInBits,
                              sm2_vec->outputKey_UserB, &sm2_vec->outputKeySize_UserB) , CC_OK);


    /* Finish performance measurement */
    TE_perfCloseEntry(cookie);

bail:
    if (workBuff != NULL) {
        Test_PalFree(workBuff);
        workBuff = NULL;
    }

    return res;
}

static TE_rc_t sm2_ke_verify(void *pContext)
{
    TE_rc_t res = TE_RC_SUCCESS;
    Sm2KeyExchangeVector_t *sm2_vec = (Sm2KeyExchangeVector_t *)pContext;

    /* Verify results */
    /* compare output of A and B - key size */
    TE_ASSERT( sm2_vec->referenceKeySize == sm2_vec->outputKeySize_UserA);
    TE_ASSERT( sm2_vec->referenceKeySize == sm2_vec->outputKeySize_UserB);

    /* compare output of A and B - key buffer */
    TE_ASSERT( memcmp (sm2_vec->outputKey_UserA, sm2_vec->referenceKey, sm2_vec->referenceKeySize) == 0);
    TE_ASSERT( memcmp (sm2_vec->outputKey_UserB, sm2_vec->referenceKey, sm2_vec->referenceKeySize) == 0);

    goto bail;
bail:
    return res;
}

static TE_rc_t sm2_ke_clean(void *pContext)
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
int TE_init_sm2_ke_test(void)
{
    TE_rc_t res = TE_RC_SUCCESS;

    TE_perfEntryInit("sm2", "key exchange - 2 parties");

    TE_ASSERT(TE_registerFlow("sm2",
                              "key exchange",
                              "2 parties",
                              sm2_ke_prepare,
                              sm2_ke_execute_2_parties,
                              sm2_ke_verify,
                              sm2_ke_clean,
                              &sm2_vector) == TE_RC_SUCCESS);


    goto bail;

bail:
    return res;
}

