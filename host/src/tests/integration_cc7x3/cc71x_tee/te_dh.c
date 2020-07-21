/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include <stdio.h>
#include <stdint.h>
#include "test_engine.h"
#include "cc_dh.h"
#include "te_dh.h"

/******************************************************************
 * Defines
 ******************************************************************/

#define TE_DH_GENERATOR_SIZE_IN_BYTES                  256
#define TE_DH_PRIME_SIZE_IN_BYTES                      TE_DH_GENERATOR_SIZE_IN_BYTES
#define TE_MAX_DH_KEY_SIZE                             256
#define TE_MAX_DH_OTHER_INFO_BUF_SIZE_BYTES            50

/******************************************************************
 * Types
 ******************************************************************/

typedef struct dhOtherInfo_t {
    uint8_t                   algID[TE_MAX_DH_OTHER_INFO_BUF_SIZE_BYTES];
    uint8_t                   partyUInfo[TE_MAX_DH_OTHER_INFO_BUF_SIZE_BYTES];
    uint8_t                   partyVInfo[TE_MAX_DH_OTHER_INFO_BUF_SIZE_BYTES];
    uint8_t                   suppPrivInfo[TE_MAX_DH_OTHER_INFO_BUF_SIZE_BYTES];
    uint8_t                   suppPublInfo[TE_MAX_DH_OTHER_INFO_BUF_SIZE_BYTES];
    size_t                    suppPrivInfoSize;
    size_t                    partyVInfoSize;
    size_t                    partyUInfoSize;
    size_t                    algIdSize;
    size_t                    suppPublInfoSize;
} dhOtherInfo_t;

typedef struct dhDataVector_t {
    CCDhOpMode_t                dhMode;
    uint8_t                     pGenerator[TE_MAX_DH_KEY_SIZE];
    size_t                      generatorSize;
    uint8_t                     pPrime[TE_MAX_DH_KEY_SIZE];
    size_t                      primeSize;
    uint16_t                    L; /* relevant only for pkcs#3 */
    uint8_t                     Q[TE_MAX_DH_OTHER_INFO_BUF_SIZE_BYTES];
    size_t                      QSize;
    size_t                      clientPrivKeySize;
    size_t                      clientPublKeySize;
    size_t                      serverPrivKeySize;
    size_t                      serverPublKeySize;
    size_t                      clientSecretKeySize;
    size_t                      serverSecretKeySize;
    CCDhHashOpMode_t            hashMode; /* relevant only for ansi942 */
    dhOtherInfo_t               otherInfo;
} dhDataVector_t;

/******************************************************************
 * Externs
 ******************************************************************/

extern CCRndState_t *pRndState_proj;
extern CCRndGenerateVectWorkFunc_t pRndFunc_proj;

/******************************************************************
 * Globals
 ******************************************************************/

static dhDataVector_t pkcs3TestVector = {
                                         .dhMode = CC_DH_PKCS3_mode,
                                         .pGenerator = { 0xc9, 0x16, 0xa6, 0x54, 0x91, 0xa7, 0x1c, 0xdf, 0x9b, 0xf9, 0x59, 0x07, 0x95, 0x06, 0x4f, 0xfa,
                                                         0x95, 0x79, 0xc5, 0x20, 0x47, 0xa4, 0x75, 0xce, 0x49, 0xb5, 0x3c, 0xfa, 0x91, 0xd4, 0xd2, 0xb5,
                                                         0xe5, 0x6b, 0x36, 0x24, 0x5f, 0x90, 0x8e, 0xfb, 0x7a, 0x1b, 0x41, 0xf7, 0x18, 0x41, 0xfc, 0x7b,
                                                         0xa5, 0xb4, 0xc3, 0xe1, 0x71, 0xb4, 0x66, 0x54, 0x02, 0x0a, 0xd3, 0xd9, 0xd2, 0x9d, 0xe6, 0x18,
                                                         0x6d, 0x2a, 0xb7, 0xdb, 0x45, 0xbe, 0xc1, 0x83, 0x7f, 0x94, 0x5b, 0xd7, 0xd8, 0x98, 0xd2, 0xcf,
                                                         0x54, 0x38, 0x39, 0xda, 0x90, 0x86, 0xcc, 0xab, 0x0f, 0x15, 0xf8, 0xb8, 0xbf, 0xde, 0x50, 0x07,
                                                         0x74, 0x45, 0x84, 0x4c, 0x2f, 0x08, 0xb1, 0x2f, 0x40, 0x49, 0x9c, 0xaf, 0xb6, 0xd1, 0x6c, 0xe3,
                                                         0x45, 0xbf, 0xf1, 0x63, 0xcc, 0x77, 0x66, 0x5d, 0x45, 0x35, 0xb9, 0x0a, 0xac, 0x74, 0x14, 0x91,
                                                         0x64, 0x1b, 0x34, 0x50, 0xb4, 0xa0, 0x1e, 0xd9, 0xa9, 0x62, 0x56, 0x57, 0xcb, 0x73, 0x3c, 0x96,
                                                         0x5f, 0x86, 0x7f, 0xc3, 0x66, 0xbf, 0xac, 0x79, 0x21, 0x51, 0x14, 0x3f, 0x37, 0x29, 0xbe, 0x96,
                                                         0xc8, 0xee, 0xf1, 0xaf, 0x4e, 0xc7, 0x9f, 0x83, 0x20, 0xe7, 0xb5, 0xb2, 0x52, 0x57, 0xcc, 0xa8,
                                                         0xb0, 0xf2, 0x4d, 0x88, 0x3e, 0x71, 0xfb, 0xd7, 0x45, 0x4d, 0x96, 0x0b, 0xcb, 0x24, 0x0a, 0x88,
                                                         0x4f, 0xaf, 0xe8, 0x96, 0x79, 0x87, 0x14, 0xf8, 0x1e, 0x3d, 0xf7, 0x2c, 0x48, 0xf7, 0x0e, 0x52,
                                                         0x4e, 0x3d, 0xcb, 0xeb, 0x57, 0x54, 0xb9, 0x90, 0xe1, 0x14, 0x5c, 0x36, 0x7d, 0xc0, 0xa3, 0x5f,
                                                         0xf4, 0xfd, 0xf6, 0x33, 0x23, 0x7e, 0xf2, 0xd0, 0xff, 0x0d, 0xe0, 0xe2, 0xa3, 0xcc, 0x81, 0x86,
                                                         0xbc, 0xde, 0x67, 0x83, 0x03, 0xd6, 0xfa, 0x5b, 0x42, 0xd3, 0x1f, 0xfe, 0xd2, 0x0f, 0x2b, 0x1b, },
                                         .generatorSize = TE_DH_GENERATOR_SIZE_IN_BYTES,
                                         .pPrime = { 0xce, 0xd3, 0x02, 0x09, 0x7d, 0xe5, 0x34, 0xf5, 0x3f, 0x14, 0x2e, 0x7b, 0x3e, 0x15, 0x4c, 0x66,
                                                     0x2c, 0xe1, 0xf0, 0xb7, 0x40, 0x72, 0x68, 0xfa, 0xad, 0xa6, 0xd5, 0xd9, 0x55, 0x1e, 0x7e, 0xfd,
                                                     0x06, 0xbc, 0x4f, 0xb8, 0x27, 0xe9, 0x22, 0x3d, 0x17, 0xfa, 0x4d, 0x8c, 0x8b, 0x8e, 0xce, 0xf6,
                                                     0xc9, 0x49, 0x38, 0x74, 0xa2, 0x77, 0x3b, 0x9a, 0xe1, 0xc0, 0xa7, 0xc8, 0x83, 0xf9, 0xdc, 0xa7,
                                                     0x9a, 0x12, 0xc5, 0x19, 0x5c, 0xfb, 0x40, 0x0c, 0x08, 0x57, 0xa1, 0xf7, 0x8d, 0xf2, 0x10, 0x83,
                                                     0xe8, 0xe7, 0x8a, 0xc1, 0x0c, 0x59, 0xa1, 0xa3, 0x77, 0xb1, 0x9f, 0x0d, 0x0f, 0xf8, 0x27, 0xdd,
                                                     0xdc, 0xed, 0xbf, 0x04, 0x91, 0xa3, 0x00, 0x19, 0x08, 0x2d, 0x7c, 0xc9, 0xda, 0xfb, 0x05, 0x31,
                                                     0xf5, 0x34, 0x0d, 0xaa, 0xd3, 0xbb, 0xc0, 0x5b, 0xfb, 0xad, 0x32, 0x6b, 0x98, 0x00, 0x17, 0x01,
                                                     0x39, 0x61, 0x0e, 0x03, 0x2e, 0xf6, 0x60, 0x30, 0x7b, 0xb9, 0xeb, 0x39, 0x60, 0x1b, 0xc4, 0x7f,
                                                     0xe5, 0xcb, 0x5f, 0xc3, 0xb0, 0x79, 0xdb, 0x04, 0xd2, 0x9a, 0x11, 0x95, 0x3e, 0xa4, 0x33, 0x61,
                                                     0x8e, 0x94, 0x22, 0x9b, 0x0a, 0xd0, 0xfb, 0xda, 0x07, 0xc7, 0x34, 0xfb, 0xa9, 0x94, 0xc8, 0x31,
                                                     0x03, 0xe1, 0x92, 0xac, 0x86, 0xfc, 0x45, 0xe3, 0x79, 0x0b, 0x9e, 0x29, 0x63, 0xe8, 0xcf, 0x26,
                                                     0x05, 0xb3, 0x6e, 0xa9, 0xae, 0x9d, 0xe3, 0xdc, 0x03, 0x43, 0x26, 0xdf, 0x7e, 0x8b, 0xae, 0xcb,
                                                     0xe8, 0x09, 0x04, 0x25, 0xdd, 0x42, 0xb8, 0x59, 0x44, 0xec, 0xc1, 0xc7, 0xbf, 0x78, 0x50, 0x31,
                                                     0xec, 0x6e, 0xa5, 0x5f, 0xe4, 0x4f, 0x79, 0x7b, 0xf3, 0xbf, 0x03, 0xd3, 0xa9, 0x7b, 0x7c, 0x70,
                                                     0xa2, 0x5f, 0xdb, 0x86, 0x96, 0xfa, 0xd1, 0x3f, 0x43, 0xc5, 0xd2, 0x2a, 0xf8, 0xf3, 0x3c, 0x7b, },
                                         .primeSize = TE_DH_PRIME_SIZE_IN_BYTES,
                                         .L = 0,
                                         .clientPrivKeySize = TE_DH_PRIME_SIZE_IN_BYTES,
                                         .clientPublKeySize = TE_DH_PRIME_SIZE_IN_BYTES,
                                         .serverPrivKeySize = TE_DH_PRIME_SIZE_IN_BYTES,
                                         .serverPublKeySize = TE_DH_PRIME_SIZE_IN_BYTES,
                                         .clientSecretKeySize = TE_DH_PRIME_SIZE_IN_BYTES,
                                         .serverSecretKeySize = TE_DH_PRIME_SIZE_IN_BYTES,
};

static dhDataVector_t ansi942TestVector = {
                                           .dhMode = CC_DH_ANSI_X942_mode,
                                           .pGenerator = { 0x47, 0x4b, 0xad, 0x73, 0x20, 0xdb, 0x7e, 0x40, 0x6e, 0x4d, 0x3c, 0x0d, 0xc4, 0xab, 0x6e, 0x8a,
                                                           0x60, 0xd5, 0x74, 0xed, 0x87, 0xcf, 0xf8, 0x68, 0x0e, 0x8e, 0x01, 0x74, 0x3e, 0x57, 0xff, 0xed,
                                                           0x0f, 0x27, 0x6f, 0x07, 0xcb, 0x95, 0x16, 0xa5, 0x42, 0xfb, 0x89, 0x69, 0x9f, 0x4d, 0xc9, 0xe9,
                                                           0x8b, 0xe0, 0x61, 0x95, 0xfa, 0x06, 0xd4, 0x4d, 0xf5, 0xe2, 0x30, 0x8b, 0x7e, 0x07, 0x4d, 0x2d,
                                                           0xaf, 0xe7, 0x52, 0xf2, 0x82, 0xef, 0xdd, 0xb9, 0x7d, 0x57, 0xb3, 0xe4, 0x7f, 0xd2, 0x17, 0x96,
                                                           0xbd, 0xb2, 0x23, 0xa9, 0x99, 0xb6, 0x32, 0x2c, 0x6f, 0x66, 0x84, 0xc2, 0xd7, 0x47, 0xcd, 0xe4,
                                                           0x5f, 0xea, 0x59, 0x5e, 0xfc, 0x15, 0x42, 0x8f, 0xdd, 0x66, 0x1b, 0x5f, 0x04, 0x2d, 0x86, 0xa1,
                                                           0x53, 0xdf, 0x17, 0xc9, 0x5a, 0xab, 0x26, 0xb6, 0x8f, 0xa7, 0x72, 0x34, 0x94, 0xcd, 0x39, 0x73,
                                                           0x2a, 0xa3, 0x94, 0x01, 0xad, 0xa6, 0xd4, 0xc4, 0xc0, 0xfd, 0x81, 0x41, 0x82, 0x51, 0x6b, 0x03,
                                                           0xf5, 0xbe, 0x1e, 0xe6, 0x00, 0x5d, 0x84, 0x54, 0xc4, 0xb4, 0x43, 0x12, 0x6e, 0x26, 0x6e, 0x09,
                                                           0x14, 0xc2, 0xdd, 0xda, 0x08, 0x94, 0xc8, 0x29, 0xd0, 0xa3, 0x20, 0xd3, 0xa5, 0x86, 0x49, 0xf4,
                                                           0x40, 0x3c, 0xdd, 0x41, 0xbd, 0xd8, 0xd4, 0x72, 0x89, 0xc8, 0x9d, 0xf1, 0x61, 0x5e, 0x7d, 0x4b,
                                                           0x32, 0x99, 0xea, 0xa7, 0xa6, 0xc0, 0x45, 0x45, 0xd0, 0x71, 0x36, 0x52, 0x51, 0x2d, 0xdf, 0xd9,
                                                           0xf1, 0xe2, 0xb1, 0xd9, 0xd6, 0x4b, 0x84, 0x83, 0xcc, 0xe6, 0xfa, 0x54, 0x63, 0x49, 0xb8, 0xa6,
                                                           0xe2, 0x6f, 0x6c, 0xd3, 0xed, 0x9d, 0x55, 0x81, 0xe4, 0xac, 0x4d, 0x39, 0x4e, 0x60, 0x80, 0x3e,
                                                           0x2c, 0xa8, 0xdd, 0xac, 0xdc, 0x0c, 0x9f, 0xfc, 0x81, 0x94, 0xf8, 0xd6, 0xd3, 0x9e, 0x04, 0x1b, },
                                           .generatorSize = TE_DH_GENERATOR_SIZE_IN_BYTES,
                                           .pPrime = { 0xdc, 0x44, 0xd2, 0xac, 0x63, 0x20, 0x99, 0x52, 0xed, 0xf8, 0xfa, 0x91, 0x58, 0x33, 0xa3, 0x98,
                                                       0x63, 0x50, 0xcd, 0xe9, 0x6e, 0x3c, 0xf6, 0x93, 0x86, 0x86, 0x75, 0x24, 0x90, 0x79, 0x7c, 0xe6,
                                                       0x03, 0x65, 0x44, 0x7f, 0xcf, 0x1e, 0xee, 0xab, 0xbf, 0x66, 0x54, 0x56, 0xe6, 0xda, 0xe0, 0x8e,
                                                       0xce, 0x13, 0x0f, 0xa1, 0x4d, 0x93, 0x1b, 0xac, 0x71, 0x09, 0xb8, 0xeb, 0x86, 0x48, 0xaa, 0x9e,
                                                       0xcb, 0x69, 0x5a, 0xba, 0x8b, 0xc2, 0x5f, 0x88, 0x77, 0x75, 0xa4, 0x93, 0x0a, 0x2e, 0x87, 0xb4,
                                                       0xb5, 0x3b, 0x97, 0x3b, 0x79, 0xfd, 0x58, 0x07, 0x51, 0xed, 0xab, 0xf7, 0x60, 0xf4, 0xd1, 0x11,
                                                       0x21, 0xbe, 0x92, 0xa2, 0x0e, 0xd5, 0x82, 0xf7, 0xfd, 0x9f, 0x19, 0x73, 0xdc, 0x27, 0x77, 0xa6,
                                                       0xdf, 0xde, 0xe2, 0x8f, 0x30, 0xb5, 0x4b, 0x50, 0x6e, 0xf9, 0x1f, 0x64, 0x77, 0x47, 0xbd, 0x1e,
                                                       0xa0, 0xee, 0x1d, 0x6d, 0x8d, 0x7e, 0x07, 0xb5, 0xe0, 0x57, 0x78, 0x81, 0xdd, 0x63, 0x7b, 0x8a,
                                                       0xb5, 0x80, 0xff, 0xd5, 0x4e, 0x05, 0xbd, 0x9f, 0xef, 0xf2, 0x52, 0xca, 0xeb, 0xd9, 0xf0, 0x13,
                                                       0x46, 0xed, 0xa0, 0x39, 0xb2, 0xd8, 0xaf, 0x20, 0xae, 0x58, 0x6e, 0x60, 0x41, 0x71, 0xca, 0xb6,
                                                       0x14, 0xfd, 0x8b, 0x74, 0x18, 0xe1, 0xdc, 0xd9, 0xf3, 0x1f, 0xea, 0x73, 0xa7, 0xaf, 0x7e, 0x03,
                                                       0x81, 0x4d, 0x5f, 0xf4, 0x08, 0x31, 0x28, 0x3b, 0x6e, 0x55, 0xcc, 0x59, 0x29, 0x42, 0x53, 0x3f,
                                                       0x5c, 0x91, 0x49, 0x01, 0xe9, 0x8c, 0x6e, 0x34, 0xe1, 0x4e, 0x6a, 0x4e, 0x65, 0x31, 0x7d, 0x2a,
                                                       0x4c, 0xa5, 0xf2, 0xe5, 0x3c, 0x41, 0x0e, 0x4b, 0xa8, 0x9a, 0x07, 0x74, 0xe7, 0xe1, 0x6f, 0x20,
                                                       0xbc, 0xd0, 0xde, 0x27, 0x73, 0xff, 0x90, 0x52, 0x7a, 0xe9, 0xce, 0x21, 0x04, 0xc4, 0x17, 0xb3, },
                                           .primeSize = TE_DH_PRIME_SIZE_IN_BYTES,
                                           .clientPrivKeySize = TE_DH_PRIME_SIZE_IN_BYTES,
                                           .clientPublKeySize = TE_DH_PRIME_SIZE_IN_BYTES,
                                           .serverPrivKeySize = TE_DH_PRIME_SIZE_IN_BYTES,
                                           .serverPublKeySize = TE_DH_PRIME_SIZE_IN_BYTES,
                                           .clientSecretKeySize = TE_DH_PRIME_SIZE_IN_BYTES,
                                           .serverSecretKeySize = TE_DH_PRIME_SIZE_IN_BYTES,
                                           .hashMode = CC_DH_HASH_SHA1_mode,
                                           .Q = { 0x8c, 0xc9, 0xf8, 0x84, 0x7d, 0xb8, 0x81, 0x52, 0xf4, 0x18,
                                                  0xfd, 0xe5, 0x84, 0xa6, 0xf8, 0x4d, 0xb6, 0xf3, 0x33, 0xfd, },
                                           .QSize = 20,
                                           .otherInfo = {.algID = { 0x30, 0x09, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3f, 0x01, 0x02, },
                                                         .partyUInfo = { 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, },
                                                         .partyVInfo = { 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, },
                                                         .suppPrivInfo = { 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, },
                                                         .suppPublInfo = { 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, },
                                                         .algIdSize = 11,
                                                         .partyUInfoSize = 7,
                                                         .partyVInfoSize = 7,
                                                         .suppPrivInfoSize = 7,
                                                         .suppPublInfoSize = 7, }
};

/******************************************************************
 * Static Prototypes
 ******************************************************************/

static TE_rc_t dh_pkcs3_exec(void* pContext);

static TE_rc_t dh_ansi942_exec(void* pContext);

/******************************************************************
 * Static functions
 ******************************************************************/

static TE_rc_t dh_pkcs3_exec(void* pContext)
{
    TE_perfIndex_t cookie = 0;
    TE_rc_t res = TE_RC_SUCCESS;
    dhDataVector_t* pDhTestVec = NULL;
    CCDhUserPubKey_t userPublKey;
    CCDhPrimeData_t primeData;
    uint8_t *pClientPrivKey = NULL, *pClientPublKey = NULL, *pServerPrivKey = NULL,
                    *pServerPublKey = NULL, *pClientSecretKey = NULL, *pServerSecretKey = NULL;

    TE_ASSERT(pContext != NULL);

    pDhTestVec = (dhDataVector_t *)pContext;

    TE_ALLOC(pClientPrivKey,pDhTestVec->clientPrivKeySize);
    TE_ALLOC(pClientPublKey,pDhTestVec->clientPublKeySize);
    TE_ALLOC(pServerPrivKey,pDhTestVec->serverPrivKeySize);
    TE_ALLOC(pServerPublKey,pDhTestVec->serverPublKeySize);
    TE_ALLOC(pClientSecretKey,pDhTestVec->clientSecretKeySize);
    TE_ALLOC(pServerSecretKey,pDhTestVec->serverSecretKeySize);

    /* Generating clients public and private keys */
    /*--------------------------------------------*/
    cookie = TE_perfOpenNewEntry("dh", "generate-keys");
    TE_ASSERT(CC_DhPkcs3GeneratePubPrv(pRndFunc_proj,
                                       pRndState_proj,
                                       pDhTestVec->pGenerator,
                                       pDhTestVec->generatorSize,
                                       pDhTestVec->pPrime,
                                       pDhTestVec->primeSize,
                                       pDhTestVec->L, &userPublKey,
                                       &primeData, pClientPrivKey,
                                       &pDhTestVec->clientPrivKeySize,
                                       pClientPublKey,
                                       &pDhTestVec->clientPublKeySize) == CC_OK);
    TE_perfCloseEntry(cookie);

    /* Generating servers public and private keys */
    /*--------------------------------------------*/
    cookie = TE_perfOpenNewEntry("dh", "generate-keys");
    TE_ASSERT(CC_DhPkcs3GeneratePubPrv(pRndFunc_proj,
                                       pRndState_proj,
                                       pDhTestVec->pGenerator,
                                       pDhTestVec->generatorSize,
                                       pDhTestVec->pPrime,
                                       pDhTestVec->primeSize,
                                       pDhTestVec->L, &userPublKey,
                                       &primeData, pServerPrivKey,
                                       &pDhTestVec->serverPrivKeySize,
                                       pServerPublKey,
                                       &pDhTestVec->serverPublKeySize) == CC_OK);
    TE_perfCloseEntry(cookie);

    /* Generating clients secret key */
    /*-------------------------------*/
    cookie = TE_perfOpenNewEntry("dh", "secret-key");
    TE_ASSERT(CC_DhGetSecretKey(pClientPrivKey,
                                pDhTestVec->clientPrivKeySize,
                                pServerPublKey,
                                pDhTestVec->serverPublKeySize,
                                pDhTestVec->pPrime,
                                pDhTestVec->primeSize,
                                &userPublKey,
                                &primeData,
                                pClientSecretKey,
                                &pDhTestVec->clientSecretKeySize) == CC_OK);
    TE_perfCloseEntry(cookie);

    /* Generating servers secret key */
    /*-------------------------------*/
    cookie = TE_perfOpenNewEntry("dh", "secret-key");
    TE_ASSERT(CC_DhGetSecretKey(pServerPrivKey,
                                pDhTestVec->serverPrivKeySize,
                                pClientPublKey,
                                pDhTestVec->clientPublKeySize,
                                pDhTestVec->pPrime,
                                pDhTestVec->primeSize,
                                &userPublKey,
                                &primeData,
                                pServerSecretKey,
                                &pDhTestVec->serverSecretKeySize) == CC_OK);
    TE_perfCloseEntry(cookie);

    /* Comparing clients and servers secret keys */
    /*-------------------------------------------*/
    TE_ASSERT(memcmp(pServerSecretKey, pClientSecretKey, pDhTestVec->serverSecretKeySize) == 0);

bail:
    TE_FREE(pClientPrivKey);
    TE_FREE(pClientPublKey);
    TE_FREE(pServerPrivKey);
    TE_FREE(pServerPublKey);
    TE_FREE(pClientSecretKey);
    TE_FREE(pServerSecretKey);
    return res;
}


static TE_rc_t dh_ansi942_exec(void* pContext)
{
    TE_perfIndex_t cookie = 0;
    TE_rc_t res = TE_RC_SUCCESS;
    dhDataVector_t* pDhTestVec = NULL;
    CCDhUserPubKey_t userPublKey;
    CCDhPrimeData_t primeData;
    CCDhTemp_t tempBuff;
    dhOtherInfo_t* pTestOtherInfo = NULL;
    CCDhOtherInfo_t otherInfo;
    uint8_t *pClientPrivKey = NULL, *pClientPublKey = NULL, *pServerPrivKey = NULL,
                    *pServerPublKey = NULL, *pClientSecretKey = NULL, *pServerSecretKey = NULL;

    TE_ASSERT(pContext != NULL);

    pDhTestVec = (dhDataVector_t *)pContext;
    pTestOtherInfo = &(pDhTestVec->otherInfo);

    TE_ALLOC(pClientPrivKey,pDhTestVec->clientPrivKeySize);
    TE_ALLOC(pClientPublKey,pDhTestVec->clientPublKeySize);
    TE_ALLOC(pServerPrivKey,pDhTestVec->serverPrivKeySize);
    TE_ALLOC(pServerPublKey,pDhTestVec->serverPublKeySize);
    TE_ALLOC(pClientSecretKey,pDhTestVec->clientSecretKeySize);
    TE_ALLOC(pServerSecretKey,pDhTestVec->serverSecretKeySize);

    /* Other info initialization for generating secret keys */
    /*------------------------------------------------------*/
    otherInfo.dataPointers[CC_KDF_ALGORITHM_ID] = pTestOtherInfo->algID;
    otherInfo.dataSizes[CC_KDF_ALGORITHM_ID] = pTestOtherInfo->algIdSize;

    otherInfo.dataPointers[CC_KDF_PARTY_U_INFO] = pTestOtherInfo->partyUInfo;
    otherInfo.dataSizes[CC_KDF_PARTY_U_INFO] = pTestOtherInfo->partyUInfoSize;

    otherInfo.dataPointers[CC_KDF_PARTY_V_INFO] = pTestOtherInfo->partyVInfo;
    otherInfo.dataSizes[CC_KDF_PARTY_V_INFO] = pTestOtherInfo->partyVInfoSize;

    otherInfo.dataPointers[CC_KDF_SUPP_PRIV_INFO] = pTestOtherInfo->suppPrivInfo;
    otherInfo.dataSizes[CC_KDF_SUPP_PRIV_INFO] = pTestOtherInfo->suppPrivInfoSize;

    otherInfo.dataPointers[CC_KDF_SUPP_PUB_INFO] = pTestOtherInfo->suppPublInfo;
    otherInfo.dataSizes[CC_KDF_SUPP_PUB_INFO] = pTestOtherInfo->suppPublInfoSize;

    /* Generating clients public and private keys */
    /*--------------------------------------------*/
    cookie = TE_perfOpenNewEntry("dh", "generate-keys");
    TE_ASSERT(CC_DhAnsiX942GeneratePubPrv(pRndFunc_proj,
                                          pRndState_proj,
                                          pDhTestVec->pGenerator,
                                          pDhTestVec->generatorSize,
                                          pDhTestVec->pPrime,
                                          pDhTestVec->primeSize,
                                          pDhTestVec->Q, pDhTestVec->QSize,
                                          &userPublKey,
                                          &primeData, pClientPrivKey,
                                          &pDhTestVec->clientPrivKeySize,
                                          pClientPublKey,
                                          &pDhTestVec->clientPublKeySize) == CC_OK);
    TE_perfCloseEntry(cookie);

    /* Generating servers public and private keys */
    /*--------------------------------------------*/
    cookie = TE_perfOpenNewEntry("dh", "generate-keys");
    TE_ASSERT(CC_DhAnsiX942GeneratePubPrv(pRndFunc_proj,
                                          pRndState_proj,
                                          pDhTestVec->pGenerator,
                                          pDhTestVec->generatorSize,
                                          pDhTestVec->pPrime,
                                          pDhTestVec->primeSize,
                                          pDhTestVec->Q, pDhTestVec->QSize,
                                          &userPublKey,
                                          &primeData, pServerPrivKey,
                                          &pDhTestVec->serverPrivKeySize,
                                          pServerPublKey,
                                          &pDhTestVec->serverPublKeySize) == CC_OK);
    TE_perfCloseEntry(cookie);

    /* Checking clients public key */
    /*-----------------------------*/
    cookie = TE_perfOpenNewEntry("dh", "publ-key-check");
    TE_ASSERT(CC_DhCheckPubKey(pDhTestVec->pPrime,
                               pDhTestVec->primeSize,
                               pDhTestVec->Q, pDhTestVec->QSize,
                               pClientPublKey,
                               pDhTestVec->clientPublKeySize,
                               &tempBuff) == CC_OK);
    TE_perfCloseEntry(cookie);

    /* Checking servers public key */
    /*-----------------------------*/
    cookie = TE_perfOpenNewEntry("dh", "publ-key-check");
    TE_ASSERT(CC_DhCheckPubKey(pDhTestVec->pPrime,
                               pDhTestVec->primeSize,
                               pDhTestVec->Q, pDhTestVec->QSize,
                               pServerPublKey,
                               pDhTestVec->serverPublKeySize,
                               &tempBuff) == CC_OK);
    TE_perfCloseEntry(cookie);

    /* Generating clients secret key */
    /*-------------------------------*/
    cookie = TE_perfOpenNewEntry("dh", "get-secret-key");
    TE_ASSERT(CC_DhX942GetSecretDataAsn1(pClientPrivKey,
                                         pDhTestVec->clientPrivKeySize,
                                         pServerPublKey,
                                         pDhTestVec->serverPublKeySize,
                                         pDhTestVec->pPrime,
                                         pDhTestVec->primeSize,
                                         &otherInfo,
                                         pDhTestVec->hashMode,
                                         &tempBuff,
                                         pClientSecretKey,
                                         pDhTestVec->clientSecretKeySize) == CC_OK);
    TE_perfCloseEntry(cookie);

    /* Generating servers secret key */
    /*-------------------------------*/
    cookie = TE_perfOpenNewEntry("dh", "get-secret-key");
    TE_ASSERT(CC_DhX942GetSecretDataAsn1(pServerPrivKey,
                                         pDhTestVec->serverPrivKeySize,
                                         pClientPublKey,
                                         pDhTestVec->clientPublKeySize,
                                         pDhTestVec->pPrime,
                                         pDhTestVec->primeSize,
                                         &otherInfo,
                                         pDhTestVec->hashMode,
                                         &tempBuff,
                                         pServerSecretKey,
                                         pDhTestVec->serverSecretKeySize) == CC_OK);
    TE_perfCloseEntry(cookie);

    /* Comparing clients and servers secret keys */
    /*-------------------------------------------*/
    TE_ASSERT(memcmp(pServerSecretKey, pClientSecretKey, pDhTestVec->serverSecretKeySize) == 0);

bail:
    TE_FREE(pClientPrivKey);
    TE_FREE(pClientPublKey);
    TE_FREE(pServerPrivKey);
    TE_FREE(pServerPublKey);
    TE_FREE(pClientSecretKey);
    TE_FREE(pServerSecretKey);
    return res;
}

/******************************************************************
 * Public
 ******************************************************************/

int TE_init_dh_test(void)
{
    TE_rc_t res = TE_RC_SUCCESS;

    TE_perfEntryInit("dh", "generate-keys");
    TE_perfEntryInit("dh", "publ-key-check");
    TE_perfEntryInit("dh", "secret-key");
    TE_perfEntryInit("dh", "get-secret-key");

    TE_ASSERT(TE_registerFlow("dh",
                              "pkcs3",
                              "2048bits-prime",
                              NULL,
                              dh_pkcs3_exec,
                              NULL,
                              NULL,
                              &pkcs3TestVector) == TE_RC_SUCCESS);

    TE_ASSERT(TE_registerFlow("dh",
                              "ansi942",
                              "2048bits-prime",
                              NULL,
                              dh_ansi942_exec,
                              NULL,
                              NULL,
                              &ansi942TestVector) == TE_RC_SUCCESS);

bail:
    return res;
}
