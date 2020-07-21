/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include <stdio.h>
#include <stdint.h>

#include "test_engine.h"

#include "cc_sm3.h"
#include "te_sm3.h"

/******************************************************************
 * Defines
 ******************************************************************/
#define SM3_TV_MAX_DATA_SIZE    64
#define SM3_TV_DIGEST_SIZE      32

/******************************************************************
 * Enums
 ******************************************************************/
/*! The SM3 test vectors. */
typedef enum {
    SM3_TV_SHORT_VECTOR     = 0,           /*!< Short vector - 3bytes. */
    SM3_TV_LONG_VECTOR      = 1,           /*!< Long vector - 64bytes. */

    /*! The maximal number of SM3 test vectors. */
    SM3_TV_NUM_OF_VECTORS,
    /*! Reserved. */
    SM3_TV_LAST_VECTOR      = 0x7FFFFFFF
}TVSm3Vectors_t;

/******************************************************************
 * Types
 ******************************************************************/
typedef struct Sm3Vector_t{
    TVSm3Vectors_t vectorType;
    size_t  dataSize;
    uint8_t dataIn[SM3_TV_MAX_DATA_SIZE];
    uint8_t dataRef[SM3_TV_DIGEST_SIZE];
    uint8_t dataOut[SM3_TV_DIGEST_SIZE];
} Sm3Vector_t;

/******************************************************************
 * Externs
 ******************************************************************/

/******************************************************************
 * Globals
 ******************************************************************/


static Sm3Vector_t sm3_3bytes_vector = {
    .dataSize = 3,
    /* Input */
    .dataIn = {0x61, 0x62, 0x63},
    /* Expected results */
    .dataRef = {0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9, 0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2,
                0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2, 0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0 },
    /* Output */
    .dataOut = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
};

static Sm3Vector_t sm3_64bytes_vector = {
    .dataSize = 64,
    /* Input */
    .dataIn = {0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
               0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
               0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
               0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64},
    /* Expected results */
    .dataRef = {0xde, 0xbe, 0x9f, 0xf9, 0x22, 0x75, 0xb8, 0xa1, 0x38, 0x60, 0x48, 0x89, 0xc1, 0x8e, 0x5a, 0x4d,
                0x6f, 0xdb, 0x70, 0xe5, 0x38, 0x7e, 0x57, 0x65, 0x29, 0x3d, 0xcb, 0xa3, 0x9c, 0x0c, 0x57, 0x32},
    /* Output */
    .dataOut = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
};

/******************************************************************
 * Static Prototypes
 ******************************************************************/
static TE_rc_t sm3_prepare(void *pContext);
static TE_rc_t sm3_execute(void *pContext);
static TE_rc_t sm3_verify(void *pContext);
static TE_rc_t sm3_clean(void *pContext);

/******************************************************************
 * Static functions
 ******************************************************************/
static TE_rc_t sm3_prepare(void *pContext)
{
    TE_rc_t res = TE_RC_SUCCESS;
    TE_UNUSED(pContext);

    goto bail;
bail:
    return res;
}

static TE_rc_t sm3_execute(void *pContext)
{
    TE_rc_t res = TE_RC_SUCCESS;
    TE_perfIndex_t cookie;
    Sm3Vector_t *sm3_vec = (Sm3Vector_t *)pContext;

    if(sm3_vec->vectorType == SM3_TV_SHORT_VECTOR) {
            cookie = TE_perfOpenNewEntry("sm3", "short");
    } else {
            cookie = TE_perfOpenNewEntry("sm3", "long");
    }

    /* test SM3 integrated API */
    TE_ASSERT(CC_Sm3((uint8_t *)&(sm3_vec->dataIn), sm3_vec->dataSize, (uint8_t *)&(sm3_vec->dataOut)) == CC_OK);

    TE_perfCloseEntry(cookie);

    goto bail;

bail:
    return res;
}

static TE_rc_t sm3_verify(void *pContext)
{
    TE_rc_t res = TE_RC_SUCCESS;
    Sm3Vector_t *sm3_vec = (Sm3Vector_t *)pContext;

    TE_ASSERT( memcmp((uint8_t *)&(sm3_vec->dataOut), (uint8_t *)&(sm3_vec->dataRef), SM3_TV_DIGEST_SIZE) == 0);

    goto bail;
bail:
    return res;
}

static TE_rc_t sm3_clean(void *pContext)
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
int TE_init_sm3_test(void)
{
    TE_rc_t res = TE_RC_SUCCESS;

    TE_perfEntryInit("sm3", "short");
    TE_perfEntryInit("sm3", "long");

    TE_ASSERT(TE_registerFlow("sm3",
                              "short",
                              "none",
                              sm3_prepare,
                              sm3_execute,
                              sm3_verify,
                              sm3_clean,
                              &sm3_3bytes_vector) == TE_RC_SUCCESS);

    TE_ASSERT(TE_registerFlow("sm3",
                              "long",
                              "none",
                              sm3_prepare,
                              sm3_execute,
                              sm3_verify,
                              sm3_clean,
                              &sm3_64bytes_vector) == TE_RC_SUCCESS);

    goto bail;

bail:
    return res;
}

