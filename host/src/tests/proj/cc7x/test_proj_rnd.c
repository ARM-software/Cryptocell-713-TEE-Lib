/*
 * Copyright (c) 2001-2020, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include "tests_log.h"
#include "test_proj_rnd.h"
#include "cc_rnd_error.h"

CCError_t Test_ProjCC_RndInstantiation(
        CCRndGenerateVectWorkFunc_t        *f_rng, /*!< [in] - Pointer to DRBG function*/
                        void               *p_rng,         /*!< [in/out] Pointer to the RND context buffer allocated by the user, which is used to
                                           maintain the RND state. This context must be saved and provided as a
                                           parameter to any API that uses the RND module.
                                           \note The buffer and it's members must be allocated.
                                           \note the context must be cleared before sent to the function. */
                        CCTrngWorkBuff_t  *pTrngWorkBuff)       /*!< [in/out] Scratchpad for the RND module's work. */
{
    uint32_t  rc = 0;

    for (int i = 0; i < TEST_PROJ_RND_TRNG_FE_RETRY; i++) {
        /* in case of LLF_RND_GetTrngSource failure enable more than 1 run */
        rc = CC_RndInstantiation(f_rng,
                p_rng, pTrngWorkBuff);
        if(rc != CC_RND_TRNG_ERRORS_ERROR) {
            break;
        }

        TEST_LOG_ERROR("\nCC_RndInstantiation failure, retry the test\n");
    }

    return rc;
}

CCError_t Test_ProjCC_RndReseeding(
                        CCRndGenerateVectWorkFunc_t *f_rng, /*!< [in] - Pointer to DRBG function*/
                        void *p_rng,                       /*!< [in/out]  - Pointer to the random context - the input to f_rng. */
                        CCTrngWorkBuff_t  *pTrngWorkBuff)      /*!< [in/out] Scratchpad for the RND module's work. */
{
    uint32_t  rc = 0;

    for (int i = 0; i < TEST_PROJ_RND_TRNG_FE_RETRY; i++) {
        /* in case of LLF_RND_GetTrngSource failure enable more than 1 run */
        rc = CC_RndReseeding(f_rng,
                p_rng, pTrngWorkBuff);
        if(rc != CC_RND_TRNG_ERRORS_ERROR) {
            break;
        }

        TEST_LOG_ERROR("\nCC_RndReseeding failure, retry the test\n");
    }

    return rc;
}
