/*
 * Copyright (c) 2001-2020, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include "tests_log.h"
#include "test_proj_rnd.h"
#include "test_proj_trng.h"
#include "cc_trng_fe.h"
#include "cc_trng_error.h"

CCError_t Test_ProjCC_TrngEntropyGet(
            /*![in] The required entropy size in bits.Size must be bigger than CC_TRNG_MIN_ENTROPY_SIZE, and smaller than CC_TRNG_MAX_ENTROPY_SIZE. */
                            size_t    entropySizeBits,
                             /*! [out] Pointer to the entropy buffer. */
                            uint8_t   *pOutEntropy,
                            /*![in] The entropy buffer size in bytes. The size must be big enough to hold the required entropySizeBits. */
                            size_t    outEntropySizeBytes)
{
    uint32_t  rc = 0;

    for (int i = 0; i < TEST_PROJ_RND_TRNG_FE_RETRY; i++) {
        /* in case of LLF_RND_GetTrngSource failure enable more than 1 run */
        rc = CC_TrngEntropyGet(entropySizeBits,
                pOutEntropy, outEntropySizeBytes);
        if(rc != CC_TRNG_ERRORS_ERROR) {
            break;
        }

        TEST_LOG_ERROR("\nCC_TrngEntropyGet failure, retry the test\n");
    }

    return rc;
}

