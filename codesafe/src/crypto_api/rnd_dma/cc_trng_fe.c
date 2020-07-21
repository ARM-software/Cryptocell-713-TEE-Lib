/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include "cc_pal_types.h"
#include "cc_pal_mem.h"
#include "cc_rnd_common_trng.h"
#include "cc_rng_plat.h"
#include "llf_rnd_trng.h"
#include "llf_rnd_hwdefs.h"
#include "cc_trng_fe.h"
#include "cc_trng_error.h"

/*! This macro calculates the number of full EHRs from bits. */
#define TRNG_FE_SOURCE_WORD_SIZE     (LLF_RND_HW_SAMPLES_NUM_ON_FE_MODE * LLF_RND_HW_TRNG_EHR_WIDTH_IN_WORDS)
#define TRNG_FE_SOURCE_BYTE_SIZE     (TRNG_FE_SOURCE_WORD_SIZE * CC_32BIT_WORD_SIZE)
#define TRNG_FE_SOURCE_BIT_SIZE      (TRNG_FE_SOURCE_BYTE_SIZE * CC_BITS_IN_BYTE)

/*! This macro calculates the number of full getTrngSource cycles. */
#define CALC_FULL_TRNG_FE(numBits)        ((numBits)/TRNG_FE_SOURCE_BIT_SIZE + (((numBits) & (TRNG_FE_SOURCE_BIT_SIZE-1)) != 0))

/* Note   The function should not support FIPS. */
CCError_t CC_TrngEntropyGet(size_t    entropySizeBits,
                            uint8_t   *pOutEntropy,
                            size_t    outEntropySizeBytes)
{
    CCError_t  error = CC_OK;
    uint32_t  ehrLoops = 0;
    uint32_t  loopsNum = 0;
    CCTrngParams_t  trngParams;
    CCTrngState_t  trngState;
    uint32_t    ehrBuffer[TRNG_FE_SOURCE_WORD_SIZE + CC_RND_TRNG_SRC_INNER_OFFSET_WORDS] = {0};
    uint32_t    entropyByteSize = 0;
    uint32_t    actEhrByteSize = 0;
    uint8_t     lastValidNumBits = 0;
    uint8_t     lastValidNumBytes = 0;
    uint32_t    *pBuff;
    uint32_t    outBuffSize;

    /* Validate inputs */
    if ((pOutEntropy == NULL) ||
            (entropySizeBits == CC_TRNG_MIN_ENTROPY_SIZE) ||
            (entropySizeBits > CC_TRNG_MAX_ENTROPY_SIZE) ||
            (outEntropySizeBytes * CC_BITS_IN_BYTE < entropySizeBits)) {
        return CC_TRNG_INVALID_PARAMS_ERROR;
    }

    CC_PalMemSetZero((uint8_t *)&trngParams, sizeof(CCTrngParams_t));
    CC_PalMemSetZero((uint8_t *)&trngState, sizeof(CCTrngState_t));

    /* Get TRNG parameters from user H file defines */
    error = RNG_PLAT_TrngUserParams(&trngParams);
    if (error != CC_OK) {
        return error;
    }

    actEhrByteSize = TRNG_FE_SOURCE_BYTE_SIZE;
    loopsNum = CALC_FULL_TRNG_FE(entropySizeBits);
    entropyByteSize = CALC_FULL_BYTES(entropySizeBits);
    lastValidNumBits = entropySizeBits % CC_BITS_IN_BYTE; /* result range is 0 - 7 */
    lastValidNumBytes = entropyByteSize % TRNG_FE_SOURCE_BYTE_SIZE;

    for (ehrLoops = 0; ehrLoops < loopsNum; ehrLoops++) {
        if ((ehrLoops == (loopsNum - 1)) && (lastValidNumBytes != 0)) {
            actEhrByteSize = lastValidNumBytes;
        }
        error = LLF_RND_GetTrngSource(
                &trngState,
                &trngParams,
                &pBuff,
                &outBuffSize,
                ehrBuffer,
                CC_FALSE);
        if (error != CC_OK) {
            error = CC_TRNG_ERRORS_ERROR;
            goto End;
        }
        CC_PalMemCopy(&pOutEntropy[ehrLoops * TRNG_FE_SOURCE_BYTE_SIZE],
                      (uint8_t *)(pBuff+CC_RND_TRNG_SRC_INNER_OFFSET_WORDS),
                      actEhrByteSize);
    }

    if (lastValidNumBits > 0) {
        pOutEntropy[entropyByteSize-1] &= ((1 << lastValidNumBits) - 1);
    }

    End:
    if (error != CC_OK) {
        CC_PalMemSetZero(pOutEntropy, outEntropySizeBytes);
    }

    return error;

}
