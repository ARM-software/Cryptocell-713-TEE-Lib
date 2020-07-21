/*
 * Copyright (c) 2001-2020, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _TEST_PROJ_TRNG_H_
#define _TEST_PROJ_TRNG_H_

/****************************************************************************/
/*   							External API  								*/
/****************************************************************************/
/*******************************************************************************/

/*!
 @brief The function is a wrapper to the CC_TrngEntropyGet
 that enable rerun the CC_TrngEntropyGet function in case of TRNG FE error.
 @return \c CC_OK on success.
 @return A non-zero value from cc_trng_error.h on failure.

*/
CCError_t Test_ProjCC_TrngEntropyGet(
            /*![in] The required entropy size in bits.Size must be bigger than CC_TRNG_MIN_ENTROPY_SIZE, and smaller than CC_TRNG_MAX_ENTROPY_SIZE. */
                            size_t    entropySizeBits,
                             /*! [out] Pointer to the entropy buffer. */
                            uint8_t   *pOutEntropy,
                            /*![in] The entropy buffer size in bytes. The size must be big enough to hold the required entropySizeBits. */
                            size_t    outEntropySizeBytes);


#endif /*_TEST_PROJ_TRNG_H_ */

