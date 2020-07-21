/*
 * Copyright (c) 2001-2020, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _TEST_PROJ_RND_H_
#define _TEST_PROJ_RND_H_

#include "cc_rnd.h"

#define TEST_PROJ_RND_TRNG_FE_RETRY 2

/****************************************************************************/
/*   							External API  								*/
/****************************************************************************/
/*******************************************************************************/

/*!
@brief This function is a wrapper to the CC_RndInstantiation
 that enable rerun the CC_RndInstantiation function in case of TRNG FE error.
@return \c CC_OK on success.
@return A non-zero value from cc_rnd_error.h on failure.
*/
CCError_t Test_ProjCC_RndInstantiation(
        CCRndGenerateVectWorkFunc_t        *f_rng, /*!< [in] - Pointer to DRBG function*/
                        void               *p_rng,         /*!< [in/out] Pointer to the RND context buffer allocated by the user, which is used to
                                           maintain the RND state. This context must be saved and provided as a
                                           parameter to any API that uses the RND module.
                                           \note The buffer and it's members must be allocated.
                                           \note the context must be cleared before sent to the function. */

                        CCTrngWorkBuff_t  *pTrngWorkBuff       /*!< [in/out] Scratchpad for the RND module's work. */
);

/*!
@brief This function is a wrapper to the Test_ProjCC_RndReseeding
 that enable rerun the Test_ProjCC_RndReseeding function in case of TRNG FE error.

@return \c CC_OK on success.
@return A non-zero value from cc_rnd_error.h on failure.
*/
CCError_t Test_ProjCC_RndReseeding(
                        CCRndGenerateVectWorkFunc_t *f_rng, /*!< [in] - Pointer to DRBG function*/
                        void *p_rng,                       /*!< [in/out]  - Pointer to the random context - the input to f_rng. */
                        CCTrngWorkBuff_t  *pTrngWorkBuff      /*!< [in/out] Scratchpad for the RND module's work. */
);

#endif /*_TEST_PROJ_RND_H_ */

