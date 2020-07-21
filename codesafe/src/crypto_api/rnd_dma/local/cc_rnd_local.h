/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _CC_RND_LOCAL_H
#define _CC_RND_LOCAL_H

#ifdef __cplusplus
extern "C"
{
#endif


#include "cc_rnd_common.h"
#include "cc_pal_trng.h"

/************************ Defines ****************************/


/*************************************************************/
/****** Common definitions for RND_DMA and non DMA     *******/
/*************************************************************/

#define CC_RND_VECT_IN_RANGE_MAX_COUNT_OF_TRIES    100

#define CC_RND_BASIC_BLOCK_SIZE_IN_WORDS 4
#define CC_RND_BASIC_BLOCK_SIZE_IN_BYTES (CC_RND_BASIC_BLOCK_SIZE_IN_WORDS*sizeof(uint32_t))
#define CC_RND_ENTROPY_BLOCK_SIZE_IN_WORDS 4
#define CC_RND_ENTROPY_BLOCK_SIZE_IN_BYTES (CC_RND_ENTROPY_BLOCK_SIZE_IN_WORDS*sizeof(uint32_t))

/* Bit-fields of Instantiation steps in the StateFlag:
    - b'0: 0 - not instantiated, 1 - instantiated normally;
    - b'1: 1 - loss samples, 0 - no loss;
    - b'2: 1 - time exceeding, 0 - no time exceeding.
    In case of sample loss or time exceed b`0 must be 0 */
#define CC_RND_NOT_INSTANTIATED             	0UL
#define CC_RND_INSTANTIATED                	1UL
#define CC_RND_KAT_DRBG_Mode 	          (1UL << 8)

/* The bit-field in the StateFlag, defining that the previous generated random
   block is valid for comparison with current block or not */
#define CC_RND_PreviousIsValid          (1UL << 16)


/* max size of KAT entropy and nonce data in words on SWEE and FE modes*/
#define CC_RND_ENTROPY_TEMP_BUFFER_MAX_SIZE_WORDS  126


/* Validation tag for random working state: should be set by:   	      *
   RndInstantiateOrReseed function on not continued mode or by           *
*  LLF_RND_StartTrngHW function on continued mode       		      */
#define CC_RND_WORK_STATE_VALID_TAG  0X0123ABCD

/*Values for entropy flag*/
#define LLF_RNG_ENTROPY_FLAG_REQUIRED   0x0
#define LLF_RNG_ENTROPY_FLAG_LOW        0x1
#define LLF_RNG_ENTROPY_FLAG_NULL       0x2
#define LLF_RNG_ENTROPY_FLAG_KAT_MODE   0x3

#define LLF_RNG_MAX_COLLECTION_ITERATION_SIZE 0x5

#define LLF_RND_MAX_NUM_OF_ROSCS 0x4
/************************ Enums ********************************/


/************************ Structs  ******************************/


/************************ Typedefs  ****************************/

/************************ Public Variables **********************/

/************************ Public Functions **********************/

/**********************************************************************************************************/
/*!
@brief Generates a random vector with specific limitations by testing candidates (described and used in FIPS Publication 186-4: Digital
Signature Standard (DSS): B.1.2, B.4.2 etc.).

This function draws a random vector, compare it to the range limits, and if within range - return it in rndVect_ptr.
If outside the range, the function continues retrying until a conforming vector is found, or the maximal retries limit is exceeded.
If maxVect_ptr is provided, rndSizeInBits specifies its size, and the output vector must conform to the range [1 < rndVect < maxVect_ptr].
If maxVect_ptr is NULL, rndSizeInBits specifies the exact required vector size, and the output vector must be the exact same
bit size (with its most significant bit = 1).
\note The RND module must be instantiated prior to invocation of this API.

@return CC_OK on success.
@return A non-zero value from cc_rnd_error.h on failure.
*/
CIMPORT_C CCError_t CC_RndGenerateVectorInRange(
                    CCRndGenerateVectWorkFunc_t f_rng, /*!< [in] - Pointer to DRBG function*/
                    void *p_rng,                           /*!< [in/out]  - Pointer to the random context - the input to f_rng. */
                    size_t   rndSizeInBits,                 /*!< [in]  The size in bits of the random vector required. The allowed size in range  2 <= rndSizeInBits < 2^19-1, bits. */
                    uint8_t  *maxVect_ptr,                  /*!< [in]  Pointer to the vector defining the upper limit for the random vector output, Given as little-endian byte array.
                                                                       If not NULL, its actual size is treated as [(rndSizeInBits+7)/8] bytes. */
                    uint8_t  *rndVect_ptr                   /*!< [in/out] Pointer to the output buffer for the random vector. Must be at least [(rndSizeInBits+7)/8] bytes.
                                                                 Treated as little-endian byte array. */
);

#ifdef __cplusplus
}
#endif

#endif


