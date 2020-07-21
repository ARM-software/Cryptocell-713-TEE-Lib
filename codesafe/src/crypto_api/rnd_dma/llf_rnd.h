/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef LLF_RND_H
#define LLF_RND_H

#include "cc_rnd_local.h"

#ifdef __cplusplus
extern "C"
{
#endif



/************************ Defines ******************************/

/* macro for calculation max. allowed time for */
#define LLF_RND_CalcMaxTrngTime(ehrSamples, SubSamplingRatio) \
	(((ehrSamples) * LLF_RND_TRNG_MAX_TIME_COEFF * \
	LLF_RND_TRNG_VON_NEUMAN_COEFF * \
	LLF_RND_HW_TRNG_EHR_WIDTH_IN_BITS * \
	(SubSamplingRatio)) >> LLF_RND_TRNG_MAX_TIME_SCALE)


/************************ Enums ********************************/
/************************ Typedefs  ****************************/
/************************ Structs  *****************************/

/******************** Public Functions *************************/
/************************************************************************************/
/**
 * @brief The LLF_RND_TurnOffTrng stops the hardware random bits collection
 *        closes RND clocks and releases HW semaphore.
 *
 *
 *
 * @return CCError_t - On success CC_OK is returned, on failure a
 *                        value MODULE_* as defined in ...
 */
void LLF_RND_TurnOffTrng(void);


CCError_t LLF_RND_GetFastestRosc(CCTrngParams_t *pTrngParams,
                                 uint32_t *rosc_ptr    /*in/out*/);

CCError_t LLF_RND_GetRoscSampleCnt(
					 uint32_t rosc,
					 CCTrngParams_t *pTrngParams);

CCError_t LLF_RND_WaitRngInterrupt(uint32_t *isr_ptr);

/**
* @brief: The function performs CPRNGT (Continued PRNG Test) according
*         to NIST 900-80 and FIPS (if defined) standards.
*
* @param[in] prev_ptr - The pointer to previous saved generated random
*                       value of size 16 bytes.
* @param[in] buff_ptr - The pointer to generated random buffer.
* @param[in] last_ptr - The pointer to last generated random block
*                       of size 16 bytes used for output last bytes.
* @param[in] countBlocks - The count of generated random blocks, including
*                          the last block. Assumed countBlocks > 0.
*
* @return CCError_t - On success CC_OK is returned, on failure a
*                        value MODULE_* as defined in cc_error.h
*/
CCError_t LLF_RND_RndCprngt(uint8_t            *prev_ptr,        /*in*/
				  uint8_t            *buff_ptr,        /*in*/
				  uint8_t            *last_ptr,        /*in*/
				  int32_t             countBlocks);   /*in*/




#ifdef __cplusplus
#endif

#endif
