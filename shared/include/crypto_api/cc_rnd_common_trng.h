/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _CC_RND_COMMON_TRNG_H
#define _CC_RND_COMMON_TRNG_H
/*!
 @file
 @brief This file contains the CryptoCell true-random-number generation definitions.
 The true-random-number generation module defines the database used for the TRNG operations.
 */

/*!
 @addtogroup cc_rnd_defines
 @{
*/

#include "cc_error.h"
#include "cc_pal_types_plat.h"
#include "cc_pal_trng.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*   Definitions of temp buffer for RND_DMA  */
/*******************************************************************/
/*   Definitions of temp buffer for DMA  */
/*! The size of the temporary buffer in words. */
#define CC_TRNG_WORK_BUFFER_SIZE_WORDS 136

/* RND source buffer inner (entrpopy) offset       */
/*! The definition of the internal offset in words. */
#define CC_RND_TRNG_SRC_INNER_OFFSET_WORDS    2
/*! The definition of the internal offset in bytes. */
#define CC_RND_TRNG_SRC_INNER_OFFSET_BYTES    (CC_RND_TRNG_SRC_INNER_OFFSET_WORDS*sizeof(uint32_t))

/************************ Structs  *****************************/

/*! The definition of the RAM buffer, for internal use in instantiation or reseeding operations. */
typedef struct CCTrngWorkBuff_t
{
    /*! Internal buffer. */
    uint32_t ccTrngIntWorkBuff[CC_TRNG_WORK_BUFFER_SIZE_WORDS];
}CCTrngWorkBuff_t;


/*! The CC Random Generator Parameters structure CCTrngParams_t -
 containing the user given parameters and characterization values. */

typedef struct  CCTrngParams_t
{
    /*! User provided parameters*/
    CC_PalTrngParams_t  userParams ;
    /*! Valid ring oscillator lengths: bits 0,1,2,3  */
    uint32_t  RoscsAllowed  ;
    /*! Sampling interval: count of ring oscillator cycles between
    consecutive bits sampling */
    uint32_t  SubSamplingRatio;

}CCTrngParams_t;


/*!
The structure for the RND state. This includes internal data that must be saved by the user between boots.
 */
typedef  struct CCTrngState_t
{
    /*! The last ROSC used for entropy collection */
    uint32_t LastTrngRosc;

} CCTrngState_t;

 /*!
 @}
 */
#endif /* #ifndef _CC_RND_COMMON_TRNG_H */
