/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef  _CC_UTIL_STIMER_H
#define  _CC_UTIL_STIMER_H

/*!
@file
@brief This file contains the functions and definitions for the Secure Timer module.
*/

/*!
 @addtogroup sec_timer
 @{
 */

#ifdef __cplusplus
extern "C"
{
#endif


#include "cc_util_error.h"
#include "cc_pal_types_plat.h"

/*! Definition for nano seconds.*/
#define NSEC_SEC 1000000000
/*! Definition for converting frequency to time.*/
#define CONVERT_CLK_TO_NSEC(clks,hz) ((NSEC_SEC/hz)*(clks))
/*! Definition for the Secure Timer counter size.*/
#define STIMER_COUNTER_BYTE_SIZE	8

/******************************************************************************
*                        	DEFINITIONS
******************************************************************************/

/*! Low-resolution clock definitions.*/
typedef struct {
	uint32_t lsbLowResTimer; /*!< 32 Low bits of the low-resolution clock. */
	uint32_t msbLowResTimer; /*!< 32 High bits of the low-resolution clock. */
}CCUtilCntr_t;

/*! Time stamp definition. */
typedef	uint64_t	CCUtilTimeStamp_t;


/*!
 * @brief This function records and retrieves the current time stamp read from the Secure Timer.
 *
 * @return \c CC_OK on success.
 * @return A non-zero value on failure.
 *
 */
CCError_t CC_UtilGetTimeStamp(CCUtilTimeStamp_t *pTimeStamp /*!< [out] Time stamp read from the Secure Timer. */);

/*!
 * @brief This function returns the elapsed time, in nanoseconds, between two recorded time stamps. The first time stamp is assumed to
 *	  be the stamp of the interval start, so if timeStamp2 is lower than timeStamp1, negative duration is returned.
 *	  The translation to nanoseconds is based on the clock frequency definitions described in \ref cc_secure_clk_defs.h.
 *
 * @return  Duration between two time stamps expressed in nanoseconds.
 *
 */
int64_t CC_UtilCmpTimeStamp(
		CCUtilTimeStamp_t timeStamp1, /*!< [in] Time stamp of the interval start. */
		CCUtilTimeStamp_t timeStamp2  /*!< [in] Time stamp of the interval end. */);

/*!
 * @brief This function resets the low resolution Secure Timer.
 *
 */
void CC_UtilResetLowResTimer(void);

#ifdef __cplusplus
}
#endif
/*!
 @}
 */
#endif /*_CC_UTIL_STIMER_H*/
