/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


#ifndef  CC_UTIL_PM_H
#define  CC_UTIL_PM_H

/*!
@file
@brief This file contains power management definitions and APIs.
*/

/*!
 @addtogroup power_manage
 @{
     */

#include "cc_util_error.h"


/*! Get Arm CryptoCell status. */
#define CC_STATUS_GET 	0	/* no active registered CC operations */

/*! Notify Arm CryptoCell is active. */
#define CC_IS_WAKE 	0 	/* Do Nothing, return without error */

/*! Notify Arm CryptoCell is idle. */
#define CC_IS_IDLE 	0 	/* Do Nothing, return without error */


/************************************************************************************/
/****************        Power management API           *****************************/
/************************************************************************************/

/****************************************************************************************/
/**
 *
 * @brief Call this function before the TEE is powered down.
 *
 * @return \c CC_UTIL_OK on success.
 * @return A non-zero value on failure.
 */
CCUtilError_t CC_PmSuspend(void);


/****************************************************************************************/
/**
 *
 * @brief Call this function once restoring the TEE from power down state,
 * 	before any cryptographic operation.
 *
 * @return \c CC_UTIL_OK on success.
 * @return A non-zero value on failure.
 */
CCUtilError_t CC_PmResume(void);
/*!
 @}
 */

#endif
