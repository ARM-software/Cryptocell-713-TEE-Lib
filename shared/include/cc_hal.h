/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


#ifndef __CC_HAL_H__
#define __CC_HAL_H__


/*!
 @file
 @brief This file contains HAL definitions and APIs.
*/

/*!
 @addtogroup cc_hal_defs
 @{
 */

#include <stdint.h>
#include <stdio.h>

#include "cc_hal_plat.h"
#include "cc_hal_defs.h"
#include "cc_pal_types.h"
#include "cc_pal_types_plat.h"

/*! Definition for 32-bits mask.v*/
#define CC_HAL_ALL_BITS     0xFFFFFFFFUL

/*!
 * @brief   This function is used to map Arm CryptoCell TEE registers to Host virtual address space.
	        It is called by ::CC_LibInit, and returns a non-zero value in case of failure.
            The existing implementation supports Linux environment. In case virtual addressing is not used, the function can be minimized to contain only the
	        following line, and return \c OK:
            gCcRegBase = (uint32_t)CC_BASE_CC;

  @return   \c CC_OK on success.
  @return   \ref CCError_t error code.
*/
CCError_t CC_HalInit(void);

/*!
 * @brief  This function is used to clear the interrupt vector.
 */
void CC_HalClearInterrupt(uint32_t data);


/*!
 * @brief   This function is used to unmap the virtual address of Arm CryptoCell TEE registers.
 *	        It is called by CC_LibFini(), and returns a non-zero value in case of failure.
 *	        In case virtual addressing is not used, the function can be minimized to be an empty function returning OK.
 *
 * @return  \ref CCError_t error code.
 */
CCError_t CC_HalTerminate(void);

/*!
 * @brief This function is used to mask IRR interrupts.

 * @return \c void
 */
void CC_HalMaskInterrupt(uint32_t irqMask);

/*!
 @}
 */
#endif

