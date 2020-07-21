/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _CC_SECURE_CLK_DEFS_H
#define _CC_SECURE_CLK_DEFS_H


/*!
@file
@brief This file contains definitions for Secure clock. The file contains configurable parameters that should be adjusted to the target
       platform.
*/

/*!
 @addtogroup cc_secure_clock
 @{
     */

#ifdef __cplusplus
extern "C"
{
#endif

/* Secure Clock definitions */
/*-------------------------*/

/*! Defines the frequency of the low-resolution clock in Hertz. Modify the value to the external slow clock frequency on
  the target platform. Arm recommends that you modify the value to 1MHz (1000000). */
#define EXTERNAL_SLOW_OSCILLATOR_HZ 1000000

#ifdef __cplusplus
}
#endif

/*!
 @}
 */
#endif



