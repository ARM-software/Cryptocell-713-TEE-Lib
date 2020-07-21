/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm’s non-OSI source license
 *
 */

#ifndef TEST_PAL_TIME_H_
#define TEST_PAL_TIME_H_

/*!
  @file
  @brief This file contains PAL time functions.
 */

/*!
  @addtogroup pal_timer_test
  @{
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/
/*!
 * @brief This function suspends execution of the calling thread
 * for microsecond intervals.
 *
 *
 * @return Void.
 */
void Test_PalDelay(
 /*! Time to suspend in microseconds. */
 const uint32_t usec
);

/******************************************************************************/
/*!
 * @brief This function returns a timestamp in milliseconds.
 *
 *
 * @return Timestamp in milliseconds.
 */
uint32_t Test_PalGetTimestamp(void);

#ifdef __cplusplus
}
#endif
/*!
 @}
 */
#endif /* TEST_PAL_TIME_H_ */
