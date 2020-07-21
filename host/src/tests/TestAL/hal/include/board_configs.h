/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm’s non-OSI source license
 *
 */


#ifndef TEST_HAL_H_
#define TEST_HAL_H_

/*!
 @file
 @brief This file contains board initialization functions.
 */

/*!
 @addtogroup board_hal_test
 @{
 */

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/
/*!
 * @brief This function initializes the board.
 *
 *
 * @return 0 on success.
 * @return 1 on failure.
 */
uint32_t Test_HalBoardInit(void);

/******************************************************************************/
/*!
 * @brief This function unmaps the addresses related to the board.
 *
 *
 * @return Void.
 */
void Test_HalBoardFree(void);

#ifdef __cplusplus
}
#endif
/*!
 @}
 */
#endif /* TEST_HAL_H_ */
