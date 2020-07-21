/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _CC71X_TEE_INTEGRATION_TE_SBRT_H
#define _CC71X_TEE_INTEGRATION_TE_SBRT_H
/*!
  @file
  @brief This file contains SBRT definitions for test usage.

  This file defines:
      <ol><li>SBRT mapping used for SBRT integration tests.</li>
      <li>Declarations of SBRT  integration test functions.</li></ol>
 */

/*!
 @addtogroup sbrt_apis
 @{
 */

/******************************************************************
 * Defines
 ******************************************************************/

/******************************************************************
 * Types
 ******************************************************************/

/******************************************************************
 * Externs
 ******************************************************************/

/******************************************************************
 * Globals
 ******************************************************************/

/******************************************************************
 * Functions
 ******************************************************************/

/*!
@brief This function allocates and initializes the sbrt test resources.


@return \c zero on success.
@return A non-zero value on failure.
*/
int TE_init_sbrt_test(void);


/*!
 @}
 */
#endif /* _CC71X_TEE_INTEGRATION_TE_SBRT_H */

