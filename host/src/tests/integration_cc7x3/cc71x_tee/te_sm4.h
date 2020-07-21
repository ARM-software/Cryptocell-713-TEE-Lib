/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _CC71X_TEE_INTEGRATION_TE_SM4_H
#define _CC71X_TEE_INTEGRATION_TE_SM4_H
/*!
  @file
  @brief This file contains SM4 definitions for test usage.

  This file defines:
      <ol><li>SM4 mapping used for SM4 integration tests.</li>
      <li>Declarations of SM4  integration test functions.</li></ol>
 */

/*!
 @addtogroup sm4_apis
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
@brief This function allocates and initializes the sm4 test resources.


@return \c zero on success.
@return A non-zero value on failure.
*/
int TE_init_sm4_test(void);


/*!
 @}
 */
#endif /* _CC71X_TEE_INTEGRATION_TE_SM4_H */

