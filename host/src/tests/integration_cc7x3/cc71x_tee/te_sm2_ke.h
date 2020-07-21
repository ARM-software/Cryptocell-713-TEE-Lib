/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _CC71X_TEE_INTEGRATION_TE_SM2_KE_H
#define _CC71X_TEE_INTEGRATION_TE_SM2_KE_H
/*!
  @file
  @brief This file contains SM2_KE definitions for test usage.

  This file defines:
      <ol><li>SM2_KE mapping used for SM2_KE integration tests.</li>
      <li>Declarations of SM2_KE  integration test functions.</li></ol>
 */

/*!
 @addtogroup sm2_ke_apis
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
@brief This function allocates and initializes the sm2_ke test resources.


@return \c zero on success.
@return A non-zero value on failure.
*/
int TE_init_sm2_ke_test(void);


/*!
 @}
 */
#endif /* _CC71X_TEE_INTEGRATION_TE_SM2_KE_H */

