/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _CC71X_TEE_INTEGRATION_TE_HKDF_H
#define _CC71X_TEE_INTEGRATION_TE_HKDF_H
/*!
  @file
  @brief This file contains HKDF definitions for test usage.

  This file defines:
      <ol><li>HKDF mapping used for HKDF integration tests.</li>
      <li>Declarations of HKDF  integration test functions.</li></ol>
 */

/*!
 @addtogroup hkdf_apis
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
@brief This function allocates and initializes the hkdf test resources.


@return \c zero on success.
@return A non-zero value on failure.
*/
int TE_init_hkdf_test(void);


/*!
 @}
 */
#endif /* _CC71X_TEE_INTEGRATION_TE_HKDF_H */

