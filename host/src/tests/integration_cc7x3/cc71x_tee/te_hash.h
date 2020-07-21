/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _CC71X_TEE_INTEGRATION_TE_HASH_H
#define _CC71X_TEE_INTEGRATION_TE_HASH_H
/*!
  @file
  @brief This file contains HASH definitions for test usage.

  This file defines:
      <ol><li>HASH mapping used for HASH integration tests.</li>
      <li>Declarations of HASH  integration test functions.</li></ol>
 */

/*!
 @addtogroup gcm_apis
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
@brief This function allocates and initializes the hash test resources.


@return \c zero on success.
@return A non-zero value on failure.
*/
int TE_init_hash_test(void);


/*!
 @}
 */
#endif /* _CC71X_TEE_INTEGRATION_TE_HASH_H */

