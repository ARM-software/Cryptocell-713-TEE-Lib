/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _CC71X_TEE_INTEGRATION_TE_KEY_DERIVATION_H
#define _CC71X_TEE_INTEGRATION_TE_KEY_DERIVATION_H
/*!
  @file
  @brief This file contains KEY_DERIVATION definitions for test usage.

  This file defines:
      <ol><li>KEY_DERIVATION mapping used for KEY_DERIVATION integration tests.</li>
      <li>Declarations of KEY_DERIVATION  integration test functions.</li></ol>
 */

/*!
 @addtogroup key_derivation_apis
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
@brief This function allocates and initializes the key_derivation test resources.


@return \c zero on success.
@return A non-zero value on failure.
*/
int TE_init_key_derivation_test(void);


/*!
 @}
 */
#endif /* _CC71X_TEE_INTEGRATION_TE_KEY_DERIVATION_H */

