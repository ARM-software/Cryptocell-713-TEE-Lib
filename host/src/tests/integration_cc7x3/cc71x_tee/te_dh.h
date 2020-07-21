/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _CC71X_TEE_INTEGRATION_TE_DH_H
#define _CC71X_TEE_INTEGRATION_TE_DH_H
/*!
  @file
  @brief This file contains Diffie-Hellman definitions for test usage.

  This file defines:
      <ol><li>Diffie-Hellman mapping used for Diffie-Hellman integration tests.</li>
      <li>Declarations of Diffie-Hellman integration test functions.</li></ol>
 */

/*!
 @addtogroup Diffie-Hellman_apis
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
 * Static Prototypes
 ******************************************************************/

/******************************************************************
 * functions
 ******************************************************************/

/*!
@brief This function allocates and initializes the DH test resources.


@return \c zero on success.
@return A non-zero value on failure.
*/
int TE_init_dh_test(void);

/*!
 @}
 */
#endif /* _CC71X_TEE_INTEGRATION_TE_DH_H */
