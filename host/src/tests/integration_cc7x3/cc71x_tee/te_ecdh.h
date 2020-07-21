/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _CC71X_TEE_INTEGRATION_TE_ECDH_H
#define _CC71X_TEE_INTEGRATION_TE_ECDH_H
/*!
  @file
  @brief This file contains EC Diffie-Hellman definitions for test usage.

  This file defines:
      <ol><li>EC Diffie-Hellman mapping used for EC Diffie-Hellman integration tests.</li>
      <li>Declarations of EC Diffie-Hellman integration test functions.</li></ol>
 */

/*!
 @addtogroup ecdh_apis
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
@brief This function allocates and initializes the ECDH test resources.


@return \c zero on success.
@return A non-zero value on failure.
*/
int TE_init_ecdh_test(void);

/*!
 @}
 */
#endif /* _CC71X_TEE_INTEGRATION_TE_ECDH_H */
