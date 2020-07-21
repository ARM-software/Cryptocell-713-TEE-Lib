/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _CC71X_TEE_INTEGRATION_TE_ECDSA_H
#define _CC71X_TEE_INTEGRATION_TE_ECDSA_H
/*!
  @file
  @brief This file contains ECDSA definitions for test usage.

  This file defines:
      <ol><li>ECDSA mapping used for ECDSA integration tests.</li>
      <li>Declarations of ECDSA integration test functions.</li></ol>
 */

/*!
 @addtogroup ecdsa_apis
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
@brief This function allocates and initializes the ECDSA test resources.


@return \c zero on success.
@return A non-zero value on failure.
*/
int TE_init_ecdsa_test(void);

/*!
 @}
 */
#endif /* _CC71X_TEE_INTEGRATION_TE_ECDSA_H */
