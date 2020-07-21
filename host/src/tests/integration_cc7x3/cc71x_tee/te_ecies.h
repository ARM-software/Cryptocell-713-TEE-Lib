/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _CC71X_TEE_INTEGRATION_TE_ECIES_H
#define _CC71X_TEE_INTEGRATION_TE_ECIES_H
/*!
  @file
  @brief This file contains ECIES definitions for test usage.

  This file defines:
      <ol><li>ECIES mapping used for ECIES integration tests.</li>
      <li>Declarations of ECIES integration test functions.</li></ol>
 */

/*!
 @addtogroup ecies_apis
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
 * Functions
 ******************************************************************/

/*!
@brief This function allocates and initializes the ECIES test resources.


@return \c zero on success.
@return A non-zero value on failure.
*/
int TE_init_ecies_test(void);

/*!
 @}
 */
#endif /* _CC71X_TEE_INTEGRATION_TE_ECIES_H */
