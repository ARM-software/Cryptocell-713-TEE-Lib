/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _CC71X_TEE_INTEGRATION_TE_TRNG_FE_H
#define _CC71X_TEE_INTEGRATION_TE_TRNG_FE_H
/*!
  @file
  @brief This file contains TRNG_FE definitions for test usage.

  This file defines:
      <ol><li>TRNG_FE mapping used for TRNG_FE integration tests.</li>
      <li>Declarations of TRNG_FE  integration test functions.</li></ol>
 */

/*!
 @addtogroup trng_fe_apis
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
@brief This function allocates and initializes the trng_fe test resources.


@return \c zero on success.
@return A non-zero value on failure.
*/
int TE_init_trngfe_test(void);


/*!
 @}
 */
#endif /* _CC71X_TEE_INTEGRATION_TE_TRNG_FE_H */

