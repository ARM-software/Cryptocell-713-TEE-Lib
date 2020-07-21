/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _CC71X_TEE_INTEGRATION_TE_TDES_H
#define _CC71X_TEE_INTEGRATION_TE_TDES_H
/*!
  @file
  @brief This file contains TDES definitions for test usage.

  This file defines:
      <ol><li>TDES mapping used for TDES integration tests.</li>
      <li>Declarations of TDES  integration test functions.</li></ol>
 */

/*!
 @addtogroup tdes_apis
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
@brief This function allocates and initializes the tdes test resources.


@return \c zero on success.
@return A non-zero value on failure.
*/
int TE_init_tdes_test(void);


/*!
 @}
 */
#endif /* _CC71X_TEE_INTEGRATION_TE_TDES_H */

