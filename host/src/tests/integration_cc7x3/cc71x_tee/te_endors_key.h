/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _CC71X_TEE_INTEGRATION_TE_ENDORS_KEY_H
#define _CC71X_TEE_INTEGRATION_TE_ENDORS_KEY_H
/*!
  @file
  @brief This file contains endors keydefinitions for test usage.

  This file defines:
      <ol><li>endors key mapping used for endors key integration tests.</li>
      <li>Declarations of endors key integration test functions.</li></ol>
 */

/*!
 @addtogroup endors_key_apis
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
@brief This function allocates and initializes the endors key test resources.


@return \c zero on success.
@return A non-zero value on failure.
*/
int TE_init_endors_key_test(void);

/*!
 @}
 */
#endif /* _CC71X_TEE_INTEGRATION_TE_ENDORS_KEY_H */
