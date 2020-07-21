/*
 * Copyright (c) 2001-2020, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _CC71X_TEE_INTEGRATION_TE_AES_H
#define _CC71X_TEE_INTEGRATION_TE_AES_H
/*!
  @file
  @brief This file contains AES definitions for test usage.

  This file defines:
      <ol><li>AES mapping used for AES integration tests.</li>
      <li>Declarations of AES integration test functions.</li></ol>
 */

/*!
 @addtogroup aes_apis
 @{
 */

/******************************************************************
 * Defines
 ******************************************************************/

/******************************************************************
 * Types
 ******************************************************************/

/******************************************************************
 * functions
 ******************************************************************/

/*!
@brief This function allocates and initializes the Aes test resources.


@return \c zero on success.
@return A non-zero value on failure.
*/
int TE_init_aes_test(void);


/*!
 @}
 */
#endif /* _CC71X_TEE_INTEGRATION_TE_AES_H */
