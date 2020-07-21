/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _CC71X_TEE_INTEGRATION_TE_AES_CCM_H
#define _CC71X_TEE_INTEGRATION_TE_AES_CCM_H
/*!
  @file
  @brief This file contains AES CCM definitions for test usage.

  This file defines:
      <ol><li>AES CCM mapping used for AES ccm integration tests.</li>
      <li>Declarations of AES CMM integration test functions.</li></ol>
 */

/*!
 @addtogroup aes_ccm_apis
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
@brief This function allocates and initializes the Aes ccm test resources.


@return \c zero on success.
@return A non-zero value on failure.
*/
int TE_init_aes_ccm_test(void);

/*!
 @}
 */
#endif /* _CC71X_TEE_INTEGRATION_TE_AES_CCM_H */
