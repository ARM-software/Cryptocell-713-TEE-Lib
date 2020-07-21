/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


#ifndef _CC71X_TEE_INTEGRATION_TE_ASSET_PROV_H
#define _CC71X_TEE_INTEGRATION_TE_ASSET_PROV_H
/*!
  @file
  @brief This file contains asset provisioning definitions for test usage.

  This file defines:
      <ol><li>Asset provisioning mapping used for asset provisioning integration tests.</li>
      <li>Declarations of asset provisioning integration test functions.</li></ol>
 */

/*!
 @addtogroup asset_provisioning_apis
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
 * functions
 ******************************************************************/

/*!
@brief This function allocates and initializes the asset provisioning test resources.


@return \c zero on success.
@return A non-zero value on failure.
*/
int TE_init_asset_prov_test(void);

/*!
 @}
 */
#endif /* _CC71X_TEE_INTEGRATION_TE_ASSET_PROV_H */
