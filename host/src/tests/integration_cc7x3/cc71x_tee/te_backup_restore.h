/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


#ifndef _CC71X_TEE_INTEGRATION_TE_BACKUP_RESTORE_H
#define _CC71X_TEE_INTEGRATION_TE_BACKUP_RESTORE_H
/*!
  @file
  @brief This file contains backup restore definitions for test usage.

  This file defines:
      <ol><li>backup restore mapping used for backup restore integration tests.</li>
      <li>Declarations of backup restore integration test functions.</li></ol>
 */

/*!
 @addtogroup backup_restore_apis
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
@brief This function allocates and initializes the backup restore test resources.


@return \c zero on success.
@return A non-zero value on failure.
*/
int TE_init_backup_restore_test(void);

/*!
 @}
 */
#endif /* _CC71X_TEE_INTEGRATION_TE_BACKUP_RESTORE_H */
