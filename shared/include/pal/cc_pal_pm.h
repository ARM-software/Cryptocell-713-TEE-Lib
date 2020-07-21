/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */
#ifndef _CC_PAL_PM_H
#define _CC_PAL_PM_H

/*!
 @file
 @brief This file contains the definitions and APIs for power-management implementation.

       This is a placeholder for platform-specific power management implementation.
       The module should be updated whether CryptoCell is active or not,
       to notify the external PMU when it might be powered down.
 */


/*!
 @addtogroup cc_pal_pm
 @{
 */

/*
******** Function pointer definitions **********
*/


#ifdef CC_IOT

/*----------------------------
      PUBLIC FUNCTIONS
-----------------------------------*/

/*!
 @brief This function initiates an atomic counter.
 @return Void.
 */
void CC_PalPowerSaveModeInit(void);

/*!
 @brief This function returns the number of active registered CryptoCell operations.

 @return The value of the atomic counter.
 */
int32_t CC_PalPowerSaveModeStatus(void);

/*!
 @brief This function updates the atomic counter on each call to CryptoCell.

 On each call to CryptoCell, the counter is increased. At the end of each operation
 the counter is decreased.
 Once the counter is zero, an external callback is called.

 @return \c 0 on success.
 @return A non-zero value on failure.
 */
CCError_t CC_PalPowerSaveModeSelect(CCBool isPowerSaveMode /*!< [in] TRUE: CryptoCell is active or FALSE: CryptoCell is idle. */ );

#else /* #ifdef CC_IOT */

/*!
 @brief This function powers down CryptoCell.

 Typically, it calls PMU to actually power down.
 When is returns, the CryptoCell is considered to be powered down and will
 not be accessed by the driver.
 */
void CC_PalPowerDown(void);

/*!
 @brief This function powers up CryptoCell.

 Typically, it will call PMU to actually do power up.
 When is returns, the CryptoCell is guaranteed to be powered up and it is saved to
 be accessed by the driver.
 */
void CC_PalPowerUp(void);

#endif /* #ifdef CC_IOT */

/*!
 @}
 */
#endif
