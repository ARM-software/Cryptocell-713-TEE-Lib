/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

/*!
@file
@brief This file contains the functions that are used for the SBROM HAL layer.
*/

#ifndef _CC_HAL_SB_H
#define _CC_HAL_SB_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "cc_hal_sb_plat.h"
#include "cc_regs.h"


/*----------------------------
      PUBLIC FUNCTIONS
-----------------------------------*/


/*!
 * @brief This function is used to configure required CC HW registers to get AXIM interrupts.
 *
 * @param[in] hwBaseAddress     - CryptoCell base address
 *
 * @return none
 */
void SB_HalInitInterrupt(unsigned long hwBaseAddress /*!< [in] CryptoCell base address. */);

/*!
@brief This function is used to clear AXIM_COMP bit in the Interrupt Clear Register (ICR).
@return void
*/
void SB_HalClearInterruptBit(unsigned long hwBaseAddress /*!< [in] CryptoCell base address. */);

/*!
@brief This function is used to wait for the IRR interrupt signal. The existing implementation performs a
"busy wait" on the IRR.
\note This function should be adapted to the customer's system.
@return The IRR value.
*/
uint32_t SB_HalWaitInterrupt(unsigned long hwBaseAddress /*!< [in] CryptoCell base address.  */);

/*!
@brief This function is used to wait for the RNG_INT interrupt signal. The existing implementation performs a
"busy wait" on the IRR RNG_INT.
\note This function should be adapted to the customer's system.
@return The RNG_INT value.
*/
uint32_t SB_HalWaitRngInterrupt(unsigned long hwBaseAddress /*!< [in] CryptoCell base address.  */);

#ifdef __cplusplus
}
#endif

#endif
