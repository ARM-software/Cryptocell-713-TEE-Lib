/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

 /*!
 @file
 @brief This file contains HAL register functions.
 */

 /*!
 @ingroup cc_hal_register
 @{
     */

#ifndef __CC_HAL_PLAT_H__
#define __CC_HAL_PLAT_H__

#include "cc_registers.h"
#include "cc_bitops.h"

/******************************************************************************
*				DEFINITIONS
******************************************************************************/

/******************************************************************************
*                               MACROS
******************************************************************************/
/*! CryptoCell registers base address. */
extern unsigned long gCcRegBase;

/******************************************************************************
*                               MACROS
******************************************************************************/

/*!
 * Read CryptoCell memory-mapped-IO register.
 *
 * \param regOffset The offset of the Arm CryptoCell register to read
 * \return uint32_t Return the value of the given register.
 */
#define CC_HAL_READ_REGISTER(regOffset) 				\
		(*((volatile uint32_t *)(gCcRegBase + (regOffset))))

/*!
 * Write CryptoCell memory-mapped-IO register.
 * \note This macro must be modified to make the operation synchronous:<ul><li> The write operation must complete.</li>
 *       <li>The new value must be written to the register before the macro returns.</li></ul> The mechanisms required to
 *       achieve this are architecture-dependent (for example: the memory barrier in Arm architecture).
 *
 * \param regOffset The offset of the Arm CryptoCell register to write.
 * \param val The value to write.
 */
#define CC_HAL_WRITE_REGISTER(regOffset, val) 		\
		(*((volatile uint32_t *)(gCcRegBase + (regOffset))) = (uint32_t)(val))

/*!
 @}
 */

#endif /*__CC_HAL_PLAT_H__*/

