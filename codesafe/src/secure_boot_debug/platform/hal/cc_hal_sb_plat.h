/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

/*!
@file
@brief This file contains platform-dependent definitions that are used in the Boot Services HAL layer.

@defgroup cc_hal_sb_plat CryptoCell Boot Services platform-dependent HAL layer definitions
@{
@ingroup cc_hal
*/

#ifndef _CC_HAL_SB_PLAT_H
#define _CC_HAL_SB_PLAT_H

#ifdef __cplusplus
extern "C"
{
#endif

/*----------------------------
      PUBLIC FUNCTIONS
-----------------------------------*/

/*! Reads a 32-bit value from a CryptoCell-713 memory-mapped register. */
#define SB_HAL_READ_REGISTER(addr,val)   \
            ((val) = (*((volatile uint32_t*)(addr))))


/*!
  Writes a 32-bit value to a CryptoCell-713 memory-mapped register.

  @note This macro must be modified to make the operation synchronous.
  That is, the write operation must complete and the new value must be
  written to the register before the macro returns. The mechanisms
  required to achieve this are architecture-dependent, for example
  the memory barrier in Arm architecture.
 */
#define SB_HAL_WRITE_REGISTER(addr,val)     \
        ((*((volatile uint32_t*)(addr))) = (uint32_t)(val))

#ifdef __cplusplus
}
#endif

#endif

/**
@}
 */

