/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

/*!
 @file
 @brief This file contains the definitions and APIs for CMPU in BC mode OTP operations.

 This is a placeholder for platform-specific CMPU in BC mode OTP implementation.
*/

/*!
 @defgroup cc_pal_bc_cmpu_otp CryptoCell PAL CMPU BC OTP APIs
 @brief Contains PAL CMPU BC OTP APIs. See cc_pal_bc_cmpu_otp.h.

 @{
 @ingroup cc_pal
 @}
 */

#ifndef _CC_PAL_BC_CMPU_OTP_H
#define _CC_PAL_BC_CMPU_OTP_H

extern unsigned long gCcEnvBase;

#include "cc_pal_types.h"

/* OTP memory mapping */
#define CC_PAL_ENV_OTP_START_OFFSET     0x2000UL

/*!
  @brief  Writes a specific word to a specific offset in the OTP.

  @return CC_OK
*/
uint32_t CC_PalOtpWordWrite(uint32_t otpData, uint32_t otpWordOffset);

/*!
  @brief  Reads a specific word from a specific offset in the OTP.

  @return OTP Word
*/

uint32_t CC_PalOtpWordRead(uint32_t otpWordOffset);

/*!
  @brief  Gets a specific RTL word mask to to XOR with a word written to the OTP.

  @return RTL OTP mask
*/
uint32_t CC_PalGetRtlOtpMask(uint32_t wordOffsetInTable, unsigned long* rtlOtpMask);

#endif
