/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

/*!
 @file
 @brief This file contains the definitions and APIs for Secure SRAM operations.

 This is a placeholder for platform-specific Secure SRAM implementation.
*/

/*!
 @defgroup cc_pal_secure_sram CryptoCell PAL SECURE SRAM APIs
 @brief Contains PAL SECURE SRAM APIs. See cc_pal_secure_sram.h.

 @{
 @ingroup cc_pal
 @}
 */

#ifndef _CC_PAL_SECURE_SRAM_H
#define _CC_PAL_SECURE_SRAM_H

/*!
  @brief   Reads a word from a specific address in the secure SRAM and write it to a specific address in OTP or to a shadow register.

  The read of the word is done in-direct and the write of the word is implemented with inline assembler.
  It is implemented this way in order to bypass the stack and not leave in it parts of the secrets.
  An external loop need to call this API 4 times in a row

  @return None
*/
void CC_PalCopyWordFromSecureSram(unsigned long srcRegAddr, unsigned long destRegAddr);

/*!
  @brief   Reads a word from a specific address in the secure SRAM and checks whether it is all 0's or 1's.

  The read of the word is done in-direct and the comparison of the word is implemented with inline assembler.
  It is implemented this way in order to bypass the stack and not leave in it parts of the secrets.
  An external loop need to call this API 4 times in a row

  @return CC_OK
*/
uint32_t CC_PalIsSramWordValid(unsigned long srcAddr, uint32_t cmpValue);

void CC_PalReadWordFromReg(unsigned long srcAddr);

#endif
