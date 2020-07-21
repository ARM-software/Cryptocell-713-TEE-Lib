/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _CC71X_TEE_INTEGRATION_TE_SBRT_DEFS_H
#define _CC71X_TEE_INTEGRATION_TE_SBRT_DEFS_H

/******************************************************************
 * Defines
 ******************************************************************/
/************** HW values **************/

/*!
  @file
  @brief This file contains user definitions for the runtime Secure Boot
         services integration tests.

   The definitions in this file are derived from either values taken from the
   tests data files or values that are burned to the OTP at the beginning of the
   integration tests.
 */

 /*!
  @addtogroup user_defs
  @{
*/

/************** OTP values **************/
/*!
 \def KCE_BUFF
Defines the KCE OEM key being burned to the OTP in the test.
 * The value must be the same as defined in \b oem_enc_asset.bin file.
 * KCE OEM is used to encrypt images in runtime Secure Boot flow. */
#define KCE_BUFF {0x24232221, 0x28272625, 0x2C2B2A29, 0x202F2E2D}

/*!
 \def HBK0_BUFF
 Defines the ICV HBK (128 bit) being burned to the OTP in the test.
 * The value must be the same as the first 16 bytes defined in
 * \b hbk_icv_oem.bin file.
 * HBK0 is used as a root of trust in the runtime Secure Boot flow. */
#define HBK0_BUFF {0x502499D1, 0x99546708, 0x56710165, 0x45B56187}

/*!
 \def HBK1_BUFF
 Defines the OEM HBK (128 bit) being burned to the OTP in the test.
 * The value must be the same as the last 16 bytes defined in \b hbk_icv_oem.bin
 * file.
 * HBK1 is used as a root of trust in the runtime Secure Boot flow. */
#define HBK1_BUFF {0x8527D794, 0x543D5B38, 0x9E54F507, 0x9C744F53}

/*!
 \def HBK256_BUFF
 Defines the OEM HBK (256 bit) being burned to the OTP in the test.
 * The value must be the same as defined in \b hbk_oem_full.bin file.
 * HBK is used as a root of trust in runtime Secure Boot flow. */
#define HBK256_BUFF {0x8527D794, 0x543D5B38, 0x9E54F507, 0x9C744F53, 0x86250B8F, 0xEE7D4CB3, 0xEB6B6C90, 0x6E9D1B25}

/******************************************************************
 * Types
 ******************************************************************/

/******************************************************************
 * Externs
 ******************************************************************/

/******************************************************************
 * functions
 ******************************************************************/
 /*!
  @}
*/
#endif /* _CC71X_TEE_INTEGRATION_TE_SBRT_DEFS_H */
