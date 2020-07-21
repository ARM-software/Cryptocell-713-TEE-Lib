/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _CC_OTP_DEFS_H
#define _CC_OTP_DEFS_H

/*!
@file
@brief This file contains general OTP definitions and memory layout.
*/


#ifdef __cplusplus
extern "C"
{
#endif


/* OTP memory layout */
#define CC_OTP_BASE_ADDR                                        0x2000U
#define CC_OTP_START_OFFSET                                     0x00U
#define CC_OTP_LAST_OFFSET                                      0x3FFU

/* [0x00-0x07] Device root key (HUK) */
#define CC_OTP_HUK_OFFSET                                       0x00U
#define CC_OTP_HUK_SIZE_IN_WORDS                                8

/* [0x08-0x0B] ICV provisioning secret (KPICV) */
#define CC_OTP_KPICV_OFFSET                                     0x08U
#define CC_OTP_KPICV_SIZE_IN_WORDS                              4

/* [0x0C-0x0F] ICV Code encryption key (KCEICV) */
#define CC_OTP_KCEICV_OFFSET                                    0x0CU
#define CC_OTP_KCEICV_SIZE_IN_WORDS                             4

/* [0x10] Manufacturer-programmed flags */
#define CC_OTP_FIRST_MANUFACTURE_FLAG_OFFSET                    0x10U
#define CC_OTP_FIRST_MANUFACTURE_SIZE_IN_WORDS                  1

/* [0x11] Manufacturer-programmed flags */
#define CC_OTP_SECOND_MANUFACTURE_FLAG_OFFSET                   0x11U
#define CC_OTP_SECOND_MANUFACTURE_SIZE_IN_WORDS                 1

/* [0x12] Manufacturer-programmed flags */
#define CC_OTP_SECURE_GUARD_CONTROL_FLAG_OFFSET                 0x12U
#define CC_OTP_SECURE_GUARD_CONTROL_SIZE_IN_WORDS               1


/* [0x13-0x1A] Root-of-Trust Public Key.
* May be used in one of the following configurations:
* - A single 256-bit SHA256 digest of the Secure Boot public key (HBK).                                        :
* - Two 128-bit truncated SHA256 digests of Secure Boot public keys 0 and 1 (HBK0, HBK1) */
#define CC_OTP_HBK_OFFSET                                       0x13U
#define CC_OTP_HBK_SIZE_IN_WORDS                                8

#define CC_OTP_HBK0_OFFSET                                      0x13U
#define CC_OTP_HBK0_SIZE_IN_WORDS                               4

#define CC_OTP_HBK1_OFFSET                                      0x17U
#define CC_OTP_HBK1_SIZE_IN_WORDS                               4

/* [0x19-0x1C] OEM provisioning secret (Kcp) */
#define CC_OTP_KCP_OFFSET                                       0x1BU
#define CC_OTP_KCP_SIZE_IN_WORDS                                4

/* OEM Code encryption key (KCE) */
#define CC_OTP_KCE_OFFSET                                       0x1FU
#define CC_OTP_KCE_SIZE_IN_WORDS                                4

/* OEM-programmed flags */
#define CC_OTP_OEM_FLAG_OFFSET                                  0x23U
#define CC_OTP_OEM_SIZE_IN_WORDS                                1

/* MV Counters */
#define CC_OTP_SECURE_MIN_SW_VERSION_FLAG_OFFSET                0x24U
#define CC_OTP_SECURE_MIN_SW_VERSION_SIZE_IN_WORDS              1

#define CC_OTP_NON_SECURE_MIN_SW_VERSION_FLAG_OFFSET            0x25U
#define CC_OTP_NON_SECURE_MIN_SW_VERSION_SIZE_IN_WORDS          7

/* OTP DCU lock mask */
#define CC_OTP_DCU_OFFSET                                       0x2CU
#define CC_OTP_DCU_SIZE_IN_WORDS                                4

/* EKcst */
#define CC_OTP_EKCST_OFFSET                                     0x30U
#define CC_OTP_EKCST_SIZE_IN_WORDS                              4

#define CC_OTP_USER_DEFINED_OFFSET                              0x34U


/* First Manufacturer-programmed flags */

/* [7:0] Number of "0" bits in HUK */
#define CC_OTP_FIRST_MANUFACTURE_FLAG_HUK_ZERO_BITS_BIT_SHIFT           0
#define CC_OTP_FIRST_MANUFACTURE_FLAG_HUK_ZERO_BITS_BIT_SIZE            8

/* [14:8] Number of "0" bits in KPICV (128 bit) */
#define CC_OTP_FIRST_MANUFACTURE_FLAG_KPICV_ZERO_BITS_BIT_SHIFT         8
#define CC_OTP_FIRST_MANUFACTURE_FLAG_KPICV_ZERO_BITS_BIT_SIZE          7

/* [15:15] KPICV "Not In Use" bit */
#define CC_OTP_FIRST_MANUFACTURE_FLAG_KPICV_NOT_IN_USE_BIT_SHIFT       15
#define CC_OTP_FIRST_MANUFACTURE_FLAG_KPICV_NOT_IN_USE_BIT_SIZE         1

/* [22:16] Number of "0" bits in KCEICV */
#define CC_OTP_FIRST_MANUFACTURE_FLAG_KCEICV_ZERO_BITS_BIT_SHIFT       16
#define CC_OTP_FIRST_MANUFACTURE_FLAG_KCEICV_ZERO_BITS_BIT_SIZE         7

/* [23:23] KCEICV "Not In Use" bit */
#define CC_OTP_FIRST_MANUFACTURE_FLAG_KCEICV_NOT_IN_USE_BIT_SHIFT      23
#define CC_OTP_FIRST_MANUFACTURE_FLAG_KCEICV_NOT_IN_USE_BIT_SIZE        1

/* [30:24] Number of "0" bits in HBK0 (in case it is used as 4  words of the ICV) */
#define CC_OTP_FIRST_MANUFACTURE_FLAG_HBK0_ZERO_BITS_BIT_SHIFT         24
#define CC_OTP_FIRST_MANUFACTURE_FLAG_HBK0_ZERO_BITS_BIT_SIZE           7

/* [31:31] HBK0 "Not In Use" bit */
#define CC_OTP_FIRST_MANUFACTURE_FLAG_HBK0_NOT_IN_USE_BIT_SHIFT        31
#define CC_OTP_FIRST_MANUFACTURE_FLAG_HBK0_NOT_IN_USE_BIT_SIZE          1


/* Second Manufacturer-programmed flags */

/* [7:0] general purpose flag */
#define CC_OTP_SECOND_MANUFACTURE_FLAG_GPR_BIT_SHIFT                    0
#define CC_OTP_SECOND_MANUFACTURE_FLAG_GPR_BIT_SIZE                     8

/* [8:8] ICV TCI bit */
#define CC_OTP_SECOND_MANUFACTURE_FLAG_TCI_BIT_SHIFT                    8
#define CC_OTP_SECOND_MANUFACTURE_FLAG_TCI_BIT_SIZE                     1

/* [9:9] ICV PCI bit */
#define CC_OTP_SECOND_MANUFACTURE_FLAG_PCI_BIT_SHIFT                    9
#define CC_OTP_SECOND_MANUFACTURE_FLAG_PCI_BIT_SIZE                     1

/* [28:10] RESERVED */

/* [29:29] secure disable flag */
#define CC_OTP_SECOND_MANUFACTURE_FLAG_SECURE_DISABLE_BIT_SHIFT         29
#define CC_OTP_SECOND_MANUFACTURE_FLAG_SECURE_DISABLE_BIT_SIZE          1

/* [30:30] ICV RMA flag */
#define CC_OTP_SECOND_MANUFACTURE_FLAG_ICV_RMA_MODE_BIT_SHIFT           30
#define CC_OTP_SECOND_MANUFACTURE_FLAG_ICV_RMA_MODE_BIT_SIZE            1

/* [31:31] OEM RMA flag */
#define CC_OTP_SECOND_MANUFACTURE_FLAG_OEM_RMA_MODE_BIT_SHIFT           31
#define CC_OTP_SECOND_MANUFACTURE_FLAG_OEM_RMA_MODE_BIT_SIZE            1


/* OEM-programmed flags */

/* [7:0] Number of "0" bits in HBK1/HBK (128/256 bits public key) */
#define CC_OTP_OEM_FLAG_HBK_ZERO_BITS_BIT_SHIFT                         0
#define CC_OTP_OEM_FLAG_HBK_ZERO_BITS_BIT_SIZE                          8

#define CC_OTP_OEM_FLAG_HBK1_ZERO_BITS_BIT_SHIFT                        0
#define CC_OTP_OEM_FLAG_HBK1_ZERO_BITS_BIT_SIZE                         8

/* [14:8] Number of "0" bits in KCP (128 bit) */
#define CC_OTP_OEM_FLAG_KCP_ZERO_BITS_BIT_SHIFT                         8
#define CC_OTP_OEM_FLAG_KCP_ZERO_BITS_BIT_SIZE                          7

/* [15:15] KCP "Not In Use" bit */
#define CC_OTP_OEM_FLAG_KCP_NOT_IN_USE_BIT_SHIFT                       15
#define CC_OTP_OEM_FLAG_KCP_NOT_IN_USE_BIT_SIZE                         1

/* [22:16] Number of "0" bits in KCE */
#define CC_OTP_OEM_FLAG_KCE_ZERO_BITS_BIT_SHIFT                        16
#define CC_OTP_OEM_FLAG_KCE_ZERO_BITS_BIT_SIZE                          7

/* [23:23] KCE "Not In Use" bit */
#define CC_OTP_OEM_FLAG_KCE_NOT_IN_USE_BIT_SHIFT                       23
#define CC_OTP_OEM_FLAG_KCE_NOT_IN_USE_BIT_SIZE                         1

/* [30:24] Number of "0" bits in EKCST */
#define CC_OTP_OEM_FLAG_EKCST_ZERO_BITS_BIT_SHIFT                      24
#define CC_OTP_OEM_FLAG_EKCST_ZERO_BITS_BIT_SIZE                        7

/* [31:31] EKcst "Not In Use" bit */
#define CC_OTP_OEM_FLAG_EKCST_NOT_IN_USE_BIT_SHIFT                     31
#define CC_OTP_OEM_FLAG_EKCST_NOT_IN_USE_BIT_SIZE                       1


/* Safe guard programmed flags */

/* [0:0] SG_SECNTL_OTP */
#define CC_OTP_SECURE_GUARD_CONTROL_SG_SECNTL_OTP_BIT_SHIFT             0
#define CC_OTP_SECURE_GUARD_CONTROL_SG_SECNTL_OTP_BIT_SIZE              1

/* [1:1] SG_ERSRT_OTP */
#define CC_OTP_SECURE_GUARD_CONTROL_SG_ERSRT_OTP_BIT_SHIFT              1
#define CC_OTP_SECURE_GUARD_CONTROL_SG_ERSRT_OTP_BIT_SIZE               1

/* [2:2] DISABLE_BYPASS_OTP */
#define CC_OTP_SECURE_GUARD_CONTROL_DISABLE_BYPASS_OTP_BIT_SHIFT        2
#define CC_OTP_SECURE_GUARD_CONTROL_DISABLE_BYPASS_OTP_BIT_SIZE         1

/* [3:3] SG_ACT_OTP */
#define CC_OTP_SECURE_GUARD_CONTROL_SG_ACT_OTP_BIT_SHIFT                3
#define CC_OTP_SECURE_GUARD_CONTROL_SG_ACT_OTP_BIT_SIZE                 1

/* [4:4] SG_STPVDIS_OTP */
#define CC_OTP_SECURE_GUARD_CONTROL_SG_STPVDIS_OTP_BIT_SHIFT            4
#define CC_OTP_SECURE_GUARD_CONTROL_SG_STPVDIS_OTP_BIT_SIZE             1

/* [6:5] SG_STPVDIS_OTP */
#define CC_OTP_SECURE_GUARD_CONTROL_SG_STPVDIS_VAL_OTP_BIT_SHIFT        5
#define CC_OTP_SECURE_GUARD_CONTROL_SG_STPVDIS_VAL_OTP_BIT_SIZE         2

/* [7:7] SG_VMIN_OTP */
#define CC_OTP_SECURE_GUARD_CONTROL_SG_VMIN_OTP_BIT_SHIFT               7
#define CC_OTP_SECURE_GUARD_CONTROL_SG_VMIN_OTP_BIT_SIZE                1

/* [10:8] SG_VMIN_THRESH_OTP */
#define CC_OTP_SECURE_GUARD_CONTROL_SG_VMIN_THRESH_OTP_BIT_SHIFT        8
#define CC_OTP_SECURE_GUARD_CONTROL_SG_VMIN_THRESH_OTP_BIT_SIZE         3

/* [10:8] SG_VMIN_THRESH_OTP */
#define CC_OTP_SECURE_GUARD_CONTROL_SG_VMIN_THRESH_OTP_BIT_SHIFT        8
#define CC_OTP_SECURE_GUARD_CONTROL_SG_VMIN_THRESH_OTP_BIT_SIZE         3

/* [11:11] FORCE_ERS_ACT_OTP. */
#define CC_OTP_SECURE_GUARD_CONTROL_FORCE_ERS_ACT_OTP_BIT_SHIFT         11
#define CC_OTP_SECURE_GUARD_CONTROL_FORCE_ERS_ACT_OTP_BIT_SIZE          1

/* [12:12] EN_ERS_HW_CTRL_OTP */
#define CC_OTP_SECURE_GUARD_CONTROL_EN_ERS_HW_CTRL_OTP_BIT_SHIFT        12
#define CC_OTP_SECURE_GUARD_CONTROL_EN_ERS_HW_CTRL_OTP_BIT_SIZE         1

/* [31:13] Reserved */

#ifdef __cplusplus
}
#endif

#endif



