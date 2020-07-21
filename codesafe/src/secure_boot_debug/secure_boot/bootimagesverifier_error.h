/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */
#ifndef _BOOT_IMAGES_VERIFIER_ERROR_H
#define _BOOT_IMAGES_VERIFIER_ERROR_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "secureboot_error.h"

/*!
@file
@brief This file contains the error codes that are used for the Secure Boot and Secure Debug APIs.

@defgroup cc_biv_error CryptoCell Secure Boot and Secure Debug error codes
@{
@ingroup cc_sb_sd
*/

/*! Invalid input parameters. */
#define CC_BOOT_IMG_VERIFIER_INV_INPUT_PARAM                            (CC_BOOT_IMG_VERIFIER_BASE_ERROR + 0x00000001)
/*! Invalid OTP version. */
#define CC_BOOT_IMG_VERIFIER_OTP_VERSION_FAILURE                        (CC_BOOT_IMG_VERIFIER_BASE_ERROR + 0x00000002)
/*! The magic number of an illegal certificate. */
#define CC_BOOT_IMG_VERIFIER_CERT_MAGIC_NUM_INCORRECT                   (CC_BOOT_IMG_VERIFIER_BASE_ERROR + 0x00000003)
/*! Illegal certificate version. */
#define CC_BOOT_IMG_VERIFIER_CERT_VERSION_NUM_INCORRECT                 (CC_BOOT_IMG_VERIFIER_BASE_ERROR + 0x00000004)
/*! Illegal certificate SW version, that is smaller than the version stored in the OTP. */
#define CC_BOOT_IMG_VERIFIER_SW_VER_SMALLER_THAN_MIN_VER                (CC_BOOT_IMG_VERIFIER_BASE_ERROR + 0x00000005)
/*! Public key verification compared to the OTP value failed. */
#define CC_BOOT_IMG_VERIFIER_PUB_KEY_HASH_VALIDATION_FAILURE            (CC_BOOT_IMG_VERIFIER_BASE_ERROR + 0x00000006)
/*! Certificate RSA signature verification failure. */
#define CC_BOOT_IMG_VERIFIER_RSA_SIG_VERIFICATION_FAILED                (CC_BOOT_IMG_VERIFIER_BASE_ERROR + 0x00000007)
/*! Workspace buffer given to the API is too small. */
#define CC_BOOT_IMG_VERIFIER_WORKSPACE_SIZE_TOO_SMALL                   (CC_BOOT_IMG_VERIFIER_BASE_ERROR + 0x00000008)
/*! SW image hash verification failure. */
#define CC_BOOT_IMG_VERIFIER_SW_COMP_FAILED_VERIFICATION                (CC_BOOT_IMG_VERIFIER_BASE_ERROR + 0x00000009)
/*! Incorrect certificate size. */
#define CC_BOOT_IMG_VERIFIER_INCORRECT_CERT_SIZE                        (CC_BOOT_IMG_VERIFIER_BASE_ERROR + 0x0000000A)
/*! Illegal SW version or ID of SW version. */
#define CC_BOOT_IMG_VERIFIER_CERT_SW_VER_ILLEGAL                        (CC_BOOT_IMG_VERIFIER_BASE_ERROR + 0x0000000B)
/*! Illegal number of SW components (zero). */
#define CC_BOOT_IMG_VERIFIER_SW_COMP_SIZE_IS_NULL                       (CC_BOOT_IMG_VERIFIER_BASE_ERROR + 0x0000000C)
/*! Hash of public key is not burned yet. */
#define CC_BOOT_IMG_VERIFIER_PUBLIC_KEY_HASH_EMPTY                      (CC_BOOT_IMG_VERIFIER_BASE_ERROR + 0x0000000D)
/*! Illegal lifecycle state (LCS) for the operation.*/
#define CC_BOOT_IMG_VERIFIER_ILLEGAL_LCS_FOR_OPERATION_ERR              (CC_BOOT_IMG_VERIFIER_BASE_ERROR + 0x0000000E)
/*! Hash of public key is already programmed.*/
#define CC_BOOT_IMG_VERIFIER_PUB_KEY_ALREADY_PROGRAMMED_ERR             (CC_BOOT_IMG_VERIFIER_BASE_ERROR + 0x0000000F)
/*! OTP write failure.*/
#define CC_BOOT_IMG_VERIFIER_OTP_WRITE_FAIL_ERR                         (CC_BOOT_IMG_VERIFIER_BASE_ERROR + 0x00000010)
/*! Incorrect certificate type.*/
#define CC_BOOT_IMG_VERIFIER_INCORRECT_CERT_TYPE                        (CC_BOOT_IMG_VERIFIER_BASE_ERROR + 0x00000011)
/*! Illegal Hash boot key index.*/
#define CC_BOOT_IMG_VERIFIER_ILLEGAL_HBK_IDX                            (CC_BOOT_IMG_VERIFIER_BASE_ERROR + 0x00000012)
/*! Hash boot key of OEM is not programmed.*/
#define CC_BOOT_IMG_VERIFIER_PUB_KEY1_NOT_PROGRAMMED_ERR                (CC_BOOT_IMG_VERIFIER_BASE_ERROR + 0x00000013)
/*! Illegal certificate version value.*/
#define CC_BOOT_IMG_VERIFIER_CERT_VER_VAL_ILLEGAL                       (CC_BOOT_IMG_VERIFIER_BASE_ERROR + 0x00000014)
/*! Illegal certificate decoding value.*/
#define CC_BOOT_IMG_VERIFIER_CERT_DECODING_ILLEGAL                      (CC_BOOT_IMG_VERIFIER_BASE_ERROR + 0x00000015)
/*! Illegal Kce in RMA LCS.*/
#define CC_BOOT_IMG_VERIFIER_ILLEGAL_KCE_IN_RMA_STATE                   (CC_BOOT_IMG_VERIFIER_BASE_ERROR + 0x00000016)
/*! Illegal SoC_ID value.*/
#define CC_BOOT_IMG_VERIFIER_ILLEGAL_SOC_ID_VALUE                       (CC_BOOT_IMG_VERIFIER_BASE_ERROR + 0x00000017)
/*! Illegal number of SW images per content certificate. */
#define CC_BOOT_IMG_VERIFIER_ILLEGAL_NUM_OF_IMAGES                      (CC_BOOT_IMG_VERIFIER_BASE_ERROR + 0x00000018)
/*! No need to verify the hashed public key. */
#define CC_BOOT_IMG_VERIFIER_SKIP_PUBLIC_KEY_VERIFY                     (CC_BOOT_IMG_VERIFIER_BASE_ERROR + 0x00000019)
/*! No supported functionality for SB solution. */
#define CC_BOOT_IMG_VERIFIER_NO_SUPPORTED_ERR                           (CC_BOOT_IMG_VERIFIER_BASE_ERROR + 0x0000001A)
/*! Mapping of physical address to virtual address error. */
#define CC_BOOT_IMG_VERIFIER_MAP_ERR                                    (CC_BOOT_IMG_VERIFIER_BASE_ERROR + 0x0000001B)


#ifdef __cplusplus
}
#endif

#endif

/**
 @}
 */

