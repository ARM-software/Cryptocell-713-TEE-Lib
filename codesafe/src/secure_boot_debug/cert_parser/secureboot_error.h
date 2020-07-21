/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


#ifndef _SECUREBOOT_ERROR_H
#define _SECUREBOOT_ERROR_H

 /*!
@file
@brief This file defines the error codes that are returned from the Secure Boot code.
 */

/*!
 @addtogroup cc_sb_error
 @{
     */


#ifdef __cplusplus
extern "C"
{
#endif


/************************ Defines ******************************/
/*! Base error number for the space that is used for the Secure Boot modules. */
#define CC_SECUREBOOT_BASE_ERROR                 0xF0000000

/*! Base error number of the Secure Boot base layer. */
#define CC_SECUREBOOT_LAYER_BASE_ERROR           0x01000000

/*! Error prefix number of the Secure Boot verifier layer. */
#define CC_SB_VERIFIER_LAYER_PREFIX         1
/*! Error prefix number of the Secure Boot driver layer. */
#define CC_SB_DRV_LAYER_PREFIX          2
/*! Error prefix number of the Secure Boot HAL layer. */
#define CC_SB_HAL_LAYER_PREFIX                  6
/*! Error prefix number of the Secure Boot RSA layer. */
#define CC_SB_RSA_LAYER_PREFIX              7
/*! Error prefix number of the Secure Boot certificate verifier layer. */
#define CC_SB_VERIFIER_CERT_LAYER_PREFIX    8
/*! Error prefix number of the Secure Boot X509 certificate layer. */
#define CC_SB_X509_CERT_LAYER_PREFIX        9


/*! Base error of the Boot images verifier = 0xF1000000. */
#define CC_BOOT_IMG_VERIFIER_BASE_ERROR          (CC_SECUREBOOT_BASE_ERROR + CC_SB_VERIFIER_LAYER_PREFIX*CC_SECUREBOOT_LAYER_BASE_ERROR)
/*! Base error of the Secure Boot HAL = 0xF6000000. */
#define CC_SB_HAL_BASE_ERROR                     (CC_SECUREBOOT_BASE_ERROR + CC_SB_HAL_LAYER_PREFIX*CC_SECUREBOOT_LAYER_BASE_ERROR)
/*! Base error of the Secure Boot RSA = 0xF7000000. */
#define CC_SB_RSA_BASE_ERROR                     (CC_SECUREBOOT_BASE_ERROR + CC_SB_RSA_LAYER_PREFIX*CC_SECUREBOOT_LAYER_BASE_ERROR)

/*! Base error of the boot images verifier certificates = 0xF8000000. */
#define CC_BOOT_IMG_VERIFIER_CERT_BASE_ERROR     (CC_SECUREBOOT_BASE_ERROR + CC_SB_VERIFIER_CERT_LAYER_PREFIX*CC_SECUREBOOT_LAYER_BASE_ERROR)

/*! Base error of the X.509 certificates = 0xF9000000. */
#define CC_SB_X509_CERT_BASE_ERROR               (CC_SECUREBOOT_BASE_ERROR + CC_SB_X509_CERT_LAYER_PREFIX*CC_SECUREBOOT_LAYER_BASE_ERROR)

/*! Base error of the cryptographic driver = 0xF2000000. */
#define CC_SB_DRV_BASE_ERROR                     (CC_SECUREBOOT_BASE_ERROR + CC_SB_DRV_LAYER_PREFIX*CC_SECUREBOOT_LAYER_BASE_ERROR)

/*! HAL fatal error. */
#define CC_SB_HAL_FATAL_ERROR_ERR                (CC_SB_HAL_BASE_ERROR + 0x00000001)
/*! Illegal input error. */
#define CC_SB_DRV_ILLEGAL_INPUT_ERR              (CC_SB_DRV_BASE_ERROR + 0x00000001)
/*! Illegal key error. */
#define CC_SB_DRV_ILLEGAL_KEY_ERR                (CC_SB_DRV_BASE_ERROR + 0x00000002)
/*! Illegal size error. */
#define CC_SB_DRV_ILLEGAL_SIZE_ERR               (CC_SB_DRV_BASE_ERROR + 0x00000003)


#ifdef __cplusplus
}
#endif

#endif

/**
 @}
 */


