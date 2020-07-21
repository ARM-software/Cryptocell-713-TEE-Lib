/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

/*!
 @file
 @brief This file contains the error definitions of the CryptoCell utility APIs.
 */



 /*!
  @addtogroup cc_utils_errors
  @{
	  */

#ifndef  _CC_UTIL_ERROR_H
#define  _CC_UTIL_ERROR_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "cc_pal_types.h"

/*! Util Error type. */
typedef uint32_t CCUtilError_t;

/***********************/
/* Util return codes   */
/***********************/
/*! Success definition. */
#define CC_UTIL_OK                                      0x00UL
/*! The error base address definition. */
#define CC_UTIL_MODULE_ERROR_BASE                       0x80000000
/*! Illegal key type. */
#define CC_UTIL_INVALID_KEY_TYPE                        (CC_UTIL_MODULE_ERROR_BASE + 0x00UL)
/*! Illegal data-in pointer. */
#define CC_UTIL_DATA_IN_POINTER_INVALID_ERROR           (CC_UTIL_MODULE_ERROR_BASE + 0x01UL)
/*! Illegal data-in size. */
#define CC_UTIL_DATA_IN_SIZE_INVALID_ERROR              (CC_UTIL_MODULE_ERROR_BASE + 0x02UL)
/*! Illegal data-out pointer. */
#define CC_UTIL_DATA_OUT_POINTER_INVALID_ERROR          (CC_UTIL_MODULE_ERROR_BASE + 0x03UL)
/*! Illegal data-out size. */
#define CC_UTIL_DATA_OUT_SIZE_INVALID_ERROR             (CC_UTIL_MODULE_ERROR_BASE + 0x04UL)
/*! Fatal error. */
#define CC_UTIL_FATAL_ERROR                             (CC_UTIL_MODULE_ERROR_BASE + 0x05UL)
/*! Illegal parameters. */
#define CC_UTIL_ILLEGAL_PARAMS_ERROR                    (CC_UTIL_MODULE_ERROR_BASE + 0x06UL)
/*! Invalid address given. */
#define CC_UTIL_BAD_ADDR_ERROR                          (CC_UTIL_MODULE_ERROR_BASE + 0x07UL)
/*! Illegal domain for endorsement key. */
#define CC_UTIL_EK_DOMAIN_INVALID_ERROR                 (CC_UTIL_MODULE_ERROR_BASE + 0x08UL)
/*! HUK is not valid. */
#define CC_UTIL_KDR_INVALID_ERROR                       (CC_UTIL_MODULE_ERROR_BASE + 0x09UL)
/*! KCP is not valid. */
#define CC_UTIL_KCP_INVALID_ERROR                       (CC_UTIL_MODULE_ERROR_BASE + 0x0AUL)
/*! KPICV is not valid. */
#define CC_UTIL_KPICV_INVALID_ERROR                     (CC_UTIL_MODULE_ERROR_BASE + 0x0BUL)
/*! KCST is not disabled */
#define CC_UTIL_KCST_NOT_DISABLED_ERROR                 (CC_UTIL_MODULE_ERROR_BASE + 0x0CUL)
/*! LCS is not valid. */
#define CC_UTIL_LCS_INVALID_ERROR                       (CC_UTIL_MODULE_ERROR_BASE + 0x0DUL)
/*! Session key is not valid. */
#define CC_UTIL_SESSION_KEY_ERROR                       (CC_UTIL_MODULE_ERROR_BASE + 0x0EUL)
/*! Illegal user key size. */
#define CC_UTIL_INVALID_USER_KEY_SIZE                   (CC_UTIL_MODULE_ERROR_BASE + 0x0FUL)
/*! Illegal LCS for the required operation. */
#define CC_UTIL_ILLEGAL_LCS_FOR_OPERATION_ERR           (CC_UTIL_MODULE_ERROR_BASE + 0x10UL)
/*! Invalid PRF type. */
#define CC_UTIL_INVALID_PRF_TYPE                        (CC_UTIL_MODULE_ERROR_BASE + 0x11UL)
/*! Invalid hash mode. */
#define CC_UTIL_INVALID_HASH_MODE                       (CC_UTIL_MODULE_ERROR_BASE + 0x12UL)
/*! Unsupported hash mode. */
#define CC_UTIL_UNSUPPORTED_HASH_MODE                   (CC_UTIL_MODULE_ERROR_BASE + 0x13UL)
/*! Key is unusable. */
#define CC_UTIL_KEY_UNUSABLE_ERROR                      (CC_UTIL_MODULE_ERROR_BASE + 0x14UL)
/*! Power Management error. */
#define CC_UTIL_PM_ERROR                                (CC_UTIL_MODULE_ERROR_BASE + 0x15UL)
/*! Security disable bit is asserted , API should not be used. */
#define CC_UTIL_SD_IS_SET_ERROR                         (CC_UTIL_MODULE_ERROR_BASE + 0x16UL)
/*! Setting fatal error failed. */
#define CC_UTIL_FATAL_ERROR_SET_FAILED                  (CC_UTIL_MODULE_ERROR_BASE + 0x17UL)
/*! Device is locked in fatal error state. */
#define CC_UTIL_FATAL_ERR_IS_LOCKED_ERR                 (CC_UTIL_MODULE_ERROR_BASE + 0x18UL)

#ifdef __cplusplus
}
#endif
/*!
  @}
  */

#endif /*_CC_UTIL_ERROR_H*/
