/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


#ifndef _CC_HMAC_ERROR_H
#define _CC_HMAC_ERROR_H

#include "cc_error.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*! @file
 @brief This file contains the definitions of the CryptoCell HMAC errors.
 */

 /*!
 @addtogroup cc_hmac_error
 @{
*/



/************************ Defines ******************************/

/* The CryptoCell HMAC module errors */
/*! Illegal context pointer. */
#define CC_HMAC_INVALID_USER_CONTEXT_POINTER_ERROR     (CC_HMAC_MODULE_ERROR_BASE + 0x0UL)
/*! Illegal operation mode. */
#define CC_HMAC_ILLEGAL_OPERATION_MODE_ERROR           (CC_HMAC_MODULE_ERROR_BASE + 0x1UL)
/*! Context is corrupted. */
#define CC_HMAC_USER_CONTEXT_CORRUPTED_ERROR           (CC_HMAC_MODULE_ERROR_BASE + 0x2UL)
/*! Illegal data in pointer. */
#define CC_HMAC_DATA_IN_POINTER_INVALID_ERROR          (CC_HMAC_MODULE_ERROR_BASE + 0x3UL)
/*! Illegal data in size. */
#define CC_HMAC_DATA_SIZE_ILLEGAL                      (CC_HMAC_MODULE_ERROR_BASE + 0x4UL)
/*! Illegal result buffer pointer. */
#define CC_HMAC_INVALID_RESULT_BUFFER_POINTER_ERROR    (CC_HMAC_MODULE_ERROR_BASE + 0x5UL)
/*! Illegal key buffer pointer. */
#define CC_HMAC_INVALID_KEY_POINTER_ERROR              (CC_HMAC_MODULE_ERROR_BASE + 0x6UL)
/*! Illegal key size. */
#define CC_HMAC_UNVALID_KEY_SIZE_ERROR                 (CC_HMAC_MODULE_ERROR_BASE + 0x7UL)
/*! Last block was already processed (may happen if previous block was not a multiple of block size). */
#define CC_HMAC_LAST_BLOCK_ALREADY_PROCESSED_ERROR     (CC_HMAC_MODULE_ERROR_BASE + 0xBUL)
/*! Illegal parameters. */
#define CC_HMAC_ILLEGAL_PARAMS_ERROR                    (CC_HMAC_MODULE_ERROR_BASE + 0xCUL)
/*! Illegal context size. */
#define CC_HMAC_CTX_SIZES_ERROR                         (CC_HMAC_MODULE_ERROR_BASE + 0xEUL)
/*! HMAC is not supported. */
#define CC_HMAC_IS_NOT_SUPPORTED                        (CC_HMAC_MODULE_ERROR_BASE + 0xFUL)



/************************ Enums ********************************/


/************************ Typedefs  ****************************/


/************************ Structs  ******************************/


/************************ Public Variables **********************/


/************************ Public Functions **********************/

#ifdef __cplusplus
}
#endif
/*!
@}
 */
#endif


