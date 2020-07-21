/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


#ifndef _CC_DES_ERROR_H
#define _CC_DES_ERROR_H

#include "cc_error.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*!
@file
@brief This file contains the definitions of the CryptoCell DES errors.
*/

/*!
 @addtogroup cc_des_error
 */


/************************ Defines ******************************/

/* The CryptoCell DES module errors */
/*! Invalid user context pointer.*/
#define CC_DES_INVALID_USER_CONTEXT_POINTER_ERROR     (CC_DES_MODULE_ERROR_BASE + 0x0UL)
/*! Invalid iv pointer. */
#define CC_DES_INVALID_IV_PTR_ON_NON_ECB_MODE_ERROR   (CC_DES_MODULE_ERROR_BASE + 0x1UL)
/*! Illegal operation mode.*/
#define CC_DES_ILLEGAL_OPERATION_MODE_ERROR           (CC_DES_MODULE_ERROR_BASE + 0x2UL)
/*! Illegal number of keys.*/
#define CC_DES_ILLEGAL_NUM_OF_KEYS_ERROR              (CC_DES_MODULE_ERROR_BASE + 0x3UL)
/*! Invalid key pointer.*/
#define CC_DES_INVALID_KEY_POINTER_ERROR              (CC_DES_MODULE_ERROR_BASE + 0x4UL)
/*! Invalid encryption mode.*/
#define CC_DES_INVALID_ENCRYPT_MODE_ERROR             (CC_DES_MODULE_ERROR_BASE + 0x5UL)
/*! Corrupted user context.*/
#define CC_DES_USER_CONTEXT_CORRUPTED_ERROR           (CC_DES_MODULE_ERROR_BASE + 0x6UL)
/*! Invalid data in pointer.*/
#define CC_DES_DATA_IN_POINTER_INVALID_ERROR          (CC_DES_MODULE_ERROR_BASE + 0x7UL)
/*! Invalid data out pointer.*/
#define CC_DES_DATA_OUT_POINTER_INVALID_ERROR         (CC_DES_MODULE_ERROR_BASE + 0x8UL)
/*! Invalid data size.*/
#define CC_DES_DATA_SIZE_ILLEGAL                      (CC_DES_MODULE_ERROR_BASE + 0x9UL)
/*! Overlap of data in and data out.*/
#define CC_DES_DATA_OUT_DATA_IN_OVERLAP_ERROR         (CC_DES_MODULE_ERROR_BASE + 0xAUL)
/*! Illegal parameters.*/
#define CC_DES_ILLEGAL_PARAMS_ERROR		      (CC_DES_MODULE_ERROR_BASE + 0x13UL)
/*! CryptoCell DES is not supported. */
#define CC_DES_IS_NOT_SUPPORTED                       (CC_DES_MODULE_ERROR_BASE + 0x1FUL)

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


