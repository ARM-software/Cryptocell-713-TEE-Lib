/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _CC_SM3_ERROR_H
#define _CC_SM3_ERROR_H


#include "cc_error.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*!
@file
@brief This file contains the definitions of the CryptoCell SM3 errors.
*/


/*!
 @addtogroup cc_sm3_error
 @{
	 */



/************************ Defines ******************************/
/*!SM3 module on the CryptoCell layer base address - 0x00F03000*/
/* The CryptoCell SM3 module errors */
/*! Illegal context pointer. */
#define CC_SM3_INVALID_USER_CONTEXT_POINTER_ERROR       (CC_SM3_MODULE_ERROR_BASE + 0x0UL)
/*! Context is corrupted. */
#define CC_SM3_USER_CONTEXT_CORRUPTED_ERROR             (CC_SM3_MODULE_ERROR_BASE + 0x1UL)
/*! Illegal data in pointer. */
#define CC_SM3_DATA_IN_POINTER_INVALID_ERROR            (CC_SM3_MODULE_ERROR_BASE + 0x2UL)
/*! Illegal data size. */
#define CC_SM3_DATA_SIZE_ILLEGAL                        (CC_SM3_MODULE_ERROR_BASE + 0x3UL)
/*! Illegal result buffer pointer. */
#define CC_SM3_INVALID_RESULT_BUFFER_POINTER_ERROR      (CC_SM3_MODULE_ERROR_BASE + 0x4UL)
/*! Last block was already processed (may happen if previous block was not a multiple of block size). */
#define CC_SM3_LAST_BLOCK_ALREADY_PROCESSED_ERROR       (CC_SM3_MODULE_ERROR_BASE + 0x5UL)
/*! Illegal parameter. */
#define CC_SM3_ILLEGAL_PARAMS_ERROR                     (CC_SM3_MODULE_ERROR_BASE + 0x6UL)
/*! Illegal context size. */
#define CC_SM3_CTX_SIZES_ERROR                          (CC_SM3_MODULE_ERROR_BASE + 0x7UL)
/*! SM3 is not supported. */
#define CC_SM3_IS_NOT_SUPPORTED                         (CC_SM3_MODULE_ERROR_BASE + 0x8UL)

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


