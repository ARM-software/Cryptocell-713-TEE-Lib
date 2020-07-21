/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

/*!
@file
@brief This file contains the definitions of the CryptoCell SM4 errors.
*/


/*!
 @addtogroup cc_sm4_error
 @{
	 */

#ifndef CC_SM4_ERROR_H
#define CC_SM4_ERROR_H

#include "cc_error.h"

#ifdef __cplusplus
extern "C"
{
#endif

/************************ Defines ******************************/

/*! CC_SM4_MODULE_ERROR_BASE - 0x00F03100 */
/*! Illegal user context. */
#define CC_SM4_INVALID_USER_CONTEXT_POINTER_ERROR     (CC_SM4_MODULE_ERROR_BASE + 0x00UL)
/*! Illegal IV pointer. */
#define CC_SM4_INVALID_IV_POINTER_ERROR               (CC_SM4_MODULE_ERROR_BASE + 0x01UL)
/*! Illegal operation. */
#define CC_SM4_ILLEGAL_OPERATION_MODE_ERROR           (CC_SM4_MODULE_ERROR_BASE + 0x02UL)
/*! Illegal key size. */
#define CC_SM4_ILLEGAL_KEY_SIZE_ERROR                 (CC_SM4_MODULE_ERROR_BASE + 0x03UL)
/*! Illegal key pointer. */
#define CC_SM4_INVALID_KEY_POINTER_ERROR              (CC_SM4_MODULE_ERROR_BASE + 0x04UL)
/*! Illegal operation. */
#define CC_SM4_INVALID_ENCRYPT_MODE_ERROR             (CC_SM4_MODULE_ERROR_BASE + 0x05UL)
/*! User context corrupted. */
#define CC_SM4_USER_CONTEXT_CORRUPTED_ERROR           (CC_SM4_MODULE_ERROR_BASE + 0x06UL)
/*! Illegal data in pointer. */
#define CC_SM4_DATA_IN_POINTER_INVALID_ERROR          (CC_SM4_MODULE_ERROR_BASE + 0x07UL)
/*! Illegal data out pointer. */
#define CC_SM4_DATA_OUT_POINTER_INVALID_ERROR         (CC_SM4_MODULE_ERROR_BASE + 0x08UL)
/*! Illegal data in size. */
#define CC_SM4_DATA_IN_SIZE_ILLEGAL                   (CC_SM4_MODULE_ERROR_BASE + 0x09UL)
/*! Illegal parameters. */
#define CC_SM4_ILLEGAL_PARAMS_ERROR                   (CC_SM4_MODULE_ERROR_BASE + 0x0AUL)
/*! Illegal inplace operation. */
#define CC_SM4_ILLEGAL_INPLACE_ERROR                  (CC_SM4_MODULE_ERROR_BASE + 0x0BUL)
/*! SM4 is not supported. */
#define CC_SM4_IS_NOT_SUPPORTED                       (CC_SM4_MODULE_ERROR_BASE + 0xFFUL)

/************************ Enums ********************************/

/************************ Typedefs  ****************************/

/************************ Structs  *****************************/

/************************ Public Variables *********************/

/************************ Public Functions *********************/

#ifdef __cplusplus
}
#endif
/*!
@}
 */

#endif /* #ifndef CC_SM4_ERROR_H */
