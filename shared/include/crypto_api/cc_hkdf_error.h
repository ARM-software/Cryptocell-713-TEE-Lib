/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _CC_HKDF_ERROR_H
#define _CC_HKDF_ERROR_H

#include "cc_error.h"


#ifdef __cplusplus
extern "C"
{
#endif

/*!
 @file
 @brief This file contains the definitions of the CryptoCell HKDF errors.
 */

 /*!
 @addtogroup cc_hkdf_error
 @{
 */


/************************ Defines *******************************/

/*! CryptoCell HKDF module errors / base address - 0x00F01100. */
/*! Invalid argument. */
#define CC_HKDF_INVALID_ARGUMENT_POINTER_ERROR      \
                                            (CC_HKDF_MODULE_ERROR_BASE + 0x0UL)
/*! Invalid argument size. */
#define CC_HKDF_INVALID_ARGUMENT_SIZE_ERROR         \
                                            (CC_HKDF_MODULE_ERROR_BASE + 0x1UL)
/*! Illegal hash mode. */
#define CC_HKDF_INVALID_ARGUMENT_HASH_MODE_ERROR    \
                                            (CC_HKDF_MODULE_ERROR_BASE + 0x3UL)
/*! HKDF not supported. */
#define CC_HKDF_IS_NOT_SUPPORTED                    \
                                           (CC_HKDF_MODULE_ERROR_BASE + 0xFFUL)


#ifdef __cplusplus
}
#endif
/*!
@}
 */
#endif




