/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _CC_FIPS_ERROR_H
#define _CC_FIPS_ERROR_H


/*!
@file
@brief This file contains error codes definitions for CryptoCell FIPS module.
*/

/*!
 @addtogroup cc_fips_errors
 @{
     */
#include "cc_error.h"

#ifdef __cplusplus
extern "C"
{
#endif

/************************ Defines ******************************/
/* FIPS module on the CryptoCell layer base address - 0x00F01700 */
/*! FIPS general error. */
#define CC_FIPS_ERROR     (CC_FIPS_MODULE_ERROR_BASE + 0x00UL)

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
#endif


