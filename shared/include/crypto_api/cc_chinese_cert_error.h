/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _CC_CH_CERT_ERROR_H
#define _CC_CH_CERT_ERROR_H


/*!
@file
@brief This file contains error codes definitions for CryptoCell Chinese
certification module.
*/

/*!
 @addtogroup ch_cert_errors
 @{
*/

#include "cc_error.h"

#ifdef __cplusplus
extern "C"
{
#endif

/************************ Defines ******************************/
/*! Chinese Certification module error base address - 0x00F01800. */
#define CC_CH_CERT_ERROR     (CC_CH_CERT_MODULE_ERROR_BASE + 0x00UL)

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


