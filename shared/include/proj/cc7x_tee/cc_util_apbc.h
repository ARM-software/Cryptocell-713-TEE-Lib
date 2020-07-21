/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


#ifndef _CC_UTIL_APBC_H_
#define _CC_UTIL_APBC_H_

/*!
@file
@defgroup cc_apbc_defs CryptoCell APBC macros
@brief This file contains APBC definitions.
@{
@ingroup cryptocell_api

*/

#ifdef __cplusplus
extern "C"
{
#endif

/*! Get APBC Access counter. Return number of active APBC accesses operations */
#define CC_APBC_CNTR_GET    0

/*! Increment APBC access counter. */
#define CC_APBC_ACCESS_INC  0   /* Do Nothing, return without error */

/*! Decrement APBC access counter. */
#define CC_APBC_ACCESS_DEC  0   /* Do Nothing, return without error */


#ifdef __cplusplus
}
#endif
/**
@}
 */
#endif /*_CC_UTIL_APBC_H_*/
