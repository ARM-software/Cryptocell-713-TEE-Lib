/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _CC_SM3_DEFS_PROJ_H
#define _CC_SM3_DEFS_PROJ_H

/*!
@file
@brief This file contains SM3 definitions.
*/

/*!
 @addtogroup cc_sm3_defs
 @{
*/

#ifdef __cplusplus
extern "C"
{
#endif

/************************ Defines ******************************/

/*! The size of user's context prototype (see CCSm3UserContext_t) in words. */
/* In order to allow contiguous context the user context is doubled + 3 words for management */
/*
CC_SM3_USER_CTX_SIZE_IN_WORDS = (2 * (<sizeof drv_ctx_hash in words> + <sizeof CCSm3PrivCtx_t in words>)) + 3 (management) = 197
* <sizeof drv_ctx_hash in words> = CC_DRV_CTX_SIZE_WORDS(64)
* <sizeof CCSm3PrivCtx_t in words> = CC_SM3_BLOCK_SIZE_IN_WORDS(16) + <size of uint32_t in words>(1)
*/
#define CC_SM3_USER_CTX_SIZE_IN_WORDS 165

#ifdef __cplusplus
}
#endif
/*!
@}
 */

#endif
