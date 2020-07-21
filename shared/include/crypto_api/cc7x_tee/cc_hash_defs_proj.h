/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _CC_HASH_DEFS_PROJ_H
#define _CC_HASH_DEFS_PROJ_H

/*!
@file
@brief This file contains HASH definitions.
*/

/*!
 @addtogroup cc_hash_defs
  @{
      */

#ifdef __cplusplus
extern "C"
{
#endif

/************************ Defines ******************************/

/*! The size of the context prototype of the user in words. */
/* In order to allow contiguous context the user context is doubled + 3 words for management */
/*
CC_HASH_USER_CTX_SIZE_IN_WORDS = (2 * (<sizeof drv_ctx_hash in words> + <sizeof CCHashPrivateContext_t in words>)) + 3 (management) = 197
* <sizeof drv_ctx_hash in words> = CC_DRV_CTX_SIZE_WORDS(64)
* <sizeof CCHashPrivateContext_t in words> = CC_HASH_SHA512_BLOCK_SIZE_IN_WORDS(32) + <size of uint32_t in words>(1)
*/
#define CC_HASH_USER_CTX_SIZE_IN_WORDS 197


#ifdef __cplusplus
}
#endif

/*!
  @}
  */

#endif
