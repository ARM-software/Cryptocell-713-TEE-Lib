/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

/*!
@file
@brief This file contains definitions that are used in the CryptoCell AES APIs.
*/
/*!
 @addtogroup cc_aes_defs
  @{
  */

#ifndef CC_AES_DEFS_PROJ_H
#define CC_AES_DEFS_PROJ_H

#include "cc_pal_types.h"


#ifdef __cplusplus
extern "C"
{
#endif

/************************ Defines ******************************/

/*! The size of your context prototype (see CCAesUserContext_t) expressed in words. */
#define CC_AES_USER_CTX_SIZE_IN_WORDS 131		/*!< \internal In order to allow contiguous context the user context is doubled + 3 words for offset management */

/*! The maximum size of the AES key expressed in words. */
#define CC_AES_KEY_MAX_SIZE_IN_WORDS 16
/*! The maximum size of the AES key expressed in bytes. */
#define CC_AES_KEY_MAX_SIZE_IN_BYTES (CC_AES_KEY_MAX_SIZE_IN_WORDS * sizeof(uint32_t))


#ifdef __cplusplus
}
#endif
 /*!
  @}
  */


#endif /* #ifndef CC_AES_DEFS_PROJ_H */
