/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

/*!
@file
@brief This file contains definitions that are used in the CryptoCell SM4 APIs.
*/

/*!
  @addtogroup cc_sm4_defs
  @{
      */

#ifndef CC_SM4_DEFS_PROJ_H
#define CC_SM4_DEFS_PROJ_H


#ifdef __cplusplus
extern "C"
{
#endif

/************************ Defines ******************************/

/*! The size of the user's context prototype (see CCSm4UserContext_t) in words.
*/
#define CC_SM4_USER_CTX_SIZE_IN_WORDS 131       /*!< \internal In order to allow contiguous context the user context is doubled + 3 words for offset management */

#ifdef __cplusplus
}
#endif
/*!
  @}
  */

#endif /* #ifndef CC_SM4_DEFS_PROJ_H */
