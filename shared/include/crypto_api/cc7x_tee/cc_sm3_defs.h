/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

/*!
 @file
 @brief This file contains definitions of the CryptoCell SM3 APIs.
 */


 /*!
  @addtogroup cc_sm3_defs
  @{
	  */

#ifndef CC_SM3_DEFS_H
#define CC_SM3_DEFS_H


#ifdef __cplusplus
extern "C"
{
#endif

#include "cc_pal_types.h"
#include "cc_error.h"
#include "cc_sm3_defs_proj.h"

/************************ Defines ******************************/

/*! The size of the SM3 result in bits. */
#define CC_SM3_RESULT_SIZE_IN_BITS      256
/*! The size of the SM3 result in bytes. */
#define CC_SM3_RESULT_SIZE_IN_BYTES     (CC_SM3_RESULT_SIZE_IN_BITS / CC_BITS_IN_BYTE)
/*! The size of the SM3 result in words. */
#define CC_SM3_RESULT_SIZE_IN_WORDS     (CC_SM3_RESULT_SIZE_IN_BYTES / CC_32BIT_WORD_SIZE)

/*! SM3 block size in bytes. */
#define CC_SM3_BLOCK_SIZE_IN_BYTES 64
/*! SM3 block size in words. */
#define CC_SM3_BLOCK_SIZE_IN_WORDS 16

/*! The maximal data size for the update operation. */
#define CC_SM3_UPDATE_DATA_MAX_SIZE_IN_BYTES (1 << 61)

/************************ Typedefs  *****************************/

/*! The SM3 result buffer. */
typedef uint8_t CCSm3ResultBuf_t[CC_SM3_RESULT_SIZE_IN_BYTES];

/************************ Structs  ******************************/
/*!
 The context prototype of the user.
 The argument type that is passed by the user to the SM3 APIs.
 The context saves the state of the operation, and must be saved by the user
 until the end of the API flow.
*/
typedef struct CCSm3UserContext_t {
    uint32_t buff[CC_SM3_USER_CTX_SIZE_IN_WORDS] /*!< The internal buffer. */;
}CCSm3UserContext_t;


#ifdef __cplusplus
}
#endif

/*!
  @}
  */

#endif /* #ifndef CC_SM3_DEFS_H */
