/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef  _CC_UTIL_RPMB_H
#define  _CC_UTIL_RPMB_H

/*!
@file
@brief This file contains the functions and definitions for the Replay Protected Memory Block.
*/

/*!
 @addtogroup rpmb_util
  @{
  */

#ifdef __cplusplus
extern "C"
{
#endif

#include "cc_util_defs.h"
#include "cc_util_error.h"

/******************************************************************************
*                        	DEFINITIONS
******************************************************************************/

/*******************************************/
/*   RPMB shared secret key definitions    */
/*******************************************/
/*! RPMB frame size in bytes. */
#define CC_UTIL_RPMB_DATA_FRAME_SIZE_IN_BYTES	 	 284
/*! RPMB minimal number of data buffers to signe on. */
#define CC_UTIL_MIN_RPMB_DATA_BUFFERS			 1
/*! RPMB maximal number of data buffers to signe on. */
#define CC_UTIL_MAX_RPMB_DATA_BUFFERS			 65535
/*! HMAC digest size in words. */
#define CC_UTIL_HMAC_SHA256_DIGEST_SIZE_IN_WORDS 	 8

/*! definition of RPMB key structure. */
typedef uint8_t 	CCUtilRpmbKey_t[CC_UTIL_AES_CMAC_RESULT_SIZE_IN_BYTES*2];
/*! definition of RPMB data frame. */
typedef uint8_t 	CCUtilRpmbDataBuffer_t[CC_UTIL_RPMB_DATA_FRAME_SIZE_IN_BYTES];
 /*! definition of HMAC result. */
typedef uint32_t 	CCUtilHmacResult_t[CC_UTIL_HMAC_SHA256_DIGEST_SIZE_IN_WORDS];


/**
 * @brief This function derives a 256-bit RPMB key by performing AES CMAC on fixed data, using Huk. Because the derivation is
 * 	  performed based on fixed data, the key does not need to be saved and can be derived again consistently.
 *
 *
 * @return \c CC_UTIL_OK on success.
 * @return A non-zero value on failure, as defined in cc_util_error.h.
 */
CCUtilError_t CC_UtilDeriveRPMBKey(CCUtilRpmbKey_t pRpmbKey /*!< [out] Pointer to 32byte output, to be used as RPMB key. */);


/**
 * @brief This function computes HMAC SHA-256 authentication code of a sequence of 284-byte RPMB frames
 * 	 (as defined in JEDEC STANDARD, Embedded Multimedia Card (eMMC), Electrical Standard), using the RPMB key (which is derived internally using ::CC_UtilDeriveRPMBKey).
 *
 *
 * @return \c CC_UTIL_OK on success.
 * @return A non-zero value on failure, as defined in cc_util_error.h.
 */
CCUtilError_t CC_UtilSignRPMBFrames(
			unsigned long *pListOfDataFrames, /*!< [in] Pointer to a list of 284-byte frame addresses. The entire frame list is signed.*/
			size_t listSize, 		  /*!< [in] The number of 284-byte frames in the list, up to 65,535. */
			CCUtilHmacResult_t pHmacResult  /*!< [out] Pointer to the output data (HMAC result). */);

#ifdef __cplusplus
}
#endif
/*!
 @}
 */
#endif /*_CC_UTIL_RPMB_H*/
