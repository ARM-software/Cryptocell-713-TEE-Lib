/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

/*!
@file
@brief This file contains the enumerations and definitions that are used for the
        CryptoCell hardware key APIs, as well as the APIs themselves.
*/

/*!
 @addtogroup cc_hw_key_utils
 @{
     */

#ifndef __CC_UTIL_HW_KEY_H__
#define __CC_UTIL_HW_KEY_H__

#include "cc_pal_types.h"
/*!Key slot value */
typedef enum {
	CC_HW_KEY_SLOT_0 = 0, /*!< Key slot value 0. */
	CC_HW_KEY_SLOT_1 = 1, /*!< Key slot value 1. */
	CC_HW_KEY_SLOT_2 = 2, /*!< Key slot value 2. */
	CC_HW_KEY_SLOT_3 = 3, /*!< Key slot value 3.*/
	CC_HW_KEY_SLOT_RESERVE32B = 0x7FFFFFFFL /*!< Reserved. */
} CCUtilSlotNum_t;

/*!Return values */
typedef enum {
	CC_HW_KEY_RET_OK = 0,
	CC_HW_KEY_RET_NULL_KEY_PTR,	/*!< Invalid key. */
	CC_HW_KEY_RET_BAD_KEY_SIZE,	/*!< Invalid key size. */
	CC_HW_KEY_RET_BAD_SLOT_NUM,	/*!< Invalid slot number. */
 	CC_HW_KEY_RET_SD_ENABLED_ERROR, /*!< Secure Disable control is set. */
	CC_HW_KEY_RET_FATAL_ERR_IS_LOCKED_ERR, /*!< Device is locked in fatal error state. */
	CC_HW_KEY_RET_RESERVE32B = 0x7FFFFFFFL /*!< Reserved. */
} CCUtilHwKeyRetCode_t;


/*!
@brief This function sets a key into the hardware key slot.
 \note This function overrides any previous existing data in the hardware slot. It is your responsibility to manage the keys in the hardware slots.
 @return \c CC_HW_KEY_RET_OK on success.
 @return A non-zero value in case of failure.
*/
CCUtilHwKeyRetCode_t CC_UtilHwKeySet(uint8_t *pKey,           /*!< [in] Pointer to the key buffer */
				     size_t keySize,          /*!< [in] Key size in bytes */
				     CCUtilSlotNum_t slotNum  /*!< [in] Slot number for setting the key into */);

  /*!
    @}
  */

#endif /*__CC_UTIL_HW_KEY_H__*/

