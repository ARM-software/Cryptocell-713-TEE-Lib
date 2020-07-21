/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef  _CC_UTIL_KEY_DERIVATION_DEFS_H
#define  _CC_UTIL_KEY_DERIVATION_DEFS_H

/*!
@file
@brief This file contains the definitions for the key derivation API.
*/

/*!
 @addtogroup cc_utils_key_defs
 @{
 */

#ifdef __cplusplus
extern "C"
{
#endif

/******************************************************************************
*                            DEFINITIONS
******************************************************************************/

/*! Maximal label length in bytes. */
#define    CC_UTIL_MAX_LABEL_LENGTH_IN_BYTES    64
/*! Maximal context length in bytes. */
#define    CC_UTIL_MAX_CONTEXT_LENGTH_IN_BYTES  64
/*! Minimal fixed data size in bytes. */
#define CC_UTIL_FIX_DATA_MIN_SIZE_IN_BYTES      3 /*!< \internal counter, 0x00, length(-0xff) */
/*! Maximal fixed data size in bytes. */
#define CC_UTIL_FIX_DATA_MAX_SIZE_IN_BYTES      4 /*!< \internal counter, 0x00, length(0x100-0xff0) */
/*! Maximal derived key material size in bytes. */
#define CC_UTIL_MAX_KDF_SIZE_IN_BYTES           \
    (CC_UTIL_MAX_LABEL_LENGTH_IN_BYTES + CC_UTIL_MAX_CONTEXT_LENGTH_IN_BYTES + CC_UTIL_FIX_DATA_MAX_SIZE_IN_BYTES)
/*! Maximal derived key size in bytes. */
#define CC_UTIL_MAX_DERIVED_KEY_SIZE_IN_BYTES   4080

#ifdef __cplusplus
}
#endif
/**
@}
 */

#endif /*_CC_UTIL_KEY_DERIVATION_DEFS_H*/

