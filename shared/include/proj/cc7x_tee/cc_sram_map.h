/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _CC_SRAM_MAP_H_
#define _CC_SRAM_MAP_H_

/*!
@file
@brief This file contains internal SRAM mapping definitions.
*/

#ifdef __cplusplus
extern "C"
{
#endif

/***********************************************
 * PKA SRAM
 * PKA dedicated SRAM buffer [0x0000-0x1800] - 6KB
 ***********************************************/
#define CC_SRAM_PKA_BASE_ADDRESS                                0x0
#define CC_PKA_SRAM_SIZE_IN_KBYTES                              6


/***********************************************
 * Internal SRAM
 * Internal dedicated SRAM buffer [0x0000-0x1000] - 4KB
 ***********************************************/
#define CC_SRAM_INTERNAL_BASE_ADDRESS                           0x0
#define CC_SRAM_INTERNAL_CLEAR_REGION_END                       1024    /*!< size of SRAM region that is automatically cleared due to POR event. in Bytes starting 0 sram base */

/*!< Addresses 0K-2K in Secure SRAM reserved for MLLI tables. */
#define CC_SRAM_MLLI_BASE_ADDR                                  0x0
#define CC_SRAM_MLLI_MAX_SIZE                                   0x800

/*!< Addresses 3K-4K in Secure SRAM reserved for driver adaptor context. */
#define CC_SRAM_DRIVER_ADAPTOR_CONTEXT_CACHE_ADDR               0xc00
#define CC_SRAM_DRIVER_ADAPTOR_CONTEXT_CACHE_LAST_WORD_ADDR     0xffc
#define CC_SRAM_DRIVER_ADAPTOR_CONTEXT_MAX_SIZE                 0x400

#ifdef __cplusplus
}
#endif

#endif /*_CC_SRAM_MAP_H_*/
