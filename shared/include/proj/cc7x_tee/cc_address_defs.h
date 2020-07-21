/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _CC_ADDRESS_DEFS_H
#define _CC_ADDRESS_DEFS_H

/*!
 @file
 @brief This file contains general CryptoCell address definitions.
*/

/*!
 @addtogroup cc_address_defs
 @{
     */

#ifdef __cplusplus
extern "C"
{
#endif

#include "cc_pal_types.h"

/************************ Defines ******************************/

/**
 * Address types within CryptoCell.
 */
/*! Definition of DMA address type. */
typedef uint64_t  CCDmaAddr_t;
/*! Definition of CryptoCell address type. */
typedef uint64_t  CCAddr_t;
/*! Definition of CryptoCell SRAM address type, set according to CryptoCell hardware. */
typedef uint32_t  CCSramAddr_t;

/*
 * CCSramAddr_t is being cast into pointer type which can be 64 bit.
 */
/*! Definition of MACRO that casts SRAM addresses to pointer types. */
#define CCSramAddr2Ptr(sramAddr) ((uintptr_t)sramAddr)

#ifdef __cplusplus
}
#endif

#endif

/**
 @}
 */


