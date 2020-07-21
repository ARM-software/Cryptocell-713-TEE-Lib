/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

/*!
 @file
 @brief This file contains internal SRAM mapping definitions.
 */

#ifndef _CC_LLI_DEFS_H_
#define _CC_LLI_DEFS_H_

#include "cc_sram_map.h"

/*!< Size of entry */
#define LLI_ENTRY_WORD_SIZE     2
#define LLI_ENTRY_BYTE_SIZE     (LLI_ENTRY_WORD_SIZE * sizeof(uint32_t))
/*!< Divide by two because we store two tables in the MLLI_SRAM, one per direction */
#define LLI_MAX_NUM_OF_ENTRIES  (((CC_SRAM_MLLI_MAX_SIZE)/2)/(LLI_ENTRY_BYTE_SIZE))

#endif /*_CC_LLI_DEFS_H_*/
