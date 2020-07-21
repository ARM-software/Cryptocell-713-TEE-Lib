/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef  _MLLI_H
#define  _MLLI_H

#include "cc_plat.h"
#include "cc_lli_defs.h"

/******************************************************************************
 *                DEFINITIONS
 ******************************************************************************/

#define MLLI_BUF_SIZE                       (LLI_MAX_NUM_OF_ENTRIES * LLI_ENTRY_BYTE_SIZE)
#define MLLI_BUF_SIZE_IN_WORDS              (LLI_MAX_NUM_OF_ENTRIES * LLI_ENTRY_WORD_SIZE)
#define MLLI_IN_OUT_BUF_SIZE                (2 * MLLI_BUF_SIZE)
#define MLLI_IN_OUT_BUF_SIZE_IN_WORDS       (2 * MLLI_BUF_SIZE_IN_WORDS)

/******************************************************************************
 *                TYPE DEFINITIONS
 ******************************************************************************/

typedef enum MLLIDirection {
    MLLI_INPUT_TABLE,
    MLLI_OUTPUT_TABLE,
    MLLI_END = INT32_MAX,
} MLLIDirection_t;

/******************************************************************************
 *                FUNCTION PROTOTYPES
 ******************************************************************************/
/*!
 * This function retrieves the pointer to the first LLI entry in the MLLI
 * table which resides in SRAM. The first LLI will always be located after
 * the link entry to the next MLLI table.
 *
 * \param dir [in] -indicates MLLI_INPUT_TABLE or MLLI_OUTPUT_TABLE
 *
 * \return A pointer to the first LLI entry in the MLLI table
 */
CCSramAddr_t MLLI_getFirstLLIPtr(MLLIDirection_t dir);

/*!
 * This function initiates reading of MLLI table in given host memory to
 * the MLLI buffer in SRAM. It pushes DLLI-to-SRAM BYPASS descriptor.
 *
 * \param mlliHostAddr [in] - Host DMA address of a structure which represents the
 *            MLLI table as follow:
 *             1. A pointer to the first input MLLI table in system RAM
 *                 and it's size.
 *             2. The total number of MLLI tables.
 *             3. The table direction (can be either MLLI_INPUT_TABLE or
 *                 MLLI_OUTPUT_TABLE).
 * \param tableSize The size in bytes of the pointed MLLI table.
 * \param axiNs The AXI NS bit
 * \param direction Denotes whether this is MLLI for input or for output
 */
void MLLI_loadTableToSRAM(CCDmaAddr_t pMlliData,
                          uint32_t size,
                          uint8_t axiNs,
                          MLLIDirection_t direction);

#endif /*_MLLI_H*/

