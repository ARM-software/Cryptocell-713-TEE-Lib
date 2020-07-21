/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#define CC_PAL_LOG_CUR_COMPONENT CC_LOG_MASK_MLLI

#include "cc_pal_types.h"
#include "cc_pal_mem.h"
#include "cc_pal_abort.h"
#include "cc_plat.h"
#include "completion.h"
#include "hw_queue.h"
#include "mlli.h"
#include "mlli_plat.h"

/******************************************************************************
 *                GLOBALS
 ******************************************************************************/
#ifdef DEBUG
#define DUMP_SRAM(addr, size)                                                                 \
    do {                                                                                      \
        uint32_t i = 0;                                                                       \
        for (i = 0; i < size / 4; ++i) {                                                      \
            uint32_t val1 = 0;                                                                \
            _ReadValueFromSram(addr + i * 4, val1);                                           \
            CC_PAL_LOG_DEBUG("%s:%d sram[0x%03x] = 0x%08x\n", __func__, __LINE__, i, val1);   \
        }                                                                                     \
    } while (0)
#else
#define DUMP_SRAM(addr, size) do { }while(0)
#endif

/******************************************************************************
 *            FUNCTIONS DECLARATIONS
 ******************************************************************************/

/******************************************************************************
 *                FUNCTIONS
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
CCSramAddr_t MLLI_getFirstLLIPtr(MLLIDirection_t direction)
{
    MLLI_table_t tableIdx = (direction == MLLI_INPUT_TABLE) ? MLLI_TABLE_1 : MLLI_TABLE_2;
    return MLLI_getWorkspace(tableIdx);
}

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
                          MLLIDirection_t direction)
{
    CCSramAddr_t mlliAdr;
    HwDesc_s desc;

    /* Check if already allocated by external module */
    if (MLLI_getIsMlliExternalAlloc() == 1) {
        CC_PalAbort("MLLI workspace is already allocated by external module");
    }

    if (size > MLLI_BUF_SIZE) {
        CC_PAL_LOG_ERR("Given MLLI size=%u B is too large!\n", (unsigned int)size);
        CC_PalAbort("Given MLLI size is too large!");
    }

    mlliAdr = MLLI_getFirstLLIPtr(direction);

    /* prepare the first MLLI mlliTable from host */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_DIN_TYPE(&desc, DMA_DLLI, pMlliData, size, axiNs);
    HW_DESC_SET_DOUT_SRAM(&desc, mlliAdr, size);
    HW_DESC_SET_FLOW_MODE(&desc, BYPASS);
    AddHWDescSequence(&desc);

    DUMP_SRAM(mlliAdr, size);


}

