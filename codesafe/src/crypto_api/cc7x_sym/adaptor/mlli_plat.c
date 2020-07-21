/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#define CC_PAL_LOG_CUR_COMPONENT CC_LOG_MASK_MLLI

#include "mlli.h"
#include "mlli_plat.h"
#include "cc_sram_map.h"
#include "cc_address_defs.h"

/******************************************************************************
 *				GLOBALS
 ******************************************************************************/

/******************************************************************************
 *			FUNCTIONS DECLARATIONS
 ******************************************************************************/

/******************************************************************************
 *				FUNCTIONS
 ******************************************************************************/
CCSramAddr_t MLLI_getWorkspace(MLLI_table_t tableIndex)
{
    /* prevent access to out of bounds space */
    if (tableIndex > MLLI_TABLE_2) {
        return CC_SRAM_MLLI_BASE_ADDR;
    }

    return CC_SRAM_MLLI_BASE_ADDR + (MLLI_BUF_SIZE * tableIndex);
}

