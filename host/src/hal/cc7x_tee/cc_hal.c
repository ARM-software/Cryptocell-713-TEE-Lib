/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#define CC_PAL_LOG_CUR_COMPONENT CC_LOG_MASK_CCLIB

#include "cc_regs.h"
#include "cc_pal_memmap.h"
#include "cc_hal.h"
#include "cc_registers.h"
#include "cc_pal_abort.h"
#include "cc_error.h"
#include "cc_pal_types_plat.h"
#include "cc_pal_interrupt_ctrl.h"
/******************************************************************************
*				DEFINITIONS
******************************************************************************/
#define DX_CC_REG_AREA_LEN 0x100000

/******************************************************************************
*				GLOBALS
******************************************************************************/
unsigned long gCcRegBase = 0;



/******************************************************************************
*				PRIVATE FUNCTIONS
******************************************************************************/

/******************************************************************************
*				FUNCTIONS
******************************************************************************/
CCError_t CC_HalInit(void)
{
#ifndef CMPU_UTIL
    unsigned long *pVirtBuffAddr = NULL;
    CC_PalMemMap(CC_BASE_CC, DX_CC_REG_AREA_LEN, (uint32_t**) &pVirtBuffAddr);
    gCcRegBase = (unsigned long) pVirtBuffAddr;
#endif

    return CC_OK;
}

CCError_t CC_HalTerminate(void)
{
#ifndef CMPU_UTIL
    CC_PalMemUnMap((uint32_t *) gCcRegBase, DX_CC_REG_AREA_LEN);
    gCcRegBase = 0;
#endif

    return CC_OK;
}

void CC_HalClearInterrupt(uint32_t data)
{
	if (0 == data) {
		CC_PalAbort("CC_HalClearInterrupt illegal input\n");
	}

	/* clear interrupt */
	CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_RGF_ICR), data);

	return;
}

void CC_HalMaskInterrupt(uint32_t data)
{
    CC_HAL_WRITE_REGISTER( CC_REG_OFFSET(HOST_RGF, HOST_RGF_IMR), data);

    return;
}



