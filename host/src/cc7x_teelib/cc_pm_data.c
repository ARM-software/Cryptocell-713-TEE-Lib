/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include "cc_pm_data.h"
#include "cc_regs.h"
#include "cc_hal.h"


/* Declare and Init of Global PM Data structure */
static CCGlobalsPmData_t gPmData = {
	.pmRegOffset =
	{
		CC_REG_OFFSET(CRY_KERNEL, AXIM_ACE_CONST),
		CC_REG_OFFSET(CRY_KERNEL, AXIM_CACHE_PARAMS),
		CC_REG_OFFSET(CRY_KERNEL, HOST_CPP_WATCHDOG),
		CC_REG_OFFSET(HOST_RGF, HOST_RGF_IMR)
	},
	.pmRegVal = {0}
};

/* Getter for PM globals struct */
CCGlobalsPmData_t *GetCcGlobalsPm(void)
{
	return &gPmData;
}

void BackupPmRegs(void)
{
	int i = 0;
	for (i = 0; i < PM_REGS_MAX_NUM; ++i) {
		gPmData.pmRegVal[i] = CC_HAL_READ_REGISTER(gPmData.pmRegOffset[i]);
	}
}

void RestorePmRegs(void)
{
	int i = 0;
	for (i = 0; i < PM_REGS_MAX_NUM; ++i) {
		CC_HAL_WRITE_REGISTER(gPmData.pmRegOffset[i], gPmData.pmRegVal[i]);
	}
}
