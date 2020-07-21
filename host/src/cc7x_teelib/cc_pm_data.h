/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

/*!
@file
@brief This is an internal file which contains all the enums and definitions
       that are used for both SLIM and FULL CryptoCell Lib init and finish APIs.
*/

#ifndef __CC_PM_DATA_H__
#define __CC_PM_DATA_H__

#include "cc_pal_types.h"


enum pmRegs {
	/* Cache related */
	PM_REGS_AXIM_ACE_CONST,
	PM_REGS_AXIM_CACHE_PARAMS,
	/* CPP related */
	PM_REGS_HOST_CPP_WATCHDOG,
	/* Interrupts related */
	PM_REGS_HOST_RGF_IMR,
	/* Total number of regs - used for array declaration */
	PM_REGS_MAX_NUM
};

typedef struct CC_GlobalsPmData {
	const uint32_t pmRegOffset[PM_REGS_MAX_NUM];
	uint32_t pmRegVal[PM_REGS_MAX_NUM];
}CCGlobalsPmData_t;


/* Getter for PM globals struct */
CCGlobalsPmData_t *GetCcGlobalsPm(void);

/* Backup PM registers - read values from HW registers into globals */
void BackupPmRegs(void);

/* Restore PM registers - write values from globals into HW registers */
void RestorePmRegs(void);


#endif /*__CC_PM_DATA_H__*/
