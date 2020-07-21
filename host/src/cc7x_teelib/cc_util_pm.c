/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include "cc_hal.h"
#include "cc_regs.h"
#include "cc_util_error.h"
#include "cc_util_pm.h"
#include "cc_pal_pm.h"
#include "cc_lib_common.h"
#include "cc_pm_data.h"

#define POWER_DOWN_EN_OFF 	0
#define POWER_DOWN_EN_ON 	1

extern int CC_CommonInit(void);
extern void CC_CommonFini(void);


CCUtilError_t CC_PmSuspend(void)
{
	/* Save values of registers into globals */
	BackupPmRegs();

	/* common with CC_LibFini */
	CC_CommonFini();

	/* Set POWER_DOWN_EN register */
	CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_POWER_DOWN_EN), POWER_DOWN_EN_ON);

	/* Power Down - call PAL function that potentially power down the CryptoCell */
	CC_PalPowerDown();

	return CC_UTIL_OK;
}


CCUtilError_t CC_PmResume(void)
{
	CCUtilError_t rc = 0;

	/* Power Up - call PAL function that makes sure that CryptoCell is on and ready to work */
	CC_PalPowerUp();

	/* wait for reset to be completed - by polling on the NVM idle register
	 * while reset in process only read access to the Cryptocell APB are
	 * available
	*/
	CC_LIB_WAIT_ON_NVM_IDLE_BIT();

	/* Clear POWER_DOWN_EN register */
	CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_POWER_DOWN_EN), POWER_DOWN_EN_OFF);

	/* Restore the hw registers from globals */
	RestorePmRegs();

	/* common initialisations */
	rc = CC_CommonInit();
	if (rc) {
		return CC_UTIL_PM_ERROR;
	}

	return CC_UTIL_OK;
}
