/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include "cc_pal_types.h"

#ifdef CC_IOT

void CC_PalPowerSaveModeInit(void)
{
	return;
}

void CC_PalPowerSaveModeStatus(void)
{
	return;
}

CCError_t CC_PalPowerSaveModeSelect(CCBool isPowerSaveMode)
{
	CC_UNUSED_PARAM(isPowerSaveMode);

	return 0;
}

#else /* #ifdef CC_IOT */

void CC_PalPowerDown(void)
{
	/*
	 * Specific implementation for power down according to the specific
	 * platform.
	 */

	return;
}

void CC_PalPowerUp(void)
{
	/*
	 * Specific implementation for power up according to the specific
	 * platform.
	 */

	return;
}

#endif /* #ifdef CC_IOT */
