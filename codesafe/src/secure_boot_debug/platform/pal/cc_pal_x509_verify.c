/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include "cc_pal_x509_defs.h"

#define CC_PAL_LOG_CUR_COMPONENT CC_LOG_MASK_SECURE_BOOT

/************* Include Files ****************/

/*!
@brief This function checks validity period and should be implemented by customer.
	<ul><li> The function gets as input start and end validiy period.</li>
	<li> For each period the function gets indication flag.</li>
	<li> if the flag is not 1 the value of current period wasn't defined be user.</li></ul>

@return CC_OK	On success.
@return a non-zero value on failure.
*/

CCError_t CC_PalVerifyCertValidity(char *pNotBeforeStr,uint32_t notBeforeStrSize,uint8_t notBeforeStrFlag,
	char *pNotAfterStr,uint32_t notAfterStrSize,uint8_t notAfterStrFlag){

	if (pNotBeforeStr != NULL)
		pNotBeforeStr = pNotBeforeStr;
	if (pNotAfterStr != NULL)
		pNotAfterStr = pNotAfterStr;

	notBeforeStrSize = notBeforeStrSize;
	notBeforeStrFlag = notBeforeStrFlag;

	notAfterStrSize = notAfterStrSize;
	notAfterStrFlag = notAfterStrFlag;

	return 0;
}

