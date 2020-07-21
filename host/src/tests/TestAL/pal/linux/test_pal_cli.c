/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm’s non-OSI source license
 *
 */

#include <stdio.h>
#include <stdint.h>
#include "test_pal_cli.h"

/******************************************************************************/
uint32_t Test_PalCLIRegisterCommand(struct Test_PalCliCommand *commandToRegister)
{
	(void)commandToRegister;
	return 0;
}

/******************************************************************************/
const char *Test_PalCLIGetParameter(const char *commandString,
			uint32_t wantedParamIndx, uint32_t *paramStringLength)
{
	(void)commandString;
	(void)wantedParamIndx;
	(void)paramStringLength;
	return NULL;
}
