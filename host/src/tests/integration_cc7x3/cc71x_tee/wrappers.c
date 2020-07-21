/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include <stdio.h>
#include <stdint.h>

#include "test_engine.h"

#include "cc_lib.h"
#include "test_proj.h"
#include "test_proj_cclib.h"
/******************************************************************
 * Defines
 ******************************************************************/

/******************************************************************
 * Types
 ******************************************************************/

/******************************************************************
 * Externs
 ******************************************************************/

/******************************************************************
 * Globals
 ******************************************************************/

/******************************************************************
 * Static Prototypes
 ******************************************************************/

/******************************************************************
 * Static functions
 ******************************************************************/

/******************************************************************
 * Public
 ******************************************************************/
int TE_initHostLib(void)
{
    TE_rc_t res = TE_RC_SUCCESS;

    /* Initiate CC TEE runtime library */
    Test_ProjInit();

    TE_ASSERT(Test_Proj_CC_LibInit_Wrap() == CC_LIB_RET_OK);

    goto bail;

bail:
	return res;
}

void TE_finHostLib(void)
{
    /* Finalise CC TEE runtime library */
    Test_Proj_CC_LibFini_Wrap();

    Test_ProjFree();
}

