/****************************************************************************
* The confidential and proprietary information contained in this file may   *
* only be used by a person authorised under and to the extent permitted     *
* by a subsisting licensing agreement from Arm Limited (or its affiliates). *
*     (C) COPYRIGHT [2018-2019] Arm Limited (or its affiliates).                 *
*         ALL RIGHTS RESERVED                                               *
* This entire notice must be reproduced on all copies of this file          *
* and copies of this file may only be made by a person if such person is    *
* permitted to do so under the terms of a subsisting license agreement      *
* from Arm Limited (or its affiliates).                                     *
*****************************************************************************/

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

    /* load REE drivers */
    system("./integration_test_run_ree.sh load");

    goto bail;

bail:
	return res;
}

void TE_finHostLib(void)
{
    /* unload REE drivers */
    system("./integration_test_run_ree.sh");

    /* Finalise CC TEE runtime library */
    Test_Proj_CC_LibFini_Wrap();

    Test_ProjFree();
}

