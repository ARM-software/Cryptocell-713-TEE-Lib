/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */
#include <stdint.h>
#include <string.h>

#include "dx_env.h"

/*TestAL*/
#include "board_configs.h"
#include "tests_log.h"

/* Test Proj*/
#include "test_proj.h"
#include "test_proj_map.h"
#include "test_proj_defs.h"
extern struct ProcessMappingArea_t processMap;

int Test_ProjInit(void)
{
    int error;

    /* Init platform specific memories: DMAble & unmanaged */
    error = Test_HalBoardInit();
    if (error != 0) {
        TEST_LOG_ERROR("Failed to Test_HalBoardInit 0x%x\n", error);
        return error;
    }

    /* Initialize processMap value */
     memset((uint8_t *)&processMap, 0, sizeof(struct ProcessMappingArea_t));

    error = Test_ProjTeeMap();
    if (error != 0) {
        TEST_LOG_ERROR("Failed to Test_ProjTeeMap 0x%x\n", error);
        goto end_with_error1;
    }

    Test_ProjSetCacheParams(TEST_PROJ_SW_CACHE);
    Test_ProjSetSecureMode();
    Test_ProjSetFlavor();

    return 0;

end_with_error1:
    Test_HalBoardFree();

    return error;
}

void Test_ProjFree(void)
{
    Test_ProjSetFullFlavor(); /* revert FPGA to the FULL flavor (default flavor)*/
    Test_ProjTeeUnmap();
    Test_HalBoardFree();
    return;
}
