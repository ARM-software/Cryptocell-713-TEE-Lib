/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include "test_proj_map.h"

#include <string.h>

/* Test Proj*/
#include "test_proj.h"
/* TestAL*/
#include "test_pal_map_addrs.h"
#include "tests_log.h"
#include "test_pal_mem.h"
#include "board_configs.h"
/* CryptoCell */
#include "dx_reg_base_host.h"


/* Global variables */
struct ProcessMappingArea_t processMap;

int Test_ProjReeMap(void)
{
    /* Set relevant mapping regions for tests */
    processMap.processReeHwRegBaseAddr = (unsigned long)Test_PalIOMap((void *)DX_REE_BASE_CC,
                                                                        TEST_PROJ_CC_REG_MAP_AREA_LEN);

    /* Verify all Maps succeeded */
    if (!VALID_MAPPED_ADDR(processMap.processReeHwRegBaseAddr)) {
        TEST_LOG_ERROR("Failed to map, processReeHwRegBaseAddr 0x%lx\n",
                    processMap.processReeHwRegBaseAddr);
        goto end_with_error;

    }
    return TEST_OK;

end_with_error:
    Test_ProjReeUnmap();
    return TEST_MAPPING_ERR;

}

void Test_ProjReeUnmap(void)
{
    Test_PalUnmapAddr((void *)processMap.processReeHwRegBaseAddr, TEST_PROJ_CC_REG_MAP_AREA_LEN);
    memset((uint8_t *)&processMap.processReeHwRegBaseAddr, 0, sizeof(unsigned long));
    return;
}


int Test_ProjTeeMap(void)
{
    processMap.processTeeUnmanagedBaseAddr = Test_PalGetUnmanagedBaseAddr();

    /* Set relevant mapping regions for tests */
    processMap.processTeeHwRegBaseAddr = (unsigned long)Test_PalIOMap((void *)CC_BASE_CC,
                                                                        TEST_PROJ_CC_REG_MAP_AREA_LEN);
    processMap.processTeeHwEnvBaseAddr = (unsigned long)Test_PalIOMap((void *)CC_BASE_ENV_REGS,
                                                                       TEST_PROJ_CC_REG_MAP_AREA_LEN);

    /* Verify all Maps succeeded */
    if ((!VALID_MAPPED_ADDR(processMap.processTeeHwRegBaseAddr)) ||
        (!VALID_MAPPED_ADDR(processMap.processTeeHwEnvBaseAddr)) ||
	(!VALID_MAPPED_ADDR(processMap.processTeeUnmanagedBaseAddr))) {
        TEST_LOG_ERROR("\nFailed to map, processTeeHwRegBaseAddr 0x%lx, processTeeHwEnvBaseAddr 0x%lx, \
                 processTeeUnmanagedBaseAddr 0x%lx\n",
                    processMap.processTeeHwRegBaseAddr,
                    processMap.processTeeHwEnvBaseAddr,
                     processMap.processTeeUnmanagedBaseAddr);
        goto end_with_error;

    }
    return TEST_OK;

end_with_error:
    Test_ProjTeeUnmap();
    return TEST_MAPPING_ERR;

}

void Test_ProjTeeUnmap(void)
{
    Test_PalUnmapAddr((void *)processMap.processTeeHwRegBaseAddr, TEST_PROJ_CC_REG_MAP_AREA_LEN);
    Test_PalUnmapAddr((void *)processMap.processTeeHwEnvBaseAddr, TEST_PROJ_CC_REG_MAP_AREA_LEN);

    processMap.processTeeHwRegBaseAddr = 0;
    processMap.processTeeHwEnvBaseAddr = 0;
    processMap.processTeeUnmanagedBaseAddr = 0;
    return;
}
