/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include "te_flash.h"
#include "test_pal_mem.h"
#include "test_proj.h"
#include "test_engine.h"

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
unsigned long flash_base_addr = 0;
/******************************************************************
 * Static Prototypes
 ******************************************************************/

/******************************************************************
 * Static functions
 ******************************************************************/
/******************************************************************
 * Public
 ******************************************************************/
int TE_flash_init(void)
{
    int res = 0;

    flash_base_addr = (unsigned long)Test_PalMalloc(TE_FLASH_MAX_SIZE);
    TE_ASSERT(flash_base_addr != 0);
bail:
    return res;
}


void TE_flash_finish(void)
{
    Test_PalFree((void *)flash_base_addr);
}


int TE_flash_read(CCAddr_t flashAddress, uint8_t *memDst, uint32_t sizeToRead, void* context)
{
    int res = 0;

    TE_ASSERT(memDst != NULL);
    TE_ASSERT(sizeToRead > 0);
    CC_UNUSED_PARAM(context);
    memcpy(memDst, (uint8_t *)(unsigned long)(flash_base_addr + flashAddress), sizeToRead);
    TE_LOG_INFO("read 0x%x bytes from flash offset 0x%lx to 0x%lx\n",
                sizeToRead, (unsigned long)flashAddress, (unsigned long)memDst);
bail:
    return res;
}

int TE_flash_write(CCAddr_t flashDest, uint8_t *memSrc, uint32_t sizeToWrite)
{
    int res = 0;

    TE_ASSERT(memSrc != NULL);
    TE_ASSERT(sizeToWrite > 0);
    TE_LOG_INFO("about to writing 0x%x bytes to flash offset 0x%lx\n", sizeToWrite, (unsigned long)flashDest);
    memcpy((uint8_t *)(unsigned long)(flash_base_addr + flashDest), memSrc, sizeToWrite);
bail:
    return res;
}


int TE_flash_memCmp(CCAddr_t flashAddress, uint8_t *expBuff, uint32_t sizeToRead, void* context)
{
    int res = 0;

    TE_ASSERT(expBuff != NULL);
    TE_ASSERT(sizeToRead > 0);
    CC_UNUSED_PARAM(context);
    TE_LOG_INFO("about to cmp 0x%x bytes from flash offset 0x%lx\n", sizeToRead, (unsigned long)flashAddress);
    res = memcmp(expBuff, (uint8_t *)(unsigned long)(flash_base_addr + flashAddress), sizeToRead);
bail:
    return res;
}

