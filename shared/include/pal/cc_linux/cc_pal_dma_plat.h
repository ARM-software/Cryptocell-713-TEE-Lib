/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _CC_PAL_DMA_PLAT_H
#define _CC_PAL_DMA_PLAT_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "cc_address_defs.h"
#include "dx_reg_base_host.h"

/*! ----------------------------
        DEFINITIONS
--------------------------------*/
#ifdef CC_PLAT_ZYNQ7000
/* Zynq EVBs have 1GB and we reserve the memory at offset 768M */
#define PAL_WORKSPACE_MEM_BASE_ADDR     0x34000000
#elif defined PLAT_VIRTEX5
/* Virtex5 platforms (PPC) have 512MB and we reserve the memory at offset 256M */
#define PAL_WORKSPACE_MEM_BASE_ADDR     0x10000000
#elif defined CC_PLAT_JUNO
/* Juno platforms (AARCH64)  */
#define PAL_WORKSPACE_MEM_BASE_ADDR     0x8A0000000
#else
#error "unknown HW"
#endif
#define PAL_WORKSPACE_MEM_SIZE      0x1000000

/*! ----------------------------
        PUBLIC FUNCTIONS
--------------------------------*/

/**
 * @brief   Initializes contiguous memory pool required for CC_PalDmaContigBufferAllocate() and CC_PalDmaContigBufferFree(). Our
 * 	    example implementation is to mmap 0x30000000 and call to bpool(), for use of bget() in CC_PalDmaContigBufferAllocate(),
 *          and brel() in CC_PalDmaContigBufferFree().
 *
 * @return A non-zero value in case of failure.
 */
extern uint32_t CC_PalDmaInit(uint32_t  buffSize,    /*!< [in] Buffer size in Bytes. */
			      CCDmaAddr_t  physBuffAddr /*!< [in] Physical start address of the memory to map. */);

/**
 * @brief   free system resources created in CC_PalDmaInit()
 *
 *
 * @return void
 */
extern void CC_PalDmaTerminate(void);
#ifdef __cplusplus
}
#endif

#endif


