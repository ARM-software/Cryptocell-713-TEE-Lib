/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */



/************* Include Files ****************/
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include "cc_pal_log.h"
#include <errno.h>
#include <string.h>
#include "cc_pal_types.h"
#include "cc_pal_log.h"
#include "cc_pal_memmap.h"
#include "cc_registers.h"
/************************ Defines ******************************/
static int mapCountImage = 0;
static int halFileImage = -1;

static int mapCount = 0;
static int halFileH = -1;

#define PAL_PAGE_SIZE       getpagesize()
#define PAL_PAGE_MASK       (~(PAL_PAGE_SIZE-1))

/************************ Enums ******************************/

/************************ Typedefs ******************************/

/************************ Global Data ******************************/

/************************ Private Functions ******************************/
static void PalMemMap(CCDmaAddr_t physicalAddress, uint32_t mapSize, uint32_t **ppVirtBuffAddr, int halFile)
{
    CCDmaAddr_t alignStartOffset = physicalAddress & PAL_PAGE_MASK;
    uint32_t alignSize = physicalAddress - alignStartOffset;

    *ppVirtBuffAddr = (uint32_t *) mmap(0,
            mapSize + alignSize,
            PROT_READ | PROT_WRITE,
            MAP_SHARED,
            halFile,
            alignStartOffset);

    if ((*ppVirtBuffAddr != NULL) && (*ppVirtBuffAddr != MAP_FAILED)) {
        *ppVirtBuffAddr = (uint32_t *)((uintptr_t)*ppVirtBuffAddr + alignSize);
    }
}

static void PalMemUnMap(uint32_t *pVirtBuffAddr, uint32_t mapSize)
{
    uint32_t *pAlignStartOffset = (uint32_t *)((uintptr_t)pVirtBuffAddr & PAL_PAGE_MASK);
    uint32_t alignSize = (uintptr_t)pVirtBuffAddr - (uintptr_t)pAlignStartOffset;

    munmap(pAlignStartOffset, mapSize + alignSize);
}

/************************ Public Functions ******************************/

/**
 * @brief This function purpose is to return the base virtual address that maps the
 *        base physical address
 *
 * @param[in] physicalAddress - Starts physical address of the I/O range to be mapped.
 * @param[in] mapSize - Number of bytes that were mapped
 * @param[out] ppVirtBuffAddr - Pointer to the base virtual address to which the physical pages were mapped
 *
 * @return Returns a non-zero value in case of failure
 */
uint32_t CC_PalMemMap(CCDmaAddr_t physicalAddress, uint32_t mapSize, uint32_t **ppVirtBuffAddr)
{
    /* Open device file if not already opened */
    if (halFileH == -1) { /* not opened */
        halFileH = open("/dev/mem", O_RDWR | O_SYNC);
        if (halFileH < 0) {
            CC_PAL_LOG_ERR("unable to open /dev/mem [%s]\n", strerror(errno));
            return 1;
        }

        (void) fcntl(halFileH, F_SETFD, FD_CLOEXEC);
    }

    PalMemMap(physicalAddress, mapSize, ppVirtBuffAddr, halFileH);
    if ((*ppVirtBuffAddr == NULL) || (*ppVirtBuffAddr == MAP_FAILED)) {
        CC_PAL_LOG_ERR("CC_PalMemMap physAddd[0x%08llx] size[%u] halFileH[%d] %s\n", physicalAddress, mapSize, halFileH, strerror(errno));
        return 2;
    }

    mapCount++;
    return 0;
}/* End of CC_PalMemMap */

uint32_t CC_PalMemMapImage(CCDmaAddr_t physicalAddress, uint32_t mapSize, uint32_t **ppVirtBuffAddr)
{
    /* Open device file if not already opened */
    if (halFileImage == -1) { /* not opened */
        halFileImage = open("/dev/cc_linux_driver", O_RDWR);
        if (halFileImage < 0) {
            CC_PAL_LOG_ERR("unable to open /dev/cc_linux_driver [%s]\n", strerror(errno));
            return 1;
        }
    }


    PalMemMap(physicalAddress, mapSize, ppVirtBuffAddr, halFileImage);
    if ((*ppVirtBuffAddr == NULL) || (*ppVirtBuffAddr == MAP_FAILED)) {
        CC_PAL_LOG_ERR("CC_PalMemMap physAddd[0x%08llx] size[%u] halFileH[%d] %s\n", physicalAddress, mapSize, halFileImage, strerror(errno));
        return 2;
    }

    mapCountImage++;
    return 0;
}/* End of CC_PalMemMap */

uint32_t CC_PalMemUnMapImage(uint32_t *pVirtBuffAddr,
	                 uint32_t mapSize)
{
    if (halFileImage < 0) {
        CC_PAL_LOG_ERR("Atempting to unmap while no FD is open\n");
        return 1;
    }

    PalMemUnMap(pVirtBuffAddr, mapSize);
    mapCountImage--;

    if (mapCountImage == 0) {
        close(halFileImage);
        halFileImage = -1;
    }

    return 0;
}/* End of CC_PalMemUnMap */

/**
 * @brief This function purpose is to Unmaps a specified address range previously mapped
 *        by CC_PalMemMap
 *
 *
 * @param[in] pVirtBuffAddr - Pointer to the base virtual address to which the physical
 *            pages were mapped
 * @param[in] mapSize - Number of bytes that were mapped
 *
 * @return Returns a non-zero value in case of failure
 */
uint32_t CC_PalMemUnMap(uint32_t *pVirtBuffAddr,
                     uint32_t mapSize)
{
    if (halFileH < 0) {
        CC_PAL_LOG_ERR("Atempting to unmap while no FD is open\n");
        return 1;
    }

    PalMemUnMap(pVirtBuffAddr, mapSize);
    mapCount--;

    if (mapCount == 0) {
        close(halFileH);
        halFileH = -1;
    }

    return 0;
}/* End of CC_PalMemUnMap */
