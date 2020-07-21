/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef __CC_PAL_LINUX_DRV_H__
#define __CC_PAL_LINUX_DRV_H__

#include "cc_pal_types.h"
#include "cc_pal_dma.h"
#include "cc_pal_dma_defs.h"


#define PAL_LINUX_CLASS_NAME  "cc_class_dev"
#define PAL_LINUX_DRV_NAME "cc_linux_driver"

/* minimun size of 256 to map user pages*/
#define PAL_MIN_MAP_BUFF_SIZE  0x100

/* Define enumartion for IOCTL */
#define PAL_LINUXL_IOC_MAGIC 	0x2D
#define PAL_LINUXL_IOC_MAP 		_IOWR(PAL_LINUXL_IOC_MAGIC, 1, int)
#define PAL_LINUXL_IOC_UNMAP 		_IOW(PAL_LINUXL_IOC_MAGIC, 2, int)
#define PAL_LINUXL_IOC_ALLOC 		_IOWR(PAL_LINUXL_IOC_MAGIC, 3, int)
#define PAL_LINUXL_IOC_FREE 		_IOW(PAL_LINUXL_IOC_MAGIC, 4, int)
#define PAL_LINUXL_IOC_MAX 		6

typedef struct {
	struct page **pPagesList;
	CCPalDmaBlockInfo_t *pDmaList;
}PalDrvCtx;

typedef struct {
	CCVirtAddr_t                usrBuffAddr;
	size_t                      usrBuffSize;
	CCPalDmaBufferDirection_t     copyDirection;
	size_t                      numOfBlocks;
	CCPalDmaBlockInfo_t           *pDmaBlockList;
	CC_PalDmaBufferHandle       *pDmaBuffHandle;
}PalDrvIoctlMap_t;



#endif /*__CC_PAL_LINUX_DRV_H__*/
