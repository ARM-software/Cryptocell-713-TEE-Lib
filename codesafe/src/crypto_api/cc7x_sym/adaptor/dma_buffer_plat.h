/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef __DMA_BUFFER_PLAT_H__
#define __DMA_BUFFER_PLAT_H__

/* Host pointer is always "smart pointer" hence, no manipulation has
   to be made but compiling to an empty macro */
#define IS_SMART_PTR(ptr) (0)
#define PTR_TO_DMA_BUFFER(ptr) ((DmaBuffer_s *)(ptr))
#define DMA_BUFFER_TO_PTR(pDmaBuffer) ((void *)(pDmaBuffer))
#endif /*__DMA_BUFFER_PLAT_H__*/
