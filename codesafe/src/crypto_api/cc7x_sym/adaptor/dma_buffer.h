/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef __DMA_BUFFER_H__
#define __DMA_BUFFER_H__

#include <stdint.h>
#include "dma_buffer_plat.h"
#include "cc_plat.h"

/* Get the DmaMode_t to match DMA buffer type */
#define DMA_BUF_TYPE_TO_MODE(dmaBufType) \
        (((dmaBufType) == DMA_BUF_NULL) ? NO_DMA :       \
     ((dmaBufType) == DMA_BUF_SEP) ? DMA_SRAM :       \
     ((dmaBufType) == DMA_BUF_DLLI) ? DMA_DLLI : DMA_MLLI)

/* DMA buffer type */
typedef enum DmaBufType {
    DMA_BUF_NULL = 0,
    DMA_BUF_SEP,
    DMA_BUF_DLLI,
    DMA_BUF_MLLI_IN_SEP,
    DMA_BUF_MLLI_IN_HOST
} DmaBufType_t;

typedef struct DmaBuffer {
    DmaBufType_t dmaBufType;
    CCDmaAddr_t pData; /* A pointer to the data (DMA_SRAM/DLLI) or MLLI table (DMA_MLLI_*) */
    uint32_t size; /* The size of the data (DMA_SRAM/DLLI) or size of first MLLI table (DMA_MLLI_*) */
    uint8_t axiNs; /* AXI NS bit */
} DmaBuffer_s;

/*!
 * Parse user buffer information that may be smart-pointer (DMA object/buffer)
 * Return uniform DMA information
 *
 * \param dataPtr Pointer given by the user
 * \param dataSize Data size given by the user (relevant for non-smart-ptr)
 * \param pDmaType
 * \param pDmaAddr
 * \param pDmaSize
 * \param pDmaAxiNs The AXI Secure bit
 *
 * \return 0 on success, !0 if parameter are invalid (e.g., dataSize != dma object data size)
 */
int dataPtrToDma(uint8_t *dataPtr,
                 uint32_t dataSize,
                 DmaBufType_t *pDmaType,
                 uint32_t *pDmaAddr,
                 uint32_t *pDmaSize,
                 uint32_t *pDmaAxiNs);

#endif /*__DMA_BUFFER_H__*/
