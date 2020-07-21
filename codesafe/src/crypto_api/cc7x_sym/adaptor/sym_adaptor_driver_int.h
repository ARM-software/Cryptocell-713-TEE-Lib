/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef  _SYM_ADAPTOR_DRIVER_INT_H
#define  _SYM_ADAPTOR_DRIVER_INT_H

#include "cc_crypto_ctx.h"

/******************************************************************************
 *                        	DEFINITIONS
 ******************************************************************************/
#define SINGLE_BLOCK_ENTRY 1

/******************************************************************************
 *                        	MACROS
 ******************************************************************************/
#define SET_DMA_BUFF(_pDmaBuff, _pData, _size, _dmaBufType, _axiNs) \
                do {\
                    _pDmaBuff->pData = _pData;\
                    _pDmaBuff->size = _size;\
                    _pDmaBuff->dmaBufType = _dmaBufType;\
                    _pDmaBuff->axiNs = _axiNs;\
                } while(0)

#define SET_DMA_BUFF_WITH_DLLI(pDmaBuff, physAddr, buffSize) \
                SET_DMA_BUFF(pDmaBuff, physAddr, buffSize, DMA_BUF_DLLI, AXI_SECURE)

#define SET_DMA_BUFF_WITH_NULL(pDmaBuff) \
                SET_DMA_BUFF(pDmaBuff, 0, 0, DMA_BUF_NULL, AXI_SECURE)

#define SET_DMA_BUFF_WITH_MLLI(pDmaBuff, physAddr, buffSize) \
                SET_DMA_BUFF(pDmaBuff, physAddr, buffSize, DMA_BUF_MLLI_IN_HOST, AXI_SECURE)

#define COPY_DMA_BUFF(dmaDest, dmaSrc) {\
                dmaDest.pData = dmaSrc.pData;\
                dmaDest.size = dmaSrc.size;\
                dmaDest.dmaBufType = dmaSrc.dmaBufType;\
                dmaDest.axiNs = dmaSrc.axiNs;\
}

/******************************************************************************
 *                          TYPES
 ******************************************************************************/
typedef struct lliInfo_t {
    uint32_t lliEntry[2];
} lliInfo_t;

typedef struct mlliTable_t{
    CCPalDmaBlockInfo_t mlliBlockInfo;
    lliInfo_t *pLliEntry;
} mlliTable_t;

typedef enum driverAdaptorDir_t {
    DRIVER_ADAPTOR_DIR_IN,
    DRIVER_ADAPTOR_DIR_OUT
} driverAdaptorDir_t;

/******************************************************************************
 *				            FUNCTION PROTOTYPES
 ******************************************************************************/
uint32_t SymDriverAdaptorCopyCtx(driverAdaptorDir_t dir,
                                 CCSramAddr_t sram_address,
                                 uint32_t *pCtx,
                                 enum drv_crypto_alg alg);

#endif /*_SYM_ADAPTOR_DRIVER_INT_H*/

