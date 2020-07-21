/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef  SEP_BYPASS_H
#define  SEP_BYPASS_H

#include "cc_crypto_ctx.h"
#include "dma_buffer.h"

/******************************************************************************
*				TYPE DEFINITIONS
******************************************************************************/
typedef enum BypassType {
	BYPASS_SRAM	= 0,
	BYPASS_DLLI	= 1,
	BYPASS_MLLI	= 2,
	BYPASS_MAX	= INT32_MAX
} Bypass_t;

/******************************************************************************
*				FUNCTION PROTOTYPES
******************************************************************************/

/*!
 * Memory copy using HW engines
 *
 *  reserved [unused]
 *  pDmaInputBuffer [in] -A structure which represents the DMA input buffer.
 *  pDmaOutputBuffer [in/out] -A structure which represents the DMA output buffer.
 *
 * \return int One of DX_SYM_* error codes defined in cc_sym_error.h.
 */
int ProcessBypass(uint32_t *reserved, uint32_t *pCtx_reserved, DmaBuffer_s *pDmaInputBuffer, DmaBuffer_s *pDmaOutputBuffer);

#endif /*BYPASS_H*/

