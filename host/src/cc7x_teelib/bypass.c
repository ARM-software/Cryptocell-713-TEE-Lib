/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */
#define CC_PAL_LOG_CUR_COMPONENT CC_LOG_MASK_CC_SYM_DRIVER

#include "cc_pal_log.h"
#include "bypass.h"
#include "cc_hw_queue_defs.h"
#include "hw_queue.h"
#include "cc_sym_error.h"

/******************************************************************************
*				PRIVATE FUNCTIONS
******************************************************************************/

/*!
 * Copy data buffer indirectly using CC HW descriptors.
 *
 * \param inType DMA type of the source buffer.
 * \param inAddr Input address of the source buffer, must be word aligned.
 * \param inSize Size in octets of the source buffer, must be multiple of word.
 * \param inAxiNs The AXI bus secure mode of the source buffer.
 * \param outType DMA type of the source buffer.
 * \param outAddr Output address of the destination buffer, must be word aligned.
 * \param outSize Size in octets of the destination buffer, must be multiple of word.
 * \param outAxiNs The AXI bus secure mode of the destination buffer.
 */
static void DescBypass(
	DmaMode_t inType,
	CCDmaAddr_t  inAddr,
	uint32_t inSize,
	uint32_t inAxiNs,
	DmaMode_t outType,
	CCDmaAddr_t outAddr,
	uint32_t outSize,
	uint32_t outAxiNs )
{
	HwDesc_s desc;

	/* Execute BYPASS operation */
	HW_DESC_INIT(&desc);
	HW_DESC_SET_DIN_TYPE(&desc, inType, inAddr, inSize, inAxiNs);
	HW_DESC_SET_DOUT_TYPE(&desc, outType, outAddr, outSize, outAxiNs);
	HW_DESC_SET_FLOW_MODE(&desc, BYPASS);
	AddHWDescSequence(&desc);
}

/*!
 * Maps a given address DMA type to a BYPASS operation type.
 *
 * \param dmaType The "addr" DMA type.
 * \param addr The address points to the data buffer.
 *
 * \return Bypass_t BYPASS operation type.
 */
static Bypass_t GetBypassType(DmaBufType_t dmaType)
{

	switch (dmaType) {
	case DMA_BUF_DLLI:
		return BYPASS_DLLI;
	case DMA_BUF_SEP:
		/* [FIXME] enable this comment when IS_VALID_SRAM_ADDR macro will be fixed */
		/*if (IS_VALID_SRAM_ADDR(addr)) {
			return BYPASS_SRAM;
		}*/
		return BYPASS_SRAM;
	default:
		return BYPASS_MAX;
	}
}

/*!
 * Memory copy using HW engines
 *
 *  reserved [unused]
 *  pDmaInputBuffer [in] -A structure which represents the DMA input buffer.
 *  pDmaOutputBuffer [in/out] -A structure which represents the DMA output buffer.
 *
 * \return int One of DX_SYM_* error codes defined in cc_sym_error.h.
 */
int ProcessBypass(CCSramAddr_t *reserved, uint32_t *pCtx_reserved, DmaBuffer_s *pDmaInputBuffer, DmaBuffer_s *pDmaOutputBuffer)
{
	Bypass_t dmaTypeIn, dmaTypeOut;
	int drvRc = CC_RET_OK;

	CC_UNUSED_PARAM(reserved);  // remove compilation warning
	CC_UNUSED_PARAM(pCtx_reserved);

	dmaTypeIn = GetBypassType(pDmaInputBuffer->dmaBufType);
	dmaTypeOut = GetBypassType(pDmaOutputBuffer->dmaBufType);

	if ((dmaTypeIn == BYPASS_MAX) || (dmaTypeOut == BYPASS_MAX)) {
		CC_PAL_LOG_ERR("Invalid din/dout memory type\n");
		drvRc = CC_RET_INVARG;
		goto EndWithErr;
	}

	switch (dmaTypeIn) {
	case BYPASS_SRAM:
		switch (dmaTypeOut) {
		case BYPASS_DLLI:
			if (IS_ALIGNED(pDmaInputBuffer->pData, sizeof(uint32_t)) ||
			    IS_MULT(pDmaInputBuffer->size, sizeof(uint32_t))) {
				DescBypass(
					DMA_SRAM,
					pDmaInputBuffer->pData,
					pDmaInputBuffer->size,
					pDmaInputBuffer->axiNs,
					DMA_DLLI,
					pDmaOutputBuffer->pData,
					pDmaOutputBuffer->size,
					pDmaOutputBuffer->axiNs);
			} else {
				CC_PAL_LOG_ERR("Bad address or bad size. SRAM to DLLI copy -Input address %lx with %ul B\n",
					(long unsigned int)pDmaInputBuffer->pData, pDmaInputBuffer->size);
				drvRc = CC_RET_INVARG;
				goto EndWithErr;
			}
			break;
		default:
			CC_PAL_LOG_ERR("Invalid BYPASS mode\n");
			drvRc = CC_RET_UNSUPP_ALG_MODE;
			goto EndWithErr;
		}
		break;
	case BYPASS_DLLI:
		switch (dmaTypeOut) {
		case BYPASS_SRAM:
			if (IS_ALIGNED(pDmaInputBuffer->pData, sizeof(uint32_t)) ||
			    IS_MULT(pDmaInputBuffer->size, sizeof(uint32_t))) {
				DescBypass(
					DMA_DLLI,
					pDmaInputBuffer->pData,
					pDmaInputBuffer->size,
					pDmaInputBuffer->axiNs,
					DMA_SRAM,
					pDmaOutputBuffer->pData,
					pDmaOutputBuffer->size,
					pDmaOutputBuffer->axiNs);
			} else {
				CC_PAL_LOG_ERR("Bad address or bad size. SRAM to DLLI copy -Input address %lx with %ul B\n",
					(long unsigned int)pDmaInputBuffer->pData, pDmaInputBuffer->size);
				drvRc = CC_RET_INVARG;
				goto EndWithErr;
			}
			break;
		case BYPASS_DLLI:
			DescBypass(
				    DMA_BUF_TYPE_TO_MODE(pDmaInputBuffer->dmaBufType),
				    pDmaInputBuffer->pData,
				    pDmaInputBuffer->size,
				    pDmaInputBuffer->axiNs,
				    DMA_BUF_TYPE_TO_MODE(pDmaOutputBuffer->dmaBufType),
				    pDmaOutputBuffer->pData,
				    pDmaOutputBuffer->size,
				    pDmaOutputBuffer->axiNs);
			break;
		default:
			CC_PAL_LOG_ERR("Invalid BYPASS mode\n");
			drvRc = CC_RET_UNSUPP_ALG_MODE;
			goto EndWithErr;
		}
		break;
	default:
		CC_PAL_LOG_ERR("Invalid BYPASS mode\n");
		drvRc = CC_RET_UNSUPP_ALG_MODE;
		break;
	}

EndWithErr:
	return drvRc;
}

