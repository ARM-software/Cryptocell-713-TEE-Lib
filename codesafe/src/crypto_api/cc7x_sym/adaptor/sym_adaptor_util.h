/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef  _SYM_ADAPTOR_UTIL_H
#define  _SYM_ADAPTOR_UTIL_H

#include "dma_buffer.h"
#include "cc_pal_types.h"
#include "cc_pal_perf.h"
#include "cc_pal_dma.h"
#include "cc_pal_mem.h"
#include "cc_lli_defs.h"
#include "cc_lli_defs_int.h"
#include "cc_sym_error.h"
#include "cc_int_general_defs.h"
#include "sym_adaptor_driver_int.h"

/******************************************************************************
 *                        	DEFINITIONS
 ******************************************************************************/
#define INPLACE                             1
#define NOT_INPLACE                         0

#define MAX_DLLI_BLOCK_SIZE                 ((1<<DLLI_SIZE_BIT_SIZE)-1)
#define MAX_MLLI_ENTRY_SIZE                 (1<<LLI_SIZE_BIT_SIZE)

#define SYM_ADAPTOR_BUFFER_INDEX            0
#define SYM_ADAPTOR_BUFFER_NUM              1

#define SYM_ADAPTOR_SBRT_BUFFER_INDEX       SYM_ADAPTOR_BUFFER_INDEX + SYM_ADAPTOR_BUFFER_NUM

#ifdef CC_SB_IMG_INFO_LIST_SIZE
#define SYM_ADAPTOR_SBRT_BUFFER_NUM         CC_SB_IMG_INFO_LIST_SIZE
#else
#define SYM_ADAPTOR_SBRT_BUFFER_NUM         1
#endif
/******************************************************************************
 *                        	MACROS
 ******************************************************************************/

/******************************************************************************
 *                          TYPES
 ******************************************************************************/
typedef enum eDmaBuiltDir_t{
    DMA_BUILD_DIR_IN,
    DMA_BUILD_DIR_OUT,
    DMA_BUILD_DIR_MAX,
} eDmaBuiltDir_t;

typedef enum eDmaBuiltFlag_t{
    DMA_BUILT_FLAG_NONE = 0x0,
    DMA_BUILT_FLAG_BI_DIR = 0x1,
    DMA_BUILT_FLAG_INPUT_BUFF = 0x2,
    DMA_BUILT_FLAG_OUTPUT_BUFF = 0x4
} eDmaBuiltFlag_t;

/******************************************************************************
 *				            FUNCTION PROTOTYPES
 ******************************************************************************/

/**
 * This function de-allocates the fields that were dynamically allocated in allocDmaBuildBuffers
 *
 * @param dir           The direction indicating the buffer to clear
 */
void freeDmaBuildBuffers(eDmaBuiltDir_t dir);

/**
 * This function allocates some of internal fields of interDmaBuildBuffer_t
 *
 * @param dir               The direction indicating the buffer to clear
 * @return                  CC_RET_OK on success, CCSymRetCode_t value otherwise.
 */
uint32_t allocDmaBuildBuffers(eDmaBuiltDir_t dir);

/**
 * This function handles the un-mapping of two buffer, input and output.
 * This function is able to get pDataIn == pDataOut in which case, inplace mapping is performed.
 *
 * @param pDataIn           Input buffer to which to unmap.
 * @param pDataOut          Output buffer to which to unmap.
 * @param dataSize          Size of buffers. same size applies to both buffers.
 * @param pDmaBuffIn        Input DmaBuff structure
 * @param pDmaBuffOut       Output DmaBuff structure
 * @param dmaBuiltFlag      An input flag that indicates which mappings were perfomred during SymDriverAdaptorBuildDataPtrFromDma
 * @param isSm4Ofb          For SM4 OFB use const DIN - no dma buffer exists
 * @return                  0 on sucess.
 */
uint32_t SymDriverAdaptorBuildDataPtrFromDma(void* pDataIn,
                                             void* pDataOut,
                                             size_t dataSize,
                                             DmaBuffer_s *pDmaBuffIn,
                                             DmaBuffer_s *pDmaBuffOut,
                                             eDmaBuiltFlag_t dmaBuiltFlag,
                                             bool isSm4Ofb,
                                             uint32_t dmaBuildBufferIndex);

/**
 * This function handles the mapping of two buffer, input and output.
 * This function is able to get pDataIn == pDataOut in which case, inplace mapping is performed.
 *
 * @param pDataIn           Input buffer to map.
 * @param pDataOut          Output buffer to map.
 * @param dataSize          Size of buffers. same size applies to both buffers.
 * @param pDmaBuffIn        Input DmaBuff structure
 * @param pDmaBuffOut       Output DmaBuff structure
 * @param dmaBuiltFlag      An output flag that remembers which mappings were perfomred
 *                          to later be used by the SymDriverAdaptorBuildDataPtrFromDma
 * @param isSm4Ofb          For SM4 OFB use const DIN - no dma buffer exists
 * @return                  0 on sucess.
 */
uint32_t SymDriverAdaptorBuildDmaFromDataPtr(void* pDataIn,
                                             void* pDataOut,
                                             size_t dataSize,
                                             DmaBuffer_s *pDmaBuffIn,
                                             DmaBuffer_s *pDmaBuffOut,
                                             uint32_t *pDmaBuiltFlag,
                                             uint8_t isInPlace,
                                             bool isSm4Ofb,
                                             uint32_t dmaBuildBufferIndex);

#endif /*_SYM_ADAPTOR_UTIL_H*/

