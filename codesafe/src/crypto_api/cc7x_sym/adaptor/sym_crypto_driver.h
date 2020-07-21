/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _SYM_CRYPTO_DRIVER_H
#define _SYM_CRYPTO_DRIVER_H

#include "cc_plat.h"
#include "dma_buffer.h"
#include "cc_hw_queue_defs.h"
#include "cc_crypto_ctx.h"

/******************************************************************************
 *                DEFINITIONS
 ******************************************************************************/

/******************************************************************************
 *                MACROS
 ******************************************************************************/

/******************************************************************************
 *                TYPE DEFINITIONS
 ******************************************************************************/
#ifndef ZERO_BLOCK_DEFINED
extern const uint32_t ZeroBlock[CC_AES_BLOCK_SIZE_WORDS];
#endif

/******************************************************************************
 *                FUNCTION PROTOTYPES
 ******************************************************************************/
/*!
 * Initializes sym. driver resources.
 *
 * \return int One of DX_SYM_* error codes defined in head of file.
 */
int SymDriverInit(void);

/*!
 * Delete sym. driver resources.
 *
 * \return int One of DX_SYM_* error codes defined in head of file.
 */
int SymDriverFini(void);

/*!
 * This function is called from the SW queue manager which passes the
 * related context. The function casts the context buffer and diverts
 * to the specific CC Init API according to the cipher algorithm that
 * associated in the given context. It is also prepare the necessary
 * firmware private context parameters that are require for the crypto
 * operation, for example, computation of the AES-MAC k1, k2, k3 values.
 * The API has no affect on the user data buffers.
 *
 * \param ctxAddr A pointer to the context buffer in SRAM.
 * \param pCtx A pointer to the AES context buffer in Host memory.
 * \param alg The algorithm of the operation.
 *
 * \return int One of DX_SYM_* error codes defined in head of file.
 */
int SymDriverDispatchInit(CCSramAddr_t ctxAddr, uint32_t *pCtx, enum drv_crypto_alg alg);

/*!
 * This function is called from the SW queue manager in order to process
 * a symmetric crypto operation on the user data buffers.
 *
 * \param ctxAddr A pointer to the context buffer in SRAM.
 * \param pCtx A pointer to the AES context buffer in Host memory.
 * \param pDmaInputBuffer A structure which represents the DMA input buffer.
 * \param pDmaOutputBuffer A structure which represents the DMA output buffer.
 * \param alg The algorithm of the operation.
 *
 * \return int One of DX_SYM_* error codes defined in head of file.
 */
int SymDriverDispatchProcess(CCSramAddr_t ctxAddr,
                             uint32_t *pCtx,
                             DmaBuffer_s *pDmaInputBuffer,
                             DmaBuffer_s *pDmaOutputBuffer,
                             enum drv_crypto_alg alg);

/*!
 * This function is called from the SW queue manager in order to complete
 * a crypto operation. The SW queue manager calls this API when the
 * "Process" bit "0x2" is set in the SW descriptor header. This function
 * may be invoked after "DispatchDriverProcess" or "DispatchDriverInit" with any
 * number of IN/OUT MLLI tables.
 *
 * \param ctxAddr A pointer to the context buffer in SRAM.
 * \param pCtx A pointer to the AES context buffer in Host memory.
 * \param pDmaInputBuffer A structure which represents the DMA input buffer.
 * \param pDmaOutputBuffer A structure which represents the DMA output buffer.
 * \param alg The algorithm of the operation.
 *
 * \return int One of DX_SYM_* error codes defined in head of file.
 */
int SymDriverDispatchFinalize(CCSramAddr_t ctxAddr,
                              uint32_t *pCtx,
                              DmaBuffer_s *pDmaInputBuffer,
                              DmaBuffer_s *pDmaOutputBuffer,
                              enum drv_crypto_alg alg);

#endif /*SEP_SYM_CRYPTO_DRIVER_H*/
