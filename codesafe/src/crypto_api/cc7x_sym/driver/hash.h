/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef  _HASH_H
#define  _HASH_H

#include "cc_plat.h"
#include "mlli.h"
#include "cc_crypto_ctx.h"
#include "dma_buffer.h"
#include "hash_defs.h"

/******************************************************************************
 *                DEFINITIONS
 ******************************************************************************/

/******************************************************************************
 *                MACROS
 ******************************************************************************/

/******************************************************************************
 *                TYPE DEFINITIONS
 ******************************************************************************/

/******************************************************************************
 *                FUNCTION PROTOTYPES
 ******************************************************************************/

/*!
 * Get Hash digest size in bytes.
 *
 * \param mode Hash mode
 * \param digestSize [out] A pointer to the digest size return value
 *
 * \return int One of DX_SYM_* error codes defined in cc_sym_error.h.
 */
int GetHashDigestSize(const enum drv_hash_mode mode, uint32_t *digestSize);

/*!
 * Get hardware digest size (HW specific) in bytes.
 *
 * \param mode Hash mode
 * \param hwDigestSize [out] A pointer to the digest size return value
 *
 * \return int One of DX_SYM_* error codes defined in cc_sym_error.h.
 */
int GetHashHwDigestSize(const enum drv_hash_mode mode, uint32_t *hwDigestSize);

/*!
 * Translate Hash mode to hardware specific Hash mode.
 *
 * \param mode Hash mode
 * \param hwMode [out] A pointer to the hash mode return value
 *
 * \return int One of DX_SYM_* error codes defined in cc_sym_error.h.
 */
int GetHashHwMode(const enum drv_hash_mode mode, uint32_t *hwMode);

/*!
 * Get Hash block size in bytes.
 *
 * \param mode Hash mode
 * \param blockSize [out] A pointer to the hash block size return value
 *
 * \return int One of DX_SYM_* error codes defined in cc_sym_error.h.
 */
int GetHashBlockSize(const enum drv_hash_mode mode, uint32_t *blockSize);

/*!
 * Loads the hash digest and hash length to the Hash HW machine.
 *
 * \param ctxAddr Hash context
 * \param paddingSelection enable/disable Hash block padding by the Hash machine,
 *      should be either HASH_PADDING_DISABLED or HASH_PADDING_ENABLED.
 *
 * \return int One of DX_SYM_* error codes defined in cc_sym_error.h.
 */
int LoadHashState(CCSramAddr_t ctxAddr,
                  enum HashConfig1Padding paddingSelection,
                  struct drv_ctx_hash * pHashCtx);

/*!
 * Writes the hash digest and hash length back to the Hash context.
 *
 * \param ctxAddr Hash context
 * \param pHashCtx Hash local context
 *
 * \return int One of DX_SYM_* error codes defined in cc_sym_error.h.
 */
int StoreHashState(CCSramAddr_t ctxAddr, struct drv_ctx_hash * pHashCtx);

/*!
 * This function is used to initialize the HASH machine to perform the
 * HASH operations. This should be the first function called.
 *
 * \param ctxAddr A pointer to the context buffer in SRAM.
 * \param pCtx A pointer to the HASH context buffer in local memory.
 * \return int One of DX_SYM_* error codes defined in dx_error.h.
 */
int InitHash(CCSramAddr_t ctxAddr, uint32_t *pCtx);

/*!
 * This function is used to process a block(s) of data on HASH machine.
 * It accepts an input data aligned to hash block size, any reminder which is not
 * aligned should be passed on calling to "FinalizeHash".
 *
 * \param ctxAddr A pointer to the HASH context buffer in SRAM.
 * \param pCtx A pointer to the HASH context buffer in local memory.
 * \param pDmaInputBuffer A structure which represents the DMA input buffer.
 * \param pDmaOutputBuffer A structure which represents the DMA output buffer.
 *
 * \return int One of DX_SYM_* error codes defined in cc_sym_error.h.
 */
int ProcessHash(CCSramAddr_t ctxAddr,
                uint32_t *pCtx,
                DmaBuffer_s *pDmaInputBuffer,
                DmaBuffer_s *pDmaOutputBuffer);

/*!
 * This function is used as finish operation of the HASH machine.
 * The function may either be called after "InitHash" or "ProcessHash".
 *
 * \param ctxAddr A pointer to the AES context buffer in SRAM.
 * \param pDmaInputBuffer A structure which represents the DMA input buffer.
 * \param pDmaOutputBuffer A structure which represents the DMA output buffer.
 *
 * \return int One of DX_SYM_* error codes defined in cc_sym_error.h.
 */
int FinalizeHash(CCSramAddr_t ctxAddr,
                 uint32_t *pCtx,
                 DmaBuffer_s *pDmaInputBuffer,
                 DmaBuffer_s *pDmaOutputBuffer);

#endif /*_HASH_H*/

