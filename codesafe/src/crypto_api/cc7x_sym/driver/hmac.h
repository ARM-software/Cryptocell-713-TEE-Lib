/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef  _HMAC_H
#define  _HMAC_H

#include "cc_plat.h"
#include "mlli.h"
#include "cc_crypto_ctx.h"
#include "dma_buffer.h"

/******************************************************************************
 *                DEFINITIONS
 ******************************************************************************/

/******************************************************************************
 *                MACROS
 ******************************************************************************/
/* the MAC key IPAD and OPAD bytes */
#define MAC_KEY_IPAD_BYTE 0x36
#define MAC_KEY_OPAD_BYTE 0x5C

/******************************************************************************
 *                TYPE DEFINITIONS
 ******************************************************************************/

/******************************************************************************
 *                FUNCTION PROTOTYPES
 ******************************************************************************/

/*!
 * This function is used to initialize the HMAC machine to perform the HMAC
 * operations. This should be the first function called.
 *
 * \param ctxAddr A pointer to the context buffer in SRAM.
 * \param pCtx A pointer to the context buffer in local memory.
 *
 * \return int One of DX_SYM_* error codes defined in cc_sym_error.h.
 */
int InitHmac(CCSramAddr_t ctxAddr, uint32_t *pCtx);

/********************************************************************************/
/********************************************************************************/
/*!! we do not implement "ProcessHmac" since it directly calls ProcessHash     */
/********************************************************************************/
/********************************************************************************/

/*!
 * This function is used as finish operation of the HMAC machine.
 * The function may be called after "InitHmac".
 *
 * \param ctxAddr A pointer to the AES context buffer in SRAM.
 * \param pDmaInputBuffer A structure which represents the DMA input buffer.
 * \param pDmaOutputBuffer A structure which represents the DMA output buffer.
 *
 * \return int One of DX_SYM_* error codes defined in cc_sym_error.h.
 */
int FinalizeHmac(CCSramAddr_t ctxAddr,
                 uint32_t *pCtx,
                 DmaBuffer_s *pDmaInputBuffer,
                 DmaBuffer_s *pDmaOutputBuffer);

#endif /*SEP_HMAC_H*/

