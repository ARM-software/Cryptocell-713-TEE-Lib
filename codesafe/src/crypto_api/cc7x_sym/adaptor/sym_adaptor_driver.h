/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef  _SYM_ADAPTOR_DRIVER_H
#define  _SYM_ADAPTOR_DRIVER_H

#include "mlli.h"
#include "cc_crypto_ctx.h"
#include "dma_buffer.h"

/******************************************************************************
 *                MACROS
 ******************************************************************************/
#define SPAD_GET_MAX_BLOCKS(size) ((size) / CC_DRV_ALG_MAX_BLOCK_SIZE)
#define SPAD_BLOCKS2BYTES(blocks) ((blocks) * CC_DRV_ALG_MAX_BLOCK_SIZE)
#define SPAD_BYTES2BLOCKS(bytes) ((bytes) / CC_DRV_ALG_MAX_BLOCK_SIZE)

/******************************************************************************
 *                TYPE DEFINITIONS
 ******************************************************************************/

typedef enum SepRangeType {
    SEP_NULL,
    SEP_SRAM,
    SEP_ICACHE,
    SEP_DCACHE,
} SepRangeType_e;

/******************************************************************************
 *                FUNCTION PROTOTYPES
 ******************************************************************************/

/*!
 * Allocate sym adaptor driver resources
 *
 * \param None
 *
 * \return 0 for success, otherwise failure
 */
int SymDriverAdaptorModuleInit(void);

/*!
 * Release sym adaptor driver resources
 *
 * \param None
 *
 * \return always success
 */
int SymDriverAdaptorModuleTerminate(void);

/*!
 * Initializes the caller context by invoking the symmetric dispatcher driver.
 * The caller context may resides in SRAM or DCACHE SEP areas.
 * This function flow is synchronous.
 *
 * \param pCtx
 * \param alg The algorithm of the operation.
 * \param mode of operation.
 * \return int One of DX_SYM_* error codes defined in cc_sym_error.h.
 */
int SymDriverAdaptorInit(uint32_t * pCtx, enum drv_crypto_alg alg, int mode);

/*!
 * Process a cryptographic data by invoking the symmetric dispatcher driver.
 * The invoker may request any amount of data aligned to the given algorithm
 * block size. It uses a scratch pad to copy (in cpu mode) the user
 * data from DCACHE/ICACHE to SRAM for processing. This function flow is
 * Synchronous.
 *
 * \param pCtx may resides in SRAM or DCACHE SeP areas
 * \param pDataIn The input data buffer. It may reside in SRAM, DCACHE or ICACHE SeP address range
 * \param pDataOut The output data buffer. It may reside in SRAM or DCACHE SeP address range
 * \param DataSize The data input size in octets
 *
 * \return int One of DX_SYM_* error codes defined in cc_sym_error.h.
 */
int SymDriverAdaptorProcess(uint32_t *pCtx,
                            void *pDataIn,
                            void *pDataOut,
                            size_t DataSize,
                            enum drv_crypto_alg alg);
/*!
 * Finalizing the cryptographic data by invoking the symmetric dispatcher driver.
 * It calls the `SymDriverDcacheAdaptorFinalize` function for processing by leaving
 * any reminder for the finalize operation.
 *
 * \param pCtx may resides in SRAM or DCACHE SeP areas
 * \param pDataIn The input data buffer. It may reside in SRAM, DCACHE or ICACHE SeP address range
 * \param pDataOut The output data buffer. It may reside in SRAM or DCACHE SeP address range
 * \param DataSize The data input size in octats
 *
 * \return int One of DX_SYM_* error codes defined in cc_sym_error.h.
 */
int SymDriverAdaptorFinalize(uint32_t *pCtx,
                             void *pDataIn,
                             void *pDataOut,
                             size_t DataSize,
                             enum drv_crypto_alg alg);

#endif /*SEP_SYM_ADAPTOR_DRIVER_H*/

