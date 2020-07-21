/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


#ifndef _BSV_SBRT_CRYPTO_DRIVER_H
#define _BSV_SBRT_CRYPTO_DRIVER_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "dma_buffer.h"
#include "cc_sbrt_crypto_defs.h"

/*----------------------------
      PUBLIC FUNCTIONS
-----------------------------------*/
/**
 * Initialize the hash engine towards SHA256 operation
 * @note It is assumed the engine is protected by mutex
 *
 * @param ivAddr        initial vector to load
 *
 * @return              0 on sucess.
 */
CCError_t SbrtHashDrvInit(CCSramAddr_t ivAddr);

/**
 * Process a chuck of data
 * @note It is assumed the engine is protected by mutex
 *
 * @param pDataInDmaBuff Dmabuff to process
 *
 * @return              0 on sucess.
 */
CCError_t SbrtHashDrvProcess(DmaBuffer_s *pDataInDmaBuff);

/**
 * Finish the hash operation and load the results into digestAddr sram offset
 * @note It is assumed the engine is protected by mutex
 *
 * @param digestAddr    sram offset to load hash result to.
 *
 * @return              0 on sucess.
 */
CCError_t SbrtHashDrvFinish(CCSramAddr_t digestAddr);

/**
 * Initialize the aes engine towards AES-CTR operation with one of two keys, Kce or Kceicv.
 * @note It is assumed the engine is protected by mutex
 *
 * @param key           Key to use. as defined in cc_hw_queue_defs.h
 * @param nonceAddr     Sram addres of nonce to use for aes operation.
 *
 * @return              0 on sucess.
 */
CCError_t SbrtAesDrvInit(uint32_t key, CCSramAddr_t nonceAddr);

/**
 * processes a chuck of data.
 * @note It is assumed the engine is protected by mutex
 *
 * @param flow              AES_and_HASH or AES_to_HASH_and_DOUT. as defined in cc_hw_queue_defs.h
 * @param pDataInDmaBuff    Input buffer
 * @param pDataOutDmaBuff   Output buffer
 *
 * @return              0 on sucess.
 */
CCError_t SbrtAesDrvProcess(uint32_t flow,
                            DmaBuffer_s *pDataInDmaBuff,
                            DmaBuffer_s *pDataOutDmaBuff);

/**
 * Finish the aes operation
 * @note It is assumed the engine is protected by mutex
 *
 * @return              0 on sucess.
 */
CCError_t SbrtAesDrvFinish(void);

#ifdef __cplusplus
}
#endif

#endif /* _BSV_SBRT_CRYPTO_DRIVER_H */

/**
@}
 */

