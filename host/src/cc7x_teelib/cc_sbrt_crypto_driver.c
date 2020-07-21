/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


/************* Include Files ****************/
#include "cc_pal_log.h"
#include "cc_hw_queue_defs.h"
#include "cc_crypto_ctx.h"
#include "cc_sym_error.h"
#include "cc_lli_defs.h"
#include "mlli.h"
#include "hw_queue.h"
#include "hash_defs.h"
#include "dma_buffer.h"
#include "cc_sbrt_crypto_driver.h"
#include "cc_sbrt_crypto_int_defs.h"

#define DIRECTION_IN    0
#define DIRECTION_OUT   1

static int SbrtSetBufferPtrAndSize(DmaBuffer_s *pDmaBuffer, DmaMode_t *pDmaMode, CCDmaAddr_t *pData, uint32_t *pDataInSize, uint8_t direction)
{
    int drvRc = CC_RET_OK;
    MLLIDirection_t dir = (direction == DIRECTION_IN ? MLLI_INPUT_TABLE :MLLI_OUTPUT_TABLE);
    if (pData == NULL) {
        CC_PAL_LOG_ERR("pData is NULL\n");
        return CC_RET_INVARG;
    }

    if (pDataInSize == NULL) {
        CC_PAL_LOG_ERR("pDataInSize is NULL\n");
        return CC_RET_INVARG;
    }

    *pDmaMode = DMA_BUF_TYPE_TO_MODE(pDmaBuffer->dmaBufType);

    switch (*pDmaMode) {
        case DMA_MLLI:
            *pData = MLLI_getFirstLLIPtr(dir);
            MLLI_loadTableToSRAM(pDmaBuffer->pData,
                                 pDmaBuffer->size,
                                 pDmaBuffer->axiNs,
                                 dir);
            /* data size should hold the number of LLIs */
            *pDataInSize = (pDmaBuffer->size) / LLI_ENTRY_BYTE_SIZE;
            break;
        case DMA_DLLI:
        case DMA_SRAM:
            *pData = pDmaBuffer->pData;
            /* set the data size */
            *pDataInSize = pDmaBuffer->size;
            break;
        case NO_DMA:
            *pData = 0;
            /* data size is meaningless in DMA-MLLI mode */
            *pDataInSize = 0;
            break;
        default:
            CC_PAL_LOG_ERR("Invalid DMA mode[%u]\n", *pDmaMode);
            drvRc = CC_RET_INVARG;
    }

    return drvRc;
}

CCError_t SbrtHashDrvInit(CCSramAddr_t ivAddr)
{
    CCError_t error = CC_OK;
    HwDesc_s desc;

    /* load hash digest */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_CIPHER_MODE(&desc, DRV_HASH_HW_SHA256);
    HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_HASH);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_STATE0);
    HW_DESC_SET_DIN_SRAM(&desc, ivAddr, CC_SBRT_IV_SIZE_IN_BYTES);
    AddHWDescSequence(&desc);

    HW_DESC_INIT(&desc);
    HW_DESC_SET_CIPHER_MODE(&desc, DRV_HASH_HW_SHA256);
    /* load hash current length */
    HW_DESC_SET_DIN_CONST(&desc, 0, CC_SBRT_HASH_SIZE_IN_BYTES);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_KEY0);
    HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_HASH);
    AddHWDescSequence(&desc);

    return error;
}

CCError_t SbrtHashDrvProcess(DmaBuffer_s *pDataInDmaBuff)
{
    CCError_t error = CC_OK;
    HwDesc_s desc;

    DmaMode_t inDmaMode = NO_DMA;
    CCDmaAddr_t inputDataAddr = 0;
    uint32_t dataInSize = 0;

    error = SbrtSetBufferPtrAndSize(pDataInDmaBuff, &inDmaMode, &inputDataAddr, &dataInSize, DIRECTION_IN);
    if (error != 0) {
        return error;
    }

    if (dataInSize > 0) {
        /* process input data */
        HW_DESC_INIT(&desc);
        HW_DESC_SET_DIN_TYPE(&desc, inDmaMode, inputDataAddr, dataInSize, pDataInDmaBuff->axiNs);
        HW_DESC_SET_FLOW_MODE(&desc, DIN_HASH);
        AddHWDescSequence(&desc);
    }

    return error;
}

CCError_t SbrtHashDrvFinish(CCSramAddr_t digestAddr)
{
    CCError_t error = CC_OK;
    HwDesc_s desc;

    /* use same address since to read the length.
     * The value itself is not needed, but we nned to call the setup descriptor */
    CCSramAddr_t lengthTempAddr = digestAddr;

    /* workaround: do-pad must be enabled only when writing current length to HW */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_CIPHER_MODE(&desc, DRV_HASH_HW_SHA256);
    HW_DESC_SET_CIPHER_CONFIG1(&desc, HASH_PADDING_ENABLED);
    HW_DESC_SET_CIPHER_DO(&desc, DO_PAD);
    HW_DESC_SET_FLOW_MODE(&desc, S_HASH_to_DOUT);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_WRITE_STATE1);
    HW_DESC_SET_DOUT_SRAM(&desc,
                          lengthTempAddr,
                          CC_SBRT_HASH_CURR_LENGTH_SIZE_IN_BYTES);
    AddHWDescSequence(&desc);

    /* get the hash digest result */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_CIPHER_MODE(&desc, DRV_HASH_HW_SHA256);
    HW_DESC_SET_FLOW_MODE(&desc, S_HASH_to_DOUT);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_WRITE_STATE0);
    HW_DESC_SET_CIPHER_CONFIG0(&desc, HASH_DIGEST_RESULT_LITTLE_ENDIAN);
    HW_DESC_SET_CIPHER_CONFIG1(&desc, HASH_PADDING_ENABLED);
    HW_DESC_SET_DOUT_SRAM(&desc,
                          digestAddr,
                          CC_SBRT_HASH_SIZE_IN_BYTES);
    AddHWDescSequence(&desc);

    return error;
}

CCError_t SbrtAesDrvInit(uint32_t key, CCSramAddr_t nonceAddr)
{
    HwDesc_s desc;

    /* load IV state descriptor */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_CIPHER_MODE(&desc, DRV_CIPHER_CTR);
    HW_DESC_SET_CIPHER_CONFIG0(&desc, DESC_DIRECTION_DECRYPT_DECRYPT);
    HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_AES);
    HW_DESC_SET_KEY_SIZE_AES(&desc, CC_SBRT_KEY_SIZE);
    HW_DESC_SET_DIN_SRAM(&desc, nonceAddr, CC_SBRT_NONCE_SIZE_IN_BYTES);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_STATE1);
    AddHWDescSequence(&desc);

    /* load key descriptor */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_CIPHER_MODE(&desc, DRV_CIPHER_CTR);
    HW_DESC_SET_CIPHER_CONFIG0(&desc, DESC_DIRECTION_DECRYPT_DECRYPT);
    HW_DESC_SET_KEY_SIZE_AES(&desc, CC_SBRT_KEY_SIZE);
    HW_DESC_SET_HW_CRYPTO_KEY(&desc, key);
    HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_AES);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_KEY0);
    AddHWDescSequence(&desc);

    return CC_OK;
}

CCError_t SbrtAesDrvProcess(uint32_t flow,
                            DmaBuffer_s *pDataInDmaBuff,
                            DmaBuffer_s *pDataOutDmaBuff)
{
    CCError_t error = CC_OK;
    HwDesc_s desc;

    DmaMode_t inDmaMode = NO_DMA;
    DmaMode_t outDmaMode = NO_DMA;
    CCDmaAddr_t inputDataAddr = 0;
    CCDmaAddr_t outputDataAddr = 0;
    uint32_t dataInSize = 0;
    uint32_t dataOutSize = 0;

    error = SbrtSetBufferPtrAndSize(pDataInDmaBuff, &inDmaMode, &inputDataAddr, &dataInSize, DIRECTION_IN);
    if (error != 0) {
        return error;
    }

    error = SbrtSetBufferPtrAndSize(pDataOutDmaBuff, &outDmaMode, &outputDataAddr, &dataOutSize, DIRECTION_OUT);
    if (error != 0) {
        return error;
    }

    /* Process input data */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_DIN_TYPE(&desc, inDmaMode, inputDataAddr, dataInSize, pDataInDmaBuff->axiNs);
    HW_DESC_SET_DOUT_TYPE(&desc, outDmaMode, outputDataAddr, dataOutSize, pDataOutDmaBuff->axiNs);
    HW_DESC_SET_FLOW_MODE(&desc, flow);
    AddHWDescSequence(&desc);

    return CC_OK;
}

CCError_t SbrtAesDrvFinish(void)
{
    /* nothing to do */

    return CC_OK;
}
