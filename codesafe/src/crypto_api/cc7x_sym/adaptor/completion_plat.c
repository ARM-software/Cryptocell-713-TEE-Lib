/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */
#define CC_PAL_LOG_CUR_COMPONENT CC_LOG_MASK_COMPLETION
#include "cc_pal_types.h"
#include "cc_plat.h"
#include "cc_pal_mem.h"
#include "cc_pal_dma.h"
#include "cc_pal_abort.h"
#include "cc_sym_error.h"
#include "cc_pal_log.h"
#include "completion.h"
#include "hw_queue.h"
#include "cc_hal.h"
#include "cc_pal_interrupt_ctrl.h"
#include "cc_pal_perf.h"
#include "cc_registers.h"

/******************************************************************************
 *                TYPES
 ******************************************************************************/
/* dummy completion buffer for last DLLI descriptor */
typedef struct {
    CCVirtAddr_t *pBuffVirtAddr;
    CCPalDmaBlockInfo_t dmaBlockList;    //CCDmaAddr_t buffPhysAddr;
    CC_PalDmaBufferHandle dmaBuffHandle;
} DmaBuffAddress_t;

/******************************************************************************
 *                GLOBALS
 ******************************************************************************/
static DmaBuffAddress_t gCompletionDummyBuffer;

/******************************************************************************
 *            FUNCTIONS PROTOTYPES
 ******************************************************************************/
static void AddLastCompletionDesc(CCBool isPreempt);

/******************************************************************************
 *                STATIC FUNCTIONS
 ******************************************************************************/

/*!
 * This function adds a dummy completion HW descriptor to a HW queue in
 * order to later on signal an internal completion event.
 * The dummy HW completion descriptor is created by using the DMA bypass
 * mode with zero size DIN and DOUT data. A counter ID is always
 * used to setup the "Ack required" field in the HW descriptor.
 * \param isPreempt - enable descriptor preemption indication
 */
static void AddLastCompletionDesc(CCBool isPreempt)
{
    HwDesc_s desc;

    HW_DESC_INIT(&desc);

    HW_DESC_SET_DIN_CONST(&desc, 0, sizeof(uint32_t));

    /* set last indication for dummy AXI completion */
    HW_DESC_SET_DOUT_DLLI(&desc,
                          gCompletionDummyBuffer.dmaBlockList.blockPhysAddr,
                          gCompletionDummyBuffer.dmaBlockList.blockSize,
                          0);

    HW_DESC_SET_FLOW_MODE(&desc, BYPASS);

    if (isPreempt == CC_TRUE) {
        /* set the QUEUE_LAST_IND & DOUT_LAST_IND bits  */
        HW_DESC_SET_QUEUE_LAST_IND(&desc);
    } else {
        /* set only the DOUT_LAST_IND bit  */
        HW_DESC_SET_LAST_IND(&desc);
    }

    HW_QUEUE_POLL_QUEUE_UNTIL_FREE_SLOTS(1);

    HW_DESC_PUSH_TO_QUEUE(&desc);

}

/******************************************************************************
 *                PUBLIC FUNCTIONS
 ******************************************************************************/
/*!
 * This function waits for current descriptor sequence completion.
 * \param isPreempt - enable descriptor preemption indication
 */
void WaitForSequenceCompletionPlat(CCBool isPreempt)
{
    CCPalPerfData_t perfIdx = 0;

    InitCompletionPlat();

    /* Acknowledge completion to host */
    AddLastCompletionDesc(isPreempt);


    CC_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_HW_CMPLT);

    /* wait for interrupt */
    /* wait only for AXIM completion interrupt */
    CC_PalWaitInterruptComp(CC_HAL_IRQ_AXIM_COMPLETE, NULL);

    CC_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_HW_CMPLT);

    /* read AXI completion - verify number of completed write transactions is 1 */
    if (CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, AXIM_MON_COMP)) != 1) {
        CC_PalAbort("AXI completion counter incorrect.");
    }

    /* Check for AXIM errors */
    if (CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, AXIM_MON_ERR))) {
        CC_PalAbort("AXI monitor error.");
    }

    CC_PAL_LOG_INFO("Sequence completed\n");
}

/*!
 * This function initializes the completion counter event and the AXI MON completion .
 *
 */
void InitCompletionPlat(void)
{
    uint32_t regVal = 0;

    /* check if there is a need to configure the interrupts */
    regVal = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_RGF_IMR));
    if (CC_REG_FLD_GET(0, HOST_RGF_IMR, AXIM_COMP_INT_MASK, regVal) != 0) {

        /* unmask AXIM interrupts to poll this bit on IRR */
        CC_REG_FLD_SET(HOST_RGF, HOST_RGF_IMR, AXIM_COMP_INT_MASK, regVal, 0);
        CC_HalMaskInterrupt(regVal);

        /* Clear AXIM pending interrupts */
        regVal = 0;
        CC_REG_FLD_SET(HOST_RGF, HOST_RGF_ICR, AXIM_COMP_INT_CLEAR, regVal, 1);
        CC_HalClearInterrupt(regVal);

        /* clear on read AXIM_MON_COMP (counts last_ind) */
        regVal = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, AXIM_MON_COMP));
    }
}

/*!
 * This function allocates a reserved word for dummy completion descriptor.
 *
 * \return a non-zero value in case of failure
 */
int AllocCompletionPlatBuffer(void)
{
    uint32_t error;
    uint32_t numOfBlocks = 1;

    /* Allocates a DMA-contiguous buffer, and gets its virtual address */
    error = CC_PalDmaContigBufferAllocate(sizeof(uint32_t),
                                          (uint8_t **) &(gCompletionDummyBuffer.pBuffVirtAddr));
    if (error != 0) {
        return error;
    }
    /* Map the dummy buffer - no need to sync data between transactions */
    error = CC_PalDmaBufferMap((uint8_t *) gCompletionDummyBuffer.pBuffVirtAddr,
                               sizeof(uint32_t),
                               CC_PAL_DMA_DIR_BI_DIRECTION,
                               &numOfBlocks,
                               &gCompletionDummyBuffer.dmaBlockList,
                               &gCompletionDummyBuffer.dmaBuffHandle);
    return error;
}

/*!
 * This function free resources previously allocated by AllocCompletionPlatBuffer.
 */
void FreeCompletionPlatBuffer(void)
{
    uint32_t numOfBlocks = 1;
    /* Unap the dummy buffer - no need to sync data between transactions */
    CC_PalDmaBufferUnmap((uint8_t *) gCompletionDummyBuffer.pBuffVirtAddr,
                         sizeof(uint32_t),
                         CC_PAL_DMA_DIR_BI_DIRECTION,
                         numOfBlocks,
                         &gCompletionDummyBuffer.dmaBlockList,
                         gCompletionDummyBuffer.dmaBuffHandle);
    CC_PalDmaContigBufferFree(sizeof(uint32_t), (uint8_t *) gCompletionDummyBuffer.pBuffVirtAddr);
    return;
}

