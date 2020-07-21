/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


/************* Include Files *************************************************/

#include "cc_pal_types.h"
#include "cc_pal_interrupt_ctrl.h"
#include "cc_regs.h"
#include "cc_registers.h"
#include "cc_hal.h"
#include "dx_reg_base_host.h"

#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>

/************************ Defines ********************************************/
#define SEM_MAX_DEPTH   1

/************************ Enums **********************************************/

/************************ Typedefs *******************************************/
/*! PAL message definition, */
typedef struct {
    uint32_t param; /*!< Parameter. */
    uint32_t error; /*!< Error. */
} CCPalMsg_t;

typedef struct CC_Completion_t {
    sem_t empty;
    sem_t full;
    CCPalMsg_t msg;
    bool valid;
} CC_Completion_t;

/************************ Extern *********************************************/

/************************ Global Data ****************************************/
pthread_t   palThreadId;
uint32_t    palThreadRc;
bool        palThreadExit = false;
bool        suspendIrqPolling = false;

CCPalISR    pIsr = NULL;

CC_Completion_t xCompletion[CC_HAL_IRQ_MAX];

/************************ Private Functions **********************************/

void *palIrqThread(void *params)
{
    CC_UNUSED_PARAM(params);

    while (!palThreadExit) {
        if (!suspendIrqPolling) {

            if (pIsr != NULL) {
                pIsr();
            }
        }
        usleep(100);    // wait 100 milisecond
    }
    palThreadRc = 0;
    pthread_exit(&palThreadRc);
}

/************************ Public Functions ***********************************/
#ifndef CC_CONFIG_INTERRUPT_POLLING
CCError_t CC_PalInitIrq(CCPalISR pIsrFunction)
{
    uint32_t rc;

    palThreadExit = false;

    if (pIsrFunction == NULL)
    {
        return CC_FAIL;
    }

    rc = pthread_create(&palThreadId, NULL, palIrqThread, NULL);
    if (rc != 0) {
        return rc;
    }

    pIsr = pIsrFunction;

    // join will be in the termination function
    return CC_SUCCESS;
}

void CC_PalFinishIrq(void)
{
    void **threadRet = NULL;

    palThreadExit = true; // The fips thread checks this flag and act accordingly
    pthread_join(palThreadId, threadRet);
}

CCError_t CC_PalInitWaitInterruptComp(CCHalIrq_t irqType)
{
    if ((irqType < CC_HAL_IRQ_MAX) && (xCompletion[irqType].valid == false)) {
        xCompletion[irqType].msg.param = 0;
        xCompletion[irqType].msg.error = CC_OK;
        xCompletion[irqType].valid = true;
        sem_init(&xCompletion[irqType].empty, 0, SEM_MAX_DEPTH);
        sem_init(&xCompletion[irqType].full, 0, 0);
    } else {
        return CC_FAIL;
    }

    return CC_OK;
}

CCError_t CC_PalFinishWaitInterruptComp(CCHalIrq_t irqType)
{
    if ((irqType < CC_HAL_IRQ_MAX) && (xCompletion[irqType].valid == true)) {
        xCompletion[irqType].valid = false;
        sem_destroy(&xCompletion[irqType].empty);
        sem_destroy(&xCompletion[irqType].full);
    } else {
        return CC_FAIL;
    }

    return CC_OK;
}

CCError_t CC_PalWaitInterruptComp(CCHalIrq_t irqType, uint32_t *irqData)
{
    if ((irqType >= CC_HAL_IRQ_MAX) || (xCompletion[irqType].valid == false)) {
        return CC_FAIL;
    }

    sem_wait(&xCompletion[irqType].full);
    sem_post(&xCompletion[irqType].empty);

    if ( xCompletion[irqType].msg.error != CC_OK) {
        return CC_FAIL;
    }

    if (irqData != NULL) {
        *irqData = xCompletion[irqType].msg.param;
    }

    return CC_OK;
}

CCError_t CC_PalInterruptNotify(CCHalIrq_t irqType, uint32_t irrData)
{
    uint32_t error = CC_OK;

    if ((irqType >= CC_HAL_IRQ_MAX) || (xCompletion[irqType].valid == false)) {
        return CC_FAIL;
    }

    if ((irqType == CC_HAL_IRQ_AXIM_COMPLETE) &&
            (CC_REG_FLD_GET(0, HOST_RGF_IRR, AXI_ERR_INT, irrData) == CC_TRUE)) {
        error = CC_FAIL;
    }

    sem_wait(&xCompletion[irqType].empty);
    xCompletion[irqType].msg.error = error;
    xCompletion[irqType].msg.param = irrData;
    sem_post(&xCompletion[irqType].full);

    return CC_OK;
}

#else

static CCError_t CC_PalInterruptHandle(CCHalIrq_t irqType, uint32_t irrData, uint32_t *irqData)
{
    if (irqType >= CC_HAL_IRQ_MAX){
        return CC_FAIL;
    }

    if (irqType == CC_HAL_IRQ_AXIM_COMPLETE) {
        if (irqData != NULL) {
            *irqData = irrData;
        }

        /* test for AXI error */
        if (CC_REG_FLD_GET(0, HOST_RGF_IRR, AXI_ERR_INT, irrData) == CC_TRUE) {
            /* clearing bus error */
            CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_RGF_ICR),
                                  CC_REG_BIT_MASK(HOST_RGF_ICR, AXI_ERR_CLEAR));
            return CC_FAIL;
        }

        /* clear interrupts */
        CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_RGF_ICR),
                CC_REG_BIT_MASK(HOST_RGF, IRR_AXIM_COMP_INT));

    }

    if (irqType == CC_HAL_IRQ_RNG) {
        /* clear interrupt value */
        if (irqData != NULL) {
            *irqData = CC_HAL_READ_REGISTER(CC_REG_OFFSET(RNG, RNG_ISR));
        }

        CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG, RNG_ICR), CC_HAL_ALL_BITS);

        /* clear interrupts */
        CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_RGF_ICR),
                CC_REG_BIT_MASK(HOST_RGF, IRR_RNG_INT));
    }

    return CC_OK;
}

CCError_t CC_PalInitIrq(CCPalISR pIsrFunction)
{
    CC_UNUSED_PARAM(pIsrFunction);


    // join will be in the termination function
    return CC_SUCCESS;
}

void CC_PalFinishIrq(void)
{
    return;
}

CCError_t CC_PalInitWaitInterruptComp(CCHalIrq_t irqType)
{
    CC_UNUSED_PARAM(irqType);

    return CC_OK;
}

CCError_t CC_PalFinishWaitInterruptComp(CCHalIrq_t irqType)
{
    CC_UNUSED_PARAM(irqType);

    return CC_OK;
}

CCError_t CC_PalWaitInterruptComp(CCHalIrq_t irqType, uint32_t *irqData)
{
    uint32_t irrData = 0;
    uint32_t mask;

    if (irqType == CC_HAL_IRQ_AXIM_COMPLETE) {
        mask =  CC_REG_BIT_MASK(HOST_RGF, IRR_AXIM_COMP_INT);
    } else if (irqType == CC_HAL_IRQ_RNG) {
        mask =  CC_REG_BIT_MASK(HOST_RGF, IRR_RNG_INT);
    } else {
        return CC_FAIL;
    }

    do {
        irrData = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_RGF_IRR));
    } while ((irrData & mask) == 0);

    return CC_PalInterruptHandle(irqType, irrData, irqData);;
}

CCError_t CC_PalInterruptNotify(CCHalIrq_t irqType, uint32_t irrData)
{
    CC_UNUSED_PARAM(irqType);
    CC_UNUSED_PARAM(irrData);

    return CC_OK;
}
#endif /* CC_CONFIG_INTERRUPT_POLLING */

