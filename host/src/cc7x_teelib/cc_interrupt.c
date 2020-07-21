/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */
#include "cc_regs.h"
#include "cc_hal_plat.h"
#include "cc_pal_types.h"
#include "cc_pal_log.h"
#include "cc_cpp.h"
#include "cc_pal_interrupt_ctrl.h"
#ifdef CC_SUPPORT_FIPS
#include "cc_fips.h"
#endif
/******************************************************************************
*               DEFINITIONS
******************************************************************************/
#define CC_CPP_MASK         CC_REG_BIT_MASK(HOST_RGF, IRR_REE_KS_OPERATION_INDICATION)
#define CC_AXIM_MASK        CC_REG_BIT_MASK(HOST_RGF, IRR_AXIM_COMP_INT)
#define CC_AXI_ERR_MASK     CC_REG_BIT_MASK(HOST_RGF, IRR_AXI_ERR_INT)
#define CC_RNG_MASK         CC_REG_BIT_MASK(HOST_RGF, IRR_RNG_INT)

#ifdef CC_SUPPORT_FIPS
#define CC_GPR0_MASK        CC_REG_BIT_MASK(HOST_RGF, IRR_GPR0_INT)
#endif

/******************************************************************************
*               EXTERNS
******************************************************************************/
extern void CC_CppEventHandler(void);

/******************************************************************************
*               FUNCTIONS
******************************************************************************/
/*!
 * This function is part of the cc7x tee driver.
 * This function is meant to be called from ISR or executed in a separate thread in a loop.
 * When working with polling mode, the AXIM_COMP and RNG_INT interrupts will be handled by the PAL context
 * CPP & GPR0 interrupts SHOULD be handled by this function (in a separate thread or ISR).
 */
void CC_InterruptHandler(void)
{
    uint32_t irrValue = 0;
    uint32_t imrValue = 0;
    uint32_t icrValue = 0;
    uint32_t rngValue = 0;

    irrValue = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_RGF_IRR));
    imrValue = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_RGF_IMR));

    if (irrValue & (~imrValue)) {

        /*
         * In this product we are not using other interrupt bits other than:
         *      REE_KS_OPERATION_INDICATION
         *      AXIM_COMP_INT
         *      AXI_ERR
         *      GPR0
         *      RNG_INT
         */
        if (irrValue & CC_CPP_MASK) {
            icrValue |= CC_CPP_MASK;
            CC_CppEventHandler();
        }

#ifdef CC_SUPPORT_FIPS
        if (irrValue & CC_GPR0_MASK) {
            icrValue |= CC_GPR0_MASK;
            CC_FipsIrqHandle();
        }
#endif


        if (irrValue & CC_AXI_ERR_MASK) {
            icrValue |= CC_AXI_ERR_MASK;
        }

        if (irrValue & CC_AXIM_MASK) {
            icrValue |= CC_AXIM_MASK;

            /* need to clear interrupt before interrupt notify */
            CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_RGF_ICR), icrValue);
            icrValue = 0;

            CC_PalInterruptNotify(CC_HAL_IRQ_AXIM_COMPLETE, irrValue);
        }

        if (irrValue & CC_RNG_MASK) {
            icrValue |= CC_RNG_MASK;

            /* for RNG - use RNG ISR value */
            rngValue = CC_HAL_READ_REGISTER(CC_REG_OFFSET(RNG, RNG_ISR));

            /* clear RNG IC */
            CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG, RNG_ICR), CC_HAL_ALL_BITS);

            /* need to clear interrupt before interrupt notify */
            CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_RGF_ICR), icrValue);
            icrValue = 0;

            CC_PalInterruptNotify(CC_HAL_IRQ_RNG, rngValue);
        }

        if (icrValue != 0) {
            CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_RGF_ICR), icrValue);
        }
    }
}

