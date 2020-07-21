/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _CC_PAL_INTERRUPTCTRL_H
#define _CC_PAL_INTERRUPTCTRL_H

#include "cc_hal.h"

/*!
   @file
   @brief This file contains APIs that are used to handle CryptoCell interrupts.
  */

 /*!
   @ingroup pal_interrupt
   @{
   */

/*! PAL interrupt service routine (ISR). */
typedef void (*CCPalISR)(void);

/**
 * @brief The function initializes the interrupt handler for
 * CryptoCell interrupts.
 *
 * @param[in]
 *      pIsrFunction - ISR handler function
 *
 *
 * @return - \c CC_SUCCESS on success.
 * @return - \c CC_FAIL on failure.
 */
CCError_t CC_PalInitIrq(CCPalISR pIsrFunction);

/**
 * @brief The function removes the interrupt handler for
 * CryptoCell interrupts.
 *
 */
void CC_PalFinishIrq(void);

/**
 * @brief This function initializes wait for interrupt completion for
 * a specific interrupt type
 *
 * @param[in]
 *      irqType       IRQ type
 *
 * @param[out]
 *
 * @return - \c CC_SUCCESS on success.
 * @return - \c CC_FAIL on failure.
 */
CCError_t CC_PalInitWaitInterruptComp(CCHalIrq_t irqType);

/**
 * @brief This function stop wait for interrupt completion for
 * a specific interrupt type
 *
 * @param[in]
 *      irqType       IRQ type
 *
 * @param[out]
 *
 * @return - \c CC_SUCCESS on success.
 * @return - \c CC_FAIL on failure.
 */
CCError_t CC_PalFinishWaitInterruptComp(CCHalIrq_t irqType);

/*!
 * @brief       A function that is called to block on waiting interrupt.
 *
 * @param[in]
 *       irqType       The IRQ to wait on.
 *
 * @param[out]
 *       irqData       Optional parameter to receive from the notifying context.
 *
 * @return - \c CC_OK on success.
 * @return - \c CC_FAIL on failure.
 */
CCError_t CC_PalWaitInterruptComp(CCHalIrq_t irqType, uint32_t *irqData);

/*!
 * @brief       A function that is called to notify PAL on interrupts.
 *
 * @param[in]
 *        irqType       The IRQ type.
 *
 * @param[in]
 *        irrData       The interrupt data.
 *
 * @return - \c CC_OK on success.
 * @return - \c CC_FAIL on failure.
 */
CCError_t CC_PalInterruptNotify(CCHalIrq_t irqType, uint32_t irrData);

   /*!
   @}
   */
#endif
/* _CC_PAL_INTERRUPTCTRL_H */

