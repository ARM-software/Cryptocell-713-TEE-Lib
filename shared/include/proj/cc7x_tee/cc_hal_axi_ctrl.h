/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


#ifndef __CC_HAL_AXI_H__
#define __CC_HAL_AXI_H__


/*!
@file
@brief This file contains HAL AXI configuration definitions and APIs.
*/

#include <stdint.h>
#include <stdio.h>

#include "cc_pal_types_plat.h"
#include "cc_axi_ctrl.h"

/*!
 * @brief   This function is called by CC_LibInit and is used for initializing the ARM TrustZone CryptoCell TEE cache settings registers.
            This function enables the user to change the default values of the ACE configuration for the Secure AXI transactions and the
            AXI master configuration for DMA.
            The existing implementation sets the registers to the values in pAxiFields.
            pAxiFields should changed by the user (it is an input to CC_LibInit).

  @return   CC_OK on success.
  @return   CCError_t error code.
*/
CCError_t CC_HalSetCacheParams(CCAxiFields_t  *pAxiFields /* out */);

/*!
 * @brief   This function is used for getting the cache parameters
            The existing implementation sets the values of the cache parameters to pAxiFields.

  @return   CC_OK on success.
  @return   CCError_t error code.
*/
CCError_t CC_HalGetCacheParams(CCAxiFields_t  *pAxiFields /* in */);

#endif /* __CC_HAL_AXI_H__ */

