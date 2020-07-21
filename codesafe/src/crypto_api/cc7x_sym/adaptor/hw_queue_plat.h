/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef  HW_QUEUE_PLAT_H
#define  HW_QUEUE_PLAT_H

#include "cc_hal.h"

/******************************************************************************
 *				MACROS
 ******************************************************************************/
#define DEFALUT_AXI_SECURITY_MODE AXI_SECURE		/* NS bit */

/******************************************************************************
 *				FUNCTION PROTOTYPES
 ******************************************************************************/

/*!
 * This function sets the DIN field of a HW descriptors to DLLI mode.
 * The AXI and NS bits are set, hard coded to zero. this asiengment is
 * for TEE only.
 *
 *
 * \param pDesc pointer HW descriptor struct
 * \param dinAdr DIN address
 * \param dinSize Data size in bytes
 */
#define HW_DESC_SET_STATE_DIN_PARAM(pDesc, dinAdr, dinSize)		\
	do {		                                                \
		HW_DESC_SET_DIN_SRAM(pDesc, dinAdr, dinSize);			\
	} while (0)

#define HW_DESC_SET_STATE_DOUT_PARAM(pDesc, doutAdr, doutSize)	\
	do {		                                                \
		HW_DESC_SET_DOUT_SRAM(pDesc, doutAdr, doutSize);		\
	} while (0)

#endif /*HW_QUEUE_PLAT_H*/
