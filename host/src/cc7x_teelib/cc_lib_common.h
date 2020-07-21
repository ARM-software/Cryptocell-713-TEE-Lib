/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

/*!
@file
@brief This is an internal file which contains all the enums and definitions
       that are used for both SLIM and FULL CryptoCell Lib init and finish APIs.
*/

#ifndef __CC_LIB_COMMON_H__
#define __CC_LIB_COMMON_H__

#include "cc_hal.h"
#include "cc_registers.h"

#define CC_LIB_WAIT_ON_NVM_IDLE_BIT() 						\
	do { 											\
		uint32_t regVal; 								\
		do { 										\
			regVal = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, NVM_IS_IDLE)); \
			regVal = CC_REG_FLD_GET(0, NVM_IS_IDLE, VALUE, regVal); 		\
		}while( !regVal ); 								\
	}while(0)


#endif /*__CC_LIB_COMMON_H__*/
