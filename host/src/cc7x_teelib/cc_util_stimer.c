/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


/************* Include Files ****************/
#include "cc_pal_types.h"
#include "cc_pal_mem.h"
#include "cc_util.h"
#include "cc_util_int_defs.h"
#include "cc_secure_clk_defs.h"
#include "cc_util_stimer.h"
#include "cc_hal_plat.h"
#include "cc_regs.h"
#include "cc_pal_mutex.h"
#include "cc_pal_abort.h"
#include "cc_fips_defs.h"

static uint64_t grayDecode(uint64_t gray)
{
    uint64_t bin = gray;
    bin ^= (bin >> 32);
    bin ^= (bin >> 16);
    bin ^= (bin >> 8);
    bin ^= (bin >> 4);
    bin ^= (bin >> 2);
    bin ^= (bin >> 1);

    return bin;
}

extern CC_PalMutex CCSymCryptoMutex;


CCError_t CC_UtilGetTimeStamp(CCUtilTimeStamp_t *pTimeStamp){

        CCError_t retCode = CC_OK;
	CCUtilCntr_t timeCntr;

	/* Check input variables */
	if (pTimeStamp == NULL) {
		return CC_ILLEGAL_RESOURCE_VAL_ERROR;
	}

        CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

        /* lock mutex before taking time stamp */
        retCode = CC_PalMutexLock(&CCSymCryptoMutex, CC_INFINITE);
        if (retCode != CC_OK) {
                CC_PalAbort("Fail to acquire mutex\n");
        }

        timeCntr.lsbLowResTimer = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF,HOST_LOW_RES_SECURE_TIMER_0));
        timeCntr.msbLowResTimer = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF,HOST_LOW_RES_SECURE_TIMER_1));
        CC_PalMemCopy((uint8_t*)pTimeStamp, (uint8_t*)&timeCntr, STIMER_COUNTER_BYTE_SIZE);
        *pTimeStamp = grayDecode(*pTimeStamp);
        CC_PAL_LOG_DEBUG("	timeStamp = %lli\n", *pTimeStamp);

        /* free mutex */
        if(CC_PalMutexUnlock(&CCSymCryptoMutex) != CC_OK) {
                CC_PalAbort("Fail to release mutex\n");
        }

        return retCode;
}


int64_t CC_UtilCmpTimeStamp(CCUtilTimeStamp_t timeStamp1, CCUtilTimeStamp_t timeStamp2) {

	int64_t diff;

        diff = CONVERT_CLK_TO_NSEC((uint64_t)(timeStamp2 - timeStamp1), EXTERNAL_SLOW_OSCILLATOR_HZ);

        return diff;
}


void CC_UtilResetLowResTimer(void)
{
        CCUtilCntr_t preTimeCntr, postTimeCntr;
        CCUtilTimeStamp_t preTimeStamp=0, postTimeStamp=0xffffffffff;

        /* Reset only the low resolution secure timer:
           Since the time of the reset is dependent on the external clock (which is unkown...).
           We sample the signal before and after the reset, and wait while (post>=pre). */

        preTimeCntr.lsbLowResTimer = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF,HOST_LOW_RES_SECURE_TIMER_0));
        preTimeCntr.msbLowResTimer = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF,HOST_LOW_RES_SECURE_TIMER_1));
        CC_PalMemCopy((uint8_t*)&preTimeStamp, (uint8_t*)&preTimeCntr, STIMER_COUNTER_BYTE_SIZE);
        preTimeStamp = grayDecode(preTimeStamp);

        CC_PAL_LOG_DEBUG("\n Reset Low resolution Secure Timer \n");
        CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(HOST_RGF,HOST_LOW_RES_SECURE_TIMER_RST), 0);

        while (postTimeStamp >= preTimeStamp){
                postTimeCntr.lsbLowResTimer = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF,HOST_LOW_RES_SECURE_TIMER_0));
                postTimeCntr.msbLowResTimer = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF,HOST_LOW_RES_SECURE_TIMER_1));
                CC_PalMemCopy((uint8_t*)&postTimeStamp, (uint8_t*)&postTimeCntr, STIMER_COUNTER_BYTE_SIZE);
                postTimeStamp = grayDecode(postTimeStamp);
        }

        return;
}
