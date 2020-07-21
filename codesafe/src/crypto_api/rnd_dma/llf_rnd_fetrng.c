/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */
/************* Include Files ****************/
#include "cc_registers.h"
#include "cc_pal_mem.h"
#include "cc_rng_plat.h"
#include "cc_hal.h"
#include "cc_regs.h"
#include "cc_rnd_error.h"
#include "llf_rnd_hwdefs.h"
#include "llf_rnd.h"
#include "llf_rnd_error.h"
#include "cc_sram_map.h"
#include "cc_plat.h"
#include "llf_rnd_trng.h"
#include "cc_int_general_defs.h"
#ifndef CMPU_UTIL
#include "cc_pal_mutex.h"
#include "cc_pal_abort.h"
#ifdef CC_SUPPORT_FULL_PROJECT
#include "cc_util_pm.h"
#endif
#endif

#if !defined(CMPU_UTIL) && !defined(SC_TEST_MODE)
extern CC_PalMutex *pCCRndCryptoMutex;

#define MUTEX_LOCK_AND_RETURN_UPON_ERROR(pmutex) \
        if (CC_PalMutexLock(pmutex, CC_INFINITE) != CC_SUCCESS) { \
            CC_PalAbort("Fail to acquire mutex\n"); \
        }

#define MUTEX_UNLOCK(pmutex) \
        if (CC_PalMutexUnlock(pmutex) != CC_SUCCESS) { \
            CC_PalAbort("Fail to release mutex\n"); \
        }

#ifdef CC_SUPPORT_FULL_PROJECT
#define DECREASE_CC_COUNTER \
        if (CC_IS_IDLE != CC_SUCCESS) { \
            CC_PalAbort("Fail to decrease PM counter\n"); \
        }

#define INCREASE_CC_COUNTER \
        if (CC_IS_WAKE != CC_SUCCESS) { \
            CC_PalAbort("Fail to increase PM counter\n"); \
        }
#else
#define DECREASE_CC_COUNTER
#define INCREASE_CC_COUNTER
#endif

#else
#define MUTEX_LOCK_AND_RETURN_UPON_ERROR(mutex)
#define MUTEX_UNLOCK(mutex)
#define DECREASE_CC_COUNTER
#define INCREASE_CC_COUNTER
#endif


/*********************************** Enums ******************************/
/*********************************Typedefs ******************************/

/**************** Global Data to be read by RNG function ****************/

/* test variables */
#ifdef RND_TEST_TRNG_WITH_ESTIMATOR
uint32_t  gEntrSize[4];
#endif


static uint32_t LLF_RND_TRNG_RoscMaskToNum(uint32_t mask)
{
    return (mask == LLF_RND_HW_TRNG_ROSC3_BIT) ? LLF_RND_HW_TRNG_ROSC3_NUM :
            (mask == LLF_RND_HW_TRNG_ROSC2_BIT) ? LLF_RND_HW_TRNG_ROSC2_NUM :
                    (mask == LLF_RND_HW_TRNG_ROSC1_BIT) ? LLF_RND_HW_TRNG_ROSC1_NUM :
                            LLF_RND_HW_TRNG_ROSC0_NUM;
}

static void LLF_RND_TRNG_EnableRngSourceAndWatchdog(CCTrngParams_t *pTrngParams)
{
    uint32_t maxCycles;
    uint32_t ehrSamples = LLF_RND_HW_EHR_SAMPLES_ON_FE_MODE;

    /* Set watchdog threshold to maximal allowed time (in CPU cycles) */
    maxCycles = LLF_RND_CalcMaxTrngTime(ehrSamples, pTrngParams->SubSamplingRatio);
    CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG, RNG_WATCHDOG_VAL), maxCycles);

    /* enable the RND source */
    CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG, RND_SOURCE_ENABLE), LLF_RND_HW_RND_SRC_ENABLE_VAL);
}

static CCError_t LLF_RND_TRNG_ReadEhrData(uint32_t *pSourceOut, CCBool_t isFipsSupported)
{
    CCError_t error = CC_OK;
    uint32_t isr = 0;
    uint32_t ehr = 0;
    uint32_t i;

    /* wait RNG interrupt: isr signals error bits */
    error = LLF_RND_WaitRngInterrupt(&isr);
    if (error != CC_OK){
        return error;
    }

    error = LLF_RND_TRNG_REQUIRED_ROSCS_NOT_ALLOWED_ERROR;
    if (CC_REG_FLD_GET(0, RNG_ISR, EHR_VALID, isr)) {
        error = CC_OK;
    }
    if (CC_REG_FLD_GET(0, RNG_ISR, CRNGT_ERR, isr) && isFipsSupported) {
        /* CRNGT requirements for FIPS 140-2. Should not try the next ROSC in FIPS mode. */
        error = LLF_RND_CRNGT_TEST_FAIL_ERROR;
    }

    /* in case of AUTOCORR_ERR or RNG_WATCHDOG, keep the default error value. will try the next ROSC. */
    if (error == CC_OK) {
        for (i = 0; i < LLF_RND_HW_TRNG_EHR_WIDTH_IN_WORDS; i++)
        {
            ehr = CC_HAL_READ_REGISTER(CC_REG_OFFSET(RNG, EHR_DATA_0) + (i*sizeof(uint32_t)));
            /* verify that the EHR read didn’t return 0 value.
             * In case of 0 value was returned, the driver shall restart the entropy collection. */
            if (ehr == 0) {
                return LLF_RND_TRNG_EHR_DATA_ZERO_ERROR;
            }
            *(pSourceOut++) = ehr;
        }
        CC_HAL_READ_REGISTER(CC_REG_OFFSET(RNG, RNG_ISR));
    }

    return error;
}

static CCError_t LLF_RND_TRNG_ReadEhrDataFromRoscs(CCTrngState_t *pTrngState,
                                                   CCTrngParams_t *pTrngParams,
                                                   uint32_t *pRoscToStart,
                                                   uint32_t *pEhrBuffer,
                                                   CCBool_t  isFipsSupported)
{
    CCError_t  error = CC_OK;

    for (; *pRoscToStart < (LLF_RND_NUM_OF_ROSCS<<1); *pRoscToStart <<= 1) {
        /* If failed to get entropy from prev ROSC, Call StartTrng, with next ROSC */
        if (error != CC_OK) {
            error = LLF_RND_StartTrngHW(
                    pTrngState,
                    pTrngParams,
                    CC_FALSE,
                    pRoscToStart);
            if (error != CC_OK) {
                return error;
            }
        }
        /* Read EHR */
        error = LLF_RND_TRNG_ReadEhrData(pEhrBuffer, isFipsSupported);
        if (error == CC_OK) {
            return CC_OK;
        }
        /* CRNGT error is interesting only in FIPS mode since HW FE continue collecting bits after such error */
        if ((error == LLF_RND_CRNGT_TEST_FAIL_ERROR) && (isFipsSupported)) {
            /* LLF_RND_CRNGT_TEST_FAIL_ERROR is set only in FIPS mode. do not continue to the next rosc. */
            return error;
        }
    }
    return LLF_RND_TRNG_GENERATION_NOT_COMPLETED_ERROR;

}

CCError_t LLF_RND_StartTrngHW(
        CCTrngState_t  *pTrngState,
        CCTrngParams_t *pTrngParams,
        CCBool_t           isRestart,
        uint32_t         *roscsToStart_ptr)
{
    CCError_t error = CC_OK;
    uint32_t tmpSamplCnt = 0;
    uint32_t roscNum = 0;

    /* Check pointers */
    if ((pTrngState == NULL) ||
            (pTrngParams == NULL) ||
            (roscsToStart_ptr == NULL)) {
        return LLF_RND_TRNG_ILLEGAL_PTR_ERROR;
    }

    /* 1. If full restart, get semaphore and set initial ROSCs      */
    if (isRestart == CC_TRUE) {
        *roscsToStart_ptr = 1UL; /* set ROSC to 1 (fastest)  */
        pTrngState->LastTrngRosc = 0;
    }

    /* FE mode  */
    /* Get fastest allowed ROSC */
    error = LLF_RND_GetFastestRosc(
            pTrngParams,
            roscsToStart_ptr);
    if (error != CC_OK) {
        return error;
    }

    error = LLF_RND_GetRoscSampleCnt(*roscsToStart_ptr, pTrngParams);
    if (error != CC_OK) {
        return error;
    }

    roscNum = LLF_RND_TRNG_RoscMaskToNum(*roscsToStart_ptr);

    /* 2. Restart the TRNG and set parameters      		        */
    /* enable the HW RND clock   */
    CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG, RNG_CLK_ENABLE), LLF_RND_HW_RND_CLK_ENABLE_VAL);

    /* do software reset */
    CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG, RNG_SW_RESET), 0x1);
    /* in order to verify that the reset has completed the sample count need to be verified */
    do {
        /* enable the HW RND clock   */
        CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG, RNG_CLK_ENABLE), LLF_RND_HW_RND_CLK_ENABLE_VAL);

        /* set sampling ratio (rng_clocks) between consecutive bits */
        CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG, SAMPLE_CNT1), pTrngParams->SubSamplingRatio);

        /* read the sampling ratio  */
        tmpSamplCnt = CC_HAL_READ_REGISTER(CC_REG_OFFSET(RNG, SAMPLE_CNT1));

    } while (tmpSamplCnt != pTrngParams->SubSamplingRatio);


    /* disable the RND source for setting new parameters in HW */
    CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG, RND_SOURCE_ENABLE), LLF_RND_HW_RND_SRC_DISABLE_VAL);

    CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG, RNG_ICR), 0xFFFFFFFF);

    /* set interrupt mask */
    CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG, RNG_IMR), LLF_RNG_INT_MASK_ON_FETRNG_MODE);

    CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG, TRNG_CONFIG), roscNum);


    /* Debug Control register: set to 0 - no bypasses */
    CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG, TRNG_DEBUG_CONTROL), LLF_RND_HW_DEBUG_CONTROL_VALUE_ON_FE_MODE);

    LLF_RND_TRNG_EnableRngSourceAndWatchdog(pTrngParams);

    /* set indication about current started ROSCs */
    pTrngState->LastTrngRosc = *roscsToStart_ptr;

    return error;
}


CCError_t LLF_RND_GetTrngSource(
        CCTrngState_t  *pTrngState,        /*in/out*/
        CCTrngParams_t  *pTrngParams,     /*in/out*/
        uint32_t        **sourceOut_ptr_ptr,	/*out*/
        uint32_t         *sourceOutSize_ptr,    /*in/out*/
        uint32_t         *pTrngWorkBuff,      /*in*/
        CCBool_t       isFipsSupported)      /*in*/
{
    CCError_t error = 0;
    uint32_t  i = 0;
    uint32_t roscToStart = 0x1;
    uint32_t *ramAddr;

    /* Lock mutex, check fatal err, and increase cc counter*/
    MUTEX_LOCK_AND_RETURN_UPON_ERROR(pCCRndCryptoMutex);

    CC_IS_FATAL_ERR_ON(error);
    if (error == CC_TRUE) {
        error = LLF_RND_CC_FATAL_ERROR;
        goto EndUnlockMutex;
    }

    INCREASE_CC_COUNTER

    error = CC_OK;

    /* since CC_TRNG_WORK_BUFFER_SIZE_WORDS is external define, we check here the value contains the minimum bytes for entropy:
     * [CC_TRNG_WORK_BUFFER_SIZE_WORDS = CC_CONFIG_TRNG90B_ENTROPY_MIN_BYTES + CC_RND_TRNG_SRC_INNER_OFFSET_WORDS + 2 extra words]
     * here we make sure the size is sufficient for FE
     * the verification is used in development phase. */
    if (CC_TRNG_WORK_BUFFER_SIZE_WORDS < (2*LLF_RND_HW_TRNG_EHR_WIDTH_IN_WORDS + CC_RND_TRNG_SRC_INNER_OFFSET_WORDS)) {
        return LLF_RND_WORKSPACE_TOO_SMALL_ERROR;
    }


    /* Set source RAM address with offset 8 bytes from sourceOut address in
          order to remain empty bytes for CC operations */
    *sourceOut_ptr_ptr = pTrngWorkBuff;
    ramAddr = *sourceOut_ptr_ptr + CC_RND_TRNG_SRC_INNER_OFFSET_WORDS;
    /* init to 0 for FE mode */
    *sourceOutSize_ptr = 0;
        /* Full restart TRNG starting ROSC is  the fastest */
        error = LLF_RND_StartTrngHW(
                pTrngState,
                pTrngParams,
                CC_TRUE/*isRestart*/,
                &roscToStart);
        if (error != CC_OK) {
            goto End;
        }

    /* Collect 2*EHR bits of entropy */
    for (i = 0; i < LLF_RND_HW_SAMPLES_NUM_ON_FE_MODE; ++i) {
        error = LLF_RND_TRNG_ReadEhrDataFromRoscs(pTrngState,
                                                  pTrngParams,
                                                  &roscToStart,
                                                  ramAddr + (i*LLF_RND_HW_TRNG_EHR_WIDTH_IN_WORDS),
                                                  isFipsSupported);
        if (error == CC_OK) {
            /* Need to enable RND_SOURCE_ENABLE before next LLF_RND_TRNG_ReadEhrData */
            LLF_RND_TRNG_EnableRngSourceAndWatchdog(pTrngParams);
        } else {
            goto End;
        }
    }
    *sourceOutSize_ptr = LLF_RND_HW_SAMPLES_NUM_ON_FE_MODE * LLF_RND_HW_TRNG_EHR_WIDTH_IN_BYTES;

End:
    if (error != CC_OK) {
        CC_PalMemSetZero((uint8_t *)ramAddr, LLF_RND_HW_SAMPLES_NUM_ON_FE_MODE * LLF_RND_HW_TRNG_EHR_WIDTH_IN_BYTES);
    }

    /* turn the RNG off    */
    LLF_RND_TurnOffTrng();

    /* release mutex and decrease CC counter */
    DECREASE_CC_COUNTER

EndUnlockMutex:
    MUTEX_UNLOCK(pCCRndCryptoMutex);

    return error;
}/* END of LLF_RND_GetTrngSource */

CCError_t LLF_RND_RunTrngStartupTest(
        CCTrngState_t        *pTrngState,
        CCTrngParams_t       *pTrngParams,
        uint32_t                *pTrngWorkBuff)
{
    CCError_t error = CC_OK;
    CC_UNUSED_PARAM(pTrngState);
    CC_UNUSED_PARAM(pTrngParams);
    CC_UNUSED_PARAM(pTrngWorkBuff);

    return error;
}

