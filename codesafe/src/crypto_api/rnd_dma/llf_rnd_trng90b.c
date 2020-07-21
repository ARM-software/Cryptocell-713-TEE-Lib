/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */
/************* Include Files ****************/
#include "cc_registers.h"
#include "cc_pal_mem.h"
#include "cc_plat.h"
#include "cc_hal.h"
#include "cc_regs.h"
#include "cc_rnd_error.h"
#include "llf_rnd_hwdefs.h"
#include "llf_rnd.h"
#include "llf_rnd_error.h"
#include "llf_rnd_trng.h"
#include "cc_config_trng90b.h"
#include "cc_int_general_defs.h"

#ifndef CMPU_UTIL
#include "cc_pal_mutex.h"
#include "cc_pal_abort.h"
#include "cc_util_pm.h"
#endif

#define ROSC_INIT_START_BIT   0x80000000

#define LLF_RND_TRNG90B_MAX_BYTES ( LLF_RND_HW_DMA_EHR_SAMPLES_NUM_ON_TRNG90B_MODE * LLF_RND_HW_TRNG_EHR_WIDTH_IN_BYTES)
#define CC_CONFIG_TRNG90B_ADAPTIVE_PROPORTION_WINDOW_SIZE      1024     // binary noise source

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

#define DECREASE_CC_COUNTER \
        if (CC_IS_IDLE != CC_SUCCESS) { \
            CC_PalAbort("Fail to decrease PM counter\n"); \
        }

#define INCREASE_CC_COUNTER \
        if (CC_IS_WAKE != CC_SUCCESS) { \
            CC_PalAbort("Fail to increase PM counter\n"); \
        }

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


/******************************************************************************/
/***************   Prototypes and Private functions    ************************/
/******************************************************************************/
static CCError_t startTrngHW(
        CCTrngState_t  *pTrngState,
        CCTrngParams_t *pTrngParams,
        CCBool_t           isRestart,
        uint32_t          *roscsToStart_ptr,
        CCBool_t           isStartup);
static CCError_t getTrngSource(CCTrngState_t  *pTrngState,
                               CCTrngParams_t  *pTrngParams,
                               uint32_t        **sourceOut_ptr_ptr,
                               uint32_t         *sourceOutSize_ptr,
                               uint32_t         *pTrngWorkBuff,
                               CCBool_t          isStartup);
static CCError_t runContinuousTesting(uint32_t* pData, uint32_t sizeInBytes, CCTrngParams_t  *pTrngParams);
CCError_t LLF_RND_RepetitionCounterTest(uint32_t* pData, uint32_t sizeInBytes, uint32_t C);
CCError_t LLF_RND_AdaptiveProportionTest(uint32_t* pData, uint32_t sizeInBytes, uint32_t C, uint32_t W);
static CCError_t LLF_RND_TRNG_ReadMultipleEHR(uint32_t inSize, uint8_t *ramAddr,
                                              CCTrngState_t  *pTrngState,
                                              CCTrngParams_t *pTrngParams,
                                              uint32_t *roscsToStart_ptr);
static int32_t LLF_RND_TRNG_ReadEhrData(uint32_t *sample,
                                        CCTrngState_t  *pTrngState,
                                        CCTrngParams_t *pTrngParams,
                                        uint32_t *roscsToStart_ptr);
static uint32_t LLF_RND_TRNG_RoscMaskToNum(uint32_t mask);
static void LLF_RND_TRNG_EnableRngSourceAndWatchdog(CCTrngParams_t *pTrngParams, CCBool_t isStartup);



CCError_t LLF_RND_StartTrngHW(
        CCTrngState_t  *pTrngState,
        CCTrngParams_t *pTrngParams,
        CCBool_t           isRestart,
        uint32_t         *roscsToStart_ptr)
{
    CCError_t error = CC_OK;
    error = startTrngHW(pTrngState, pTrngParams, isRestart, roscsToStart_ptr, CC_FALSE/*isStartup*/);

    return error;
}


CCError_t LLF_RND_GetTrngSource(
        CCTrngState_t  *pTrngState,	   /*in/out*/
        CCTrngParams_t  *pTrngParams,   /*in/out*/
        uint32_t        **sourceOut_ptr_ptr,	/*out*/
        uint32_t         *sourceOutSize_ptr,/*in/out*/
        uint32_t         *pTrngWorkBuff,      /*in*/
        CCBool_t          isFipsSupported)      /*in*/
{
    CCError_t error = CC_OK;

    CC_UNUSED_PARAM(isFipsSupported);

    /* Lock mutex, check fatal err, and increase cc counter*/
    MUTEX_LOCK_AND_RETURN_UPON_ERROR(pCCRndCryptoMutex);

    CC_IS_FATAL_ERR_ON(error);
    if (error == CC_TRUE) {
        error = LLF_RND_TRNG_GENERATION_NOT_COMPLETED_ERROR;
        goto EndUnlockMutex;
    }

    INCREASE_CC_COUNTER

    /*Function Logic:*/
    error = getTrngSource(pTrngState, pTrngParams,
                          sourceOut_ptr_ptr, sourceOutSize_ptr, pTrngWorkBuff, CC_FALSE/* isStartup*/);

    /* release mutex and decrease CC counter */
    DECREASE_CC_COUNTER

    EndUnlockMutex:
    MUTEX_UNLOCK(pCCRndCryptoMutex);
    return error;
}

CCError_t LLF_RND_RunTrngStartupTest(
        CCTrngState_t        *pTrngState,
        CCTrngParams_t       *pTrngParams,
        uint32_t                *pTrngWorkBuff)
{
    CCError_t error = CC_OK;

    uint32_t        *pSourceOut;
    uint32_t         sourceOutSize;

    /* Lock mutex, check fatal err, and increase cc counter*/
    MUTEX_LOCK_AND_RETURN_UPON_ERROR(pCCRndCryptoMutex);

    CC_IS_FATAL_ERR_ON(error);
    if (error == CC_TRUE) {
        error = LLF_RND_TRNG_GENERATION_NOT_COMPLETED_ERROR;
        goto EndUnlockMutex;
    }

    INCREASE_CC_COUNTER
    error = getTrngSource(pTrngState, pTrngParams,
                          &pSourceOut, &sourceOutSize, pTrngWorkBuff, CC_TRUE/* isStartup*/);

    /* release mutex and decrease CC counter */
    DECREASE_CC_COUNTER

    EndUnlockMutex:
    MUTEX_UNLOCK(pCCRndCryptoMutex);
    return error;
}

static CCError_t startTrngHW(
        CCTrngState_t  *pTrngState,
        CCTrngParams_t *pTrngParams,
        CCBool_t          isRestart,
        uint32_t         *roscsToStart_ptr,
        CCBool_t 	  isStartup)
{
    /* LOCAL DECLARATIONS */

    CCError_t error = CC_OK;
    uint32_t tmpSamplCnt = 0;
    uint32_t roscNum = 0;

    /* FUNCTION LOGIC */

    /* Check pointers */
    if ((pTrngState == NULL) || (pTrngParams == NULL) ||
            (roscsToStart_ptr == NULL))
        return LLF_RND_TRNG_ILLEGAL_PTR_ERROR;


    /*--------------------------------------------------------------*/
    /* 1. If full restart, get semaphore and set initial ROSCs      */
    /*--------------------------------------------------------------*/
    if (isRestart == CC_TRUE) {
        /* set ROSC to 1 (fastest)  */
        *roscsToStart_ptr = 1UL;

        /* init rndState flags to zero */
        pTrngState->LastTrngRosc = 0;
    }

    /* Get fastest allowed ROSC */
    error = LLF_RND_GetFastestRosc(
            pTrngParams,
            roscsToStart_ptr	 /*in/out*/);
    if (error)
        return error;

    error = LLF_RND_GetRoscSampleCnt(*roscsToStart_ptr, pTrngParams);
    if (error)
        return error;

    roscNum = LLF_RND_TRNG_RoscMaskToNum(*roscsToStart_ptr);

    /* 2. Restart the TRNG and set parameters and enable the HW RND clock	*/
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
    CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG, RNG_IMR), LLF_RNG_INT_MASK_ON_TRNG90B_MODE);

    CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG, TRNG_CONFIG), roscNum);

    /* Debug Control register: set to 0 - no bypasses */
    CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG, TRNG_DEBUG_CONTROL), LLF_RND_HW_DEBUG_CONTROL_VALUE_ON_TRNG90B_MODE);

    LLF_RND_TRNG_EnableRngSourceAndWatchdog(pTrngParams, isStartup);

    /* set indication about current started ROSCs:  */
    /*new started*/
    pTrngState->LastTrngRosc = *roscsToStart_ptr;

    return error;
}




static uint32_t LLF_RND_TRNG_RoscMaskToNum(uint32_t mask)
{
    return (mask == LLF_RND_HW_TRNG_ROSC3_BIT) ? LLF_RND_HW_TRNG_ROSC3_NUM :
            (mask == LLF_RND_HW_TRNG_ROSC2_BIT) ? LLF_RND_HW_TRNG_ROSC2_NUM :
                    (mask == LLF_RND_HW_TRNG_ROSC1_BIT) ? LLF_RND_HW_TRNG_ROSC1_NUM :
                            LLF_RND_HW_TRNG_ROSC0_NUM;
}

static CCError_t getTrngSource(
        CCTrngState_t  *pTrngState,	  /*in/out*/
        CCTrngParams_t  *pTrngParams,   /*in/out*/
        uint32_t        **sourceOut_ptr_ptr,   /*out*/
        uint32_t         *sourceOutSize_ptr,/*in/out*/
        uint32_t         *pTrngWorkBuff,     /*in*/
        CCBool_t          isStartup)	       /*in*/
{
    /* LOCAL DECLARATIONS */

    /* The return error identifier */
    CCError_t error = 0;
    int32_t  i = 0;
    uint32_t roscToStart = 0x1;
    uint32_t *ramAddr;
    uint32_t trng90bRequiredBytes;

    /* FUNCTION LOGIC */
    /* ............... local initializations .............................. */
    /* -------------------------------------------------------------------- */

    /* initializing the Error to O.K */
    error = CC_OK;

    /* since CC_TRNG_WORK_BUFFER_SIZE_WORDS is external define, we check here the value contains the minimum bytes for entropy:
     * [CC_TRNG_WORK_BUFFER_SIZE_WORDS = CC_CONFIG_TRNG90B_ENTROPY_MIN_BYTES + CC_RND_TRNG_SRC_INNER_OFFSET_WORDS + 2 extra words]
     * the verification is used in development phase. */
    if (CC_TRNG_WORK_BUFFER_SIZE_WORDS < CALC_FULL_32BIT_WORDS(CC_CONFIG_TRNG90B_ENTROPY_MIN_BYTES) + CC_RND_TRNG_SRC_INNER_OFFSET_WORDS) {
        return LLF_RND_WORKSPACE_TOO_SMALL_ERROR;
    }

    if(isStartup == CC_FALSE) {
        trng90bRequiredBytes = pTrngParams->userParams.trngModeParams.numOfBytes;
        if (trng90bRequiredBytes > CC_CONFIG_TRNG90B_ENTROPY_MIN_BYTES) {
            return LLF_RND_TRNG_BUFFER_TOO_SMALL_ERROR;
        }
    } else {
        trng90bRequiredBytes = CC_CONFIG_TRNG90B_AMOUNT_OF_BYTES_STARTUP;
    }

    /* Set source RAM address with offset 8 bytes from sourceOut address in
	  order to remain empty bytes for CC operations */
    *sourceOut_ptr_ptr = pTrngWorkBuff;
    ramAddr = *sourceOut_ptr_ptr + CC_RND_TRNG_SRC_INNER_OFFSET_WORDS;

    /* init to 0 for FE mode */
    *sourceOutSize_ptr = 0;
        /* Full restart TRNG */
        error = startTrngHW(
                pTrngState,
                pTrngParams,
                CC_TRUE/*isRestart*/,
                &roscToStart,
                isStartup);

        /*Note: in case of error the TRNG HW is still not started*/
        if (error)
            goto End;

    /*====================================================*/
    /*====================================================*/
    /*         Processing after previous start            */
    /*====================================================*/
    /*====================================================*/

    /*====================================================*/
    /* TRNG90b mode processing: start Roscs sequentionally - *
     * from fast to slow Rosc 			      */
    /*====================================================*/

    for (i = 0; i < LLF_RND_NUM_OF_ROSCS; ++i) {
        error = LLF_RND_TRNG_ReadMultipleEHR(trng90bRequiredBytes, (uint8_t *)ramAddr,
                                             pTrngState,
                                             pTrngParams,
                                             &roscToStart);

        if (error == CC_OK) {
            error = runContinuousTesting(ramAddr, trng90bRequiredBytes, pTrngParams);
            if (error == CC_OK) {
                *sourceOutSize_ptr = trng90bRequiredBytes;
                break;
            }
        }
        if (error == LLF_RND_CRNGT_TEST_FAIL_ERROR) {
            /* LLF_RND_CRNGT_TEST_FAIL_ERROR is set only in FIPS mode. do not continue to the next rosc. */
            break;
        }
        if (error != CC_OK) {/* try next rosc */
            /*  if no remain roscs to start, return error */
            if (roscToStart == 0x8) {
                error = LLF_RND_TRNG_GENERATION_NOT_COMPLETED_ERROR;
                break;
            }
            else {
                /* Call StartTrng, with next ROSC */
                roscToStart <<= 1;
                error = LLF_RND_StartTrngHW(
                        pTrngState,
                        pTrngParams,
                        CC_FALSE/*isRestart*/,
                        &roscToStart);

                /* if no remain valid roscs, return error */
                if (error == LLF_RND_TRNG_REQUIRED_ROSCS_NOT_ALLOWED_ERROR && (pTrngParams->RoscsAllowed != 0)) {

                    error = LLF_RND_TRNG_GENERATION_NOT_COMPLETED_ERROR;
                }

                if (error != CC_OK) {
                    goto End;
                }
            }
        }


        /* update total processed ROSCs */
        pTrngState->LastTrngRosc = roscToStart;
    }

    /* ................. end of function ..................................... */
    /* ----------------------------------------------------------------------- */
    End:

    if (error != CC_OK) {
        CC_PalMemSetZero((uint8_t *)ramAddr, trng90bRequiredBytes);
    }
    /* turn the RNG off    */
    LLF_RND_TurnOffTrng();

    return error;
}/* END of getTrngSource */


/*
implementation of Continuous Testing (NIST SP 800-90B 6.5.1.2)
 */

static CCError_t runContinuousTesting(uint32_t* pData,
                                      uint32_t sizeInBytes,
                                      CCTrngParams_t  *pTrngParams)
{
    CCError_t error = CC_OK;
    uint32_t repC = pTrngParams->userParams.trngModeParams.repetitionCounterCutoff;
    uint32_t adpW = CC_CONFIG_TRNG90B_ADAPTIVE_PROPORTION_WINDOW_SIZE;
    uint32_t adpC = pTrngParams->userParams.trngModeParams.adaptiveProportionCutOff;


    error = LLF_RND_RepetitionCounterTest(pData, sizeInBytes, repC);
    if (error != CC_OK) {
        return error;
    }
    error = LLF_RND_AdaptiveProportionTest(pData, sizeInBytes, adpC, adpW);
    if (error != CC_OK) {
        return error;
    }

    return CC_OK;
}

#define UINT8_SIZE_IN_BITS  8
#define UINT32_SIZE_IN_BITS (sizeof(uint32_t) * UINT8_SIZE_IN_BITS)
static uint32_t getBitsFromUint32Array(uint32_t arrayBitsOffset, uint32_t numOfBits, uint32_t* arr)
{
    uint32_t res = 0;
    uint32_t byteOffset = arrayBitsOffset / UINT32_SIZE_IN_BITS;
    uint32_t bitOffset = arrayBitsOffset % UINT32_SIZE_IN_BITS;
    if (numOfBits > UINT32_SIZE_IN_BITS) {
        return 0;
    }
    res = arr[byteOffset] >> bitOffset;
    // (UINT32_SIZE_IN_BITS - bitOffset) bits were taken from the first dword.

    if (UINT32_SIZE_IN_BITS - bitOffset > numOfBits)
        // we copied more bits than required. zero the extra bits.
    {
        res &= (0xFFFFFFFF >> (UINT32_SIZE_IN_BITS - numOfBits));
    } else if (UINT32_SIZE_IN_BITS - bitOffset < numOfBits)
        // we copied less bits than required. copy the next bits from the next dword.
    {
        numOfBits -= UINT32_SIZE_IN_BITS - bitOffset;
        res |= (arr[byteOffset + 1] & (0xFFFFFFFF >> (UINT32_SIZE_IN_BITS - numOfBits))) << (UINT32_SIZE_IN_BITS - bitOffset);
    }

    return res;
}

/*
implementation of Repetition Counter Test (NIST SP 800-90B (2nd Draft) 4.4.1)
C = the cutoff value at which the Repetition Count Test fails
 */
CCError_t LLF_RND_RepetitionCounterTest(uint32_t* pData, uint32_t sizeInBytes, uint32_t C)
{
    uint32_t bitOffset=0;
    uint32_t newSample = 0;
    uint32_t A = 0;			/* the most recently seen sample value */
    uint32_t B = 0;			/* the number of consecutive times that the value A has been seen */
    uint32_t bitsPerSample = 1;	/* always use single bit per sample for repetition counter test */


    if (pData == NULL || sizeInBytes == 0 || LLF_RND_TRNG90B_MAX_BYTES < sizeInBytes) {
        return LLF_RND_TRNG_REPETITION_COUNTER_ERROR;
    }

    // the repetition count test is performed as follows:
    for (bitOffset = 0; bitOffset <= (sizeInBytes * UINT8_SIZE_IN_BITS) - bitsPerSample; bitOffset += bitsPerSample) {
        newSample = getBitsFromUint32Array(bitOffset, bitsPerSample, (uint32_t*)pData);

        // 1. Let A be the current sample value.
        // 2. Initialize the counter B to 1.
        if (bitOffset == 0) {
            A = newSample;
            B = 1;
        }
        // 3. If the next sample value is A, increment B by one.
        else if (A == newSample) {
            ++B;
            // If B is equal to C, return an error.
            if (B == C) {
                return LLF_RND_TRNG_REPETITION_COUNTER_ERROR;
            }
        } else {
            // Let A be the next sample value.
            A = newSample;
            // Initialize the counter B to 1.
            B = 1;
            // Repeat Step 3.
        }
    }
    return CC_OK;
}

/*
implementation of Adaptive Proportion Test (NIST SP 800-90B (2nd Draft) 4.4.2)
N = the total number of samples that must be observed in one run of the test, also known as the "window size" of the test
C = the cutoff value above which the test should fail
 */
CCError_t LLF_RND_AdaptiveProportionTest(uint32_t* pData, uint32_t sizeInBytes, uint32_t C, uint32_t W)
{
    uint32_t bitOffset=0;
    uint32_t currentSample = 0;
    uint32_t A = 0;         /* the sample value currently being counted */
    uint32_t B = 0;	        /* the current number of times that A has been seen in the S samples examined so far */
    uint32_t i = 0;         /* the counter for the number of samples examined in the current window */
    uint32_t bitsPerSample = 1; /* binary source */

    if (pData == NULL || sizeInBytes == 0 || LLF_RND_TRNG90B_MAX_BYTES < sizeInBytes || W == 0 || C == 0) {
        return LLF_RND_TRNG_ADAPTION_PROPORTION_ERROR;
    }

    // The test is performed as follows:
    for (bitOffset = 0; bitOffset <= (sizeInBytes * UINT8_SIZE_IN_BITS) - bitsPerSample; bitOffset += bitsPerSample) {
        currentSample = getBitsFromUint32Array(bitOffset, bitsPerSample, (uint32_t*)pData);

        // 1. Let A be the current sample value.
        // 2. Initialize the counter B to 1
        if ((bitOffset == 0) || (i == W)) {
            A = currentSample;
            B = 1;
            i = 0;
        }
        // 3. For i = 1 to W-1
        else {
            // If the next sample is equal to A, increment B by 1.
            if (A == currentSample) {
                ++B;
            }
        }
        // 4. If B > C, return error.
        if (i == W - 1) {
            if (B > C) {
                return LLF_RND_TRNG_ADAPTION_PROPORTION_ERROR;
            }
        }
        ++i;
        // 5. Go to Step 1.
    }
    return CC_OK;
}

static int32_t LLF_RND_TRNG_ReadEhrData(uint32_t *sample,
                                        CCTrngState_t  *pTrngState,
                                        CCTrngParams_t *pTrngParams,
                                        uint32_t *roscsToStart_ptr)
{
    uint32_t i;
    CCError_t err = CC_OK;
    uint32_t isr = 0;
    uint32_t ehr = 0;

    err = startTrngHW(pTrngState, pTrngParams, CC_FALSE, roscsToStart_ptr, CC_FALSE);
    if (err) {
        return err;
    }

    /* wait RNG interrupt: isr signals error bits */
    err = LLF_RND_WaitRngInterrupt(&isr);
    if (err != CC_OK){
        return err;
    }

    err = LLF_RND_TRNG_REQUIRED_ROSCS_NOT_ALLOWED_ERROR;
    if (CC_REG_FLD_GET(0, RNG_ISR, EHR_VALID, isr)) {
        err = CC_OK;
    }

    /* Read EHR into tmp buffer */
    for (i = 0; i < LLF_RND_HW_TRNG_EHR_WIDTH_IN_WORDS; i++) {
        ehr = CC_HAL_READ_REGISTER(CC_REG_OFFSET(RNG, EHR_DATA_0) + (i * sizeof(uint32_t)));
        /* verify that the EHR read didn’t return 0 value.
         * In case of 0 value was returned, the driver shall restart the entropy collection. */
        if (ehr == 0) {
            return LLF_RND_TRNG_EHR_DATA_ZERO_ERROR;
        }
        sample[i] = ehr;
    }

    return CC_OK;
}

static CCError_t LLF_RND_TRNG_ReadMultipleEHR(uint32_t inSize, uint8_t *ramAddr,
                                              CCTrngState_t  *pTrngState,
                                              CCTrngParams_t *pTrngParams,
                                              uint32_t *roscsToStart_ptr)
{
    uint32_t noise_samples[LLF_RND_HW_TRNG_EHR_WIDTH_IN_WORDS];
    CCError_t err = CC_OK;
    uint32_t  final_chunk_size=0;
    uint32_t counter = 0;
    /* in case inSize is not divided by 6, copy partial last chunk */
    if (inSize % LLF_RND_HW_TRNG_EHR_WIDTH_IN_WORDS){
        final_chunk_size = inSize % LLF_RND_HW_TRNG_EHR_WIDTH_IN_WORDS;
    }
    while (inSize) {
        LLF_RND_TurnOffTrng();
        err = LLF_RND_TRNG_ReadEhrData(noise_samples, pTrngState, pTrngParams, roscsToStart_ptr);
        if (err != CC_OK) {
            CC_PalMemSetZero(ramAddr, inSize);
            return err;
        }
        if ((counter == inSize/LLF_RND_HW_TRNG_EHR_WIDTH_IN_WORDS) && (final_chunk_size != 0))
        {
            /* Copy the needed amount of bytes to the result buffer */
            CC_PalMemCopy(ramAddr, (uint8_t *)noise_samples, final_chunk_size);
            inSize -= final_chunk_size;
            ramAddr += final_chunk_size;
        }
        else{
            /* Copy the needed amount of bytes to the result buffer */
            CC_PalMemCopy(ramAddr, (uint8_t *)noise_samples, LLF_RND_HW_TRNG_EHR_WIDTH_IN_BYTES);
            inSize -= LLF_RND_HW_TRNG_EHR_WIDTH_IN_BYTES;
            ramAddr += LLF_RND_HW_TRNG_EHR_WIDTH_IN_BYTES;
        }
        counter++;
    }

    return CC_OK;
}

static void LLF_RND_TRNG_EnableRngSourceAndWatchdog(CCTrngParams_t *pTrngParams, CCBool_t isStartup)
{
    uint32_t maxCycles;
    uint32_t ehrSamples;

    if (isStartup == CC_TRUE) {
        ehrSamples = CC_CONFIG_TRNG90B_AMOUNT_OF_BYTES_STARTUP;
    } else {
        ehrSamples = pTrngParams->userParams.trngModeParams.numOfBytes;
    }
    ehrSamples/= LLF_RND_HW_TRNG_EHR_WIDTH_IN_BYTES;

    /* Set watchdog threshold to maximal allowed time (in CPU cycles) */
    maxCycles = LLF_RND_CalcMaxTrngTime(ehrSamples, pTrngParams->SubSamplingRatio);
    CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG, RNG_WATCHDOG_VAL), maxCycles);

    /* enable the RND source */
    CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG, RND_SOURCE_ENABLE), LLF_RND_HW_RND_SRC_ENABLE_VAL);
}

