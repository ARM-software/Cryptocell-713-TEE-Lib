/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */
/************* Include Files ****************/

#include "cc_registers.h"
#include "cc_pal_mem.h"
#include "cc_pal_types.h"
#include "cc_hal.h"
#include "cc_regs.h"
#include "cc_rnd_local.h"
#include "cc_rnd_error.h"
#include "llf_rnd_hwdefs.h"
#include "llf_rnd_error.h"

#ifdef CMPU_UTIL
#include "cc_hal_sb.h"

extern unsigned long gCcRegBase;
#else
#include "cc_pal_interrupt_ctrl.h"
#endif

/****************************************************************************************/
/***********************      Auxiliary Functions              **************************/
/****************************************************************************************/


/************************************************************************************/
/*!
 * Busy wait upon RNG Interrupt signals.
 *
 * This function waits RNG interrupt and then disables RNG source.
 * It calls wait for interrupt completion function to get RNG ISR (status) register.
 *
 * \return uint32_t RNG Interrupt status.
 */
CCError_t LLF_RND_WaitRngInterrupt(uint32_t *isr_ptr)
{
    CCError_t error = CC_OK;

#ifndef CMPU_UTIL
    uint32_t irqData = 0;

    /* wait for watermark signal */
    error = CC_PalWaitInterruptComp(CC_HAL_IRQ_RNG, &irqData);
    if (error == CC_OK){
        *isr_ptr = irqData;
    }
#else
    *isr_ptr = SB_HalWaitRngInterrupt(gCcRegBase);
#endif

    /* stop DMA and the RNG source */
    CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG,RNG_DMA_ENABLE), 0);
    CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG, RND_SOURCE_ENABLE), 0);

    return error;
}

/*****************************************************************/

CCError_t LLF_RND_GetRoscSampleCnt(uint32_t rosc, CCTrngParams_t *pTrngParams)
{
    switch (rosc) {
    case 0x1:
        pTrngParams->SubSamplingRatio = pTrngParams->userParams.SubSamplingRatio1;
        break;
    case 0x2:
        pTrngParams->SubSamplingRatio = pTrngParams->userParams.SubSamplingRatio2;
        break;
    case 0x4:
        pTrngParams->SubSamplingRatio = pTrngParams->userParams.SubSamplingRatio3;
        break;
    case 0x8:
        pTrngParams->SubSamplingRatio = pTrngParams->userParams.SubSamplingRatio4;
        break;
    default:
        return LLF_RND_TRNG_REQUIRED_ROSCS_NOT_ALLOWED_ERROR;
    }

    return CC_OK;
}

/**
 * The function gets next allowed rosc
 *
 * @author reuvenl (9/12/2012)
 *
 * @param pTrngParams - a pointer to params structure.
 * @param rosc_ptr - a pointer to previous rosc /in/, and
 * 			to next rosc /out/.
 *
 * @return CCError_t
 */
CCError_t LLF_RND_GetFastestRosc(
        CCTrngParams_t *pTrngParams,
        uint32_t *rosc_ptr	 /*in/out*/)
{
    /* setting rosc */
    if (*rosc_ptr == 0) {
        return LLF_RND_TRNG_REQUIRED_ROSCS_NOT_ALLOWED_ERROR;
    }
    while (*rosc_ptr <= 0x08) {
		if (*rosc_ptr & pTrngParams->RoscsAllowed) {
			return CC_OK;
		} else {
			*rosc_ptr <<= 1;
		}
	}
    return LLF_RND_MISSING_ROSC_ERROR;
}


/****************************************************************************************/
/*****************************       Public Functions      ******************************/
/****************************************************************************************/


/************************************************************************************/
/**
 * @brief The LLF_RND_TurnOffTrng stops the hardware random bits collection
 *        closes RND clocks and releases HW semaphore.
 *
 *
 *
 * @return CCError_t - On success CC_OK is returned, on failure a
 *                        value MODULE_* as defined in ...
 */
void LLF_RND_TurnOffTrng(void)
{
    /* LOCAL DECLARATIONS */

    uint32_t temp = 0;


    /* FUNCTION LOGIC */

    /* disable the RND source  */
    CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG,RND_SOURCE_ENABLE), LLF_RND_HW_RND_SRC_DISABLE_VAL);

    /* close the Hardware clock */
    CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG,RNG_CLK_ENABLE), LLF_RND_HW_RND_CLK_DISABLE_VAL);

    /* clear RNG interrupts */
    CC_REG_FLD_SET(HOST_RGF, HOST_RGF_ICR, RNG_INT_CLEAR, temp, 1);                                               \
    CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_RGF_ICR), temp);
    CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG,RNG_ICR), 0xFFFFFFFF);


    return;

}/* END OF LLF_RND_TurnOffTrng*/


/**
 * @brief: The function performs CPRNGT (Continued PRNG Test) according
 *         to NIST 900-80 and FIPS (if defined) standards.
 *
 * @param[in] prev_ptr - The pointer to previous saved generated random
 *                       value of size 16 bytes.
 * @param[in] buff_ptr - The pointer to generated random buffer.
 * @param[in] last_ptr - The pointer to last generated random block
 *                       of size 16 bytes used for output last bytes.
 * @param[in] countBlocks - The count of generated random blocks, including
 *                          the last block. Assumed countBlocks > 0.
 *
 * @return CCError_t - On success CC_OK is returned, on failure a
 *                        value MODULE_* as defined in cc_error.h
 */
CCError_t LLF_RND_RndCprngt(uint8_t            *prev_ptr,        /*in*/
                            uint8_t            *buff_ptr,        /*in*/
                            uint8_t            *last_ptr,        /*in*/
                            int32_t             countBlocks)   /*in*/
{
    /* LOCAL DECLARATIONS */

    CCError_t error = CC_OK;
    int32_t  i;

    /*  FUNCTION LOGIC */

    /* compare the previous Value and last block */
    if (countBlocks == 1) {
        if (CC_PalMemCmp(prev_ptr, /*prev*/
                         last_ptr,/*last block*/
                         CC_AES_BLOCK_SIZE_IN_BYTES) == 0) {
            error =  CC_RND_CPRNG_TEST_FAIL_ERROR;
            goto End;
        }
    } else { /* countBlocks > 1, compare first and last blocks */
        if (CC_PalMemCmp(prev_ptr,  /*prev*/
                         buff_ptr, /*first block*/
                         CC_AES_BLOCK_SIZE_IN_BYTES) == 0) {
            error =  CC_RND_CPRNG_TEST_FAIL_ERROR;
            goto End;
        }

        if (CC_PalMemCmp(buff_ptr + (countBlocks-2)*CC_AES_BLOCK_SIZE_IN_BYTES, /*prev*/
                         last_ptr,/*last block*/
                         CC_AES_BLOCK_SIZE_IN_BYTES) == 0) {
            error =  CC_RND_CPRNG_TEST_FAIL_ERROR;
            goto End;
        }
    }
    /* compare intermediate blocks */
    if (countBlocks > 2 && error == CC_OK) {
        for (i = 0; i < countBlocks-2; i++) {
            /* compare all current with previous blocks */
            if (CC_PalMemCmp(buff_ptr + i*CC_AES_BLOCK_SIZE_IN_BYTES,
                             buff_ptr + (i+1)*CC_AES_BLOCK_SIZE_IN_BYTES,
                             CC_AES_BLOCK_SIZE_IN_BYTES) == 0) {
                error = CC_RND_CPRNG_TEST_FAIL_ERROR;
                goto End;
            }
        }
    }

    End:


    return error;
}


