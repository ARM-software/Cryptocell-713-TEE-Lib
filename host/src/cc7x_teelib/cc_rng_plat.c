/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */




/************* Include Files ****************/

#include "cc_registers.h"
#include "cc_hal_plat.h"
#include "cc_pal_types.h"
#include "dx_reg_base_host.h"
#include "cc_regs.h"
#include "cc_rnd_common.h"
#include "cc_rnd_error.h"
#include "cc_rnd_local.h"
#include "cc_rng_plat.h"
#include "cc_pal_mutex.h"
#include "cc_plat.h"
#include "hw_queue.h"
#include "cc_pal_dma.h"
#include "cc_pal_mem.h"
#include "cc_pal_abort.h"
#include "cc_general_defs.h"
#include "cc_address_defs.h"
#include "llf_rnd_trng.h"
#include "cc_pal_trng.h"

extern CC_PalMutex CCSymCryptoMutex;

/****************************************************************************************/
/**
 *
 * @brief The function retrieves the TRNG parameters, provided by the User trough PAL implementation,
 *        and sets them into structures given by pTrngParams.
 *
 * @param[out] pTrngParams - The pointer to structure, containing parameters
 *                            of HW TRNG.
 *
 * @return CCError_t - no return value
 */
CCError_t RNG_PLAT_TrngUserParams(
        CCTrngParams_t  *pTrngParams)
{
        CCError_t  error = CC_OK;
        size_t  paramsSize = sizeof(CC_PalTrngParams_t);

        error = CC_PalTrngParamGet(&pTrngParams->userParams, &paramsSize);
        if (error != CC_OK) {
            return error;
        }
        // Verify PAL and run-time lib compiled with the same CC_CONFIG_TRNG_MODE
        if (paramsSize != sizeof(CC_PalTrngParams_t)) {
            error = CC_RND_MODE_MISMATCH_ERROR;
            goto func_error;
        }
        /* Allowed ROSCs lengths b'0-3. If bit value 1 - appropriate ROSC is allowed. */
        pTrngParams->RoscsAllowed = (((pTrngParams->userParams.SubSamplingRatio1 > 0) ? 0x1 : 0x0) |
                ((pTrngParams->userParams.SubSamplingRatio2 > 0) ? 0x2 : 0x0) |
                ((pTrngParams->userParams.SubSamplingRatio3 > 0) ? 0x4 : 0x0) |
                ((pTrngParams->userParams.SubSamplingRatio4 > 0) ? 0x8 : 0x0));
        pTrngParams->SubSamplingRatio = 0;
        if (pTrngParams->RoscsAllowed == 0) {
            error = CC_RND_STATE_VALIDATION_TAG_ERROR;
            goto func_error;
        }

        return CC_OK;
func_error:
        CC_PalMemSetZero(pTrngParams, sizeof(CC_PalTrngParams_t));
        return error;
}


/****************************************************************************************/
/**
 *
 * @brief The function retrieves the TRNG parameters, provided by the User trough NVM,
 *        and sets them into structures given by pointers rndContext_ptr and trngParams_ptr.
 *
 * @author reuvenl (6/26/2012)
 *
 * @param[out] pRndState - The pointer to structure, containing PRNG data and
 *                            parameters.
 * @param[out] pTrngParams - The pointer to structure, containing parameters
 *                            of HW TRNG.
 *
 * @return CCError_t - no return value
 */
CCError_t RNG_PLAT_SetUserRngParameters(
        CCRndState_t *pRndState,
        CCTrngParams_t  *pTrngParams)
{
    pRndState->KeySizeWords = CC_AES_KDR_MAX_SIZE_WORDS; /*SUPPORT_256_192_KEY*/

    return RNG_PLAT_TrngUserParams(pTrngParams);

}

/**********************************************************************/
/*!
 * Copy TRNG source from SRAM to RAM using CC HW descriptors.
 *
 * \param inSramAddr - Input SRAM address of the source buffer, must be word
 * aligned.
 * \param inSize - Size in octets of the source buffer, must be multiple of
 * word.
 * \param outRamAddr - Output RAM address of the destination buffer, must be
 * word aligned.
 *
 * \return 0 if success, else 1.
 *
 *  Note: The AXI bus secure mode for in/out buffers is used: AxiNs = 0.
 */
uint32_t LLF_RND_DescBypass(CCSramAddr_t  inSramAddr, uint32_t inSize, uint32_t *outAddr_ptr)
{
        uint32_t error = 0;

        HwDesc_s desc;
        /* Virtual and physical address of allocated temp buffer */
        uint8_t *tmpVirtAddr_ptr;
        CCPalDmaBlockInfo_t  tmpBlockInfo;
        uint32_t  numOfBlocks = 1;
        CC_PalDmaBufferHandle dmaH;

        error = CC_PalMutexLock(&CCSymCryptoMutex, CC_INFINITE);
        if (error != CC_SUCCESS) {
                CC_PalAbort("Fail to acquire mutex\n");
        }
        /* Allocate contiguous buffer for DMA transfer */
        error = CC_PalDmaContigBufferAllocate(inSize,
                                               &tmpVirtAddr_ptr);
        if (error != 0) {
                goto End;
        }

        numOfBlocks = 1;
        error = CC_PalDmaBufferMap(tmpVirtAddr_ptr,
                                    inSize,
                                    CC_PAL_DMA_DIR_FROM_DEVICE,
                                    &numOfBlocks,
                                    &tmpBlockInfo,
                                    &dmaH);
        if ((error != 0) || (numOfBlocks != 1)) {
                goto End;
        }

        /* Execute BYPASS operation */
        HW_DESC_INIT(&desc);
        HW_DESC_SET_DIN_SRAM(&desc, inSramAddr, inSize);
        HW_DESC_SET_DOUT_TYPE(&desc, DMA_DLLI/*outType*/, tmpBlockInfo.blockPhysAddr,
                              inSize, DEFALUT_AXI_SECURITY_MODE/*outAxiNs*/);
        HW_DESC_SET_FLOW_MODE(&desc, BYPASS);
        AddHWDescSequence(&desc);

        /* Wait */
        WaitForSequenceCompletionPlat(CC_TRUE);
        CC_PalDmaBufferUnmap(tmpVirtAddr_ptr,
                              inSize,
                              CC_PAL_DMA_DIR_FROM_DEVICE,
                              numOfBlocks,
                              &tmpBlockInfo,
                              dmaH);

        /* Copy data from temp buffer into RAM output, using virt. addresses */
        CC_PalMemCopy((uint8_t*)outAddr_ptr, tmpVirtAddr_ptr, inSize);

        /* Release the temp buffer */
        error = CC_PalDmaContigBufferFree(inSize,
                                           tmpVirtAddr_ptr);

        End:
        if (CC_PalMutexUnlock(&CCSymCryptoMutex) != CC_SUCCESS) {
                CC_PalAbort("Fail to release mutex\n");
        }

        return error;
}



