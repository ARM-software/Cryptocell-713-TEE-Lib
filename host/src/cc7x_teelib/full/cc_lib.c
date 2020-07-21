/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#define CC_PAL_LOG_CUR_COMPONENT CC_LOG_MASK_CCLIB

/************* Include Files *************************************************/
#include "cc_pal_types.h"
#include "cc_pal_log.h"
#include "cc_pal_mem.h"
#include "cc_lib.h"
#include "cc_hal.h"
#include "cc_hal_defs.h"
#include "cc_pal_init.h"
#include "cc_pal_mutex.h"
#include "cc_pal_interrupt_ctrl.h"
#include "hw_queue.h"
#include "completion.h"
#include "cc_rnd.h"
#include "cc_rnd_common.h"
#include "sym_adaptor_driver.h"
#include "cc_pal_dma.h"
#include "cc_pal_perf.h"
#include "cc_general_defs.h"
#include "pki.h"
#include "llf_rnd_trng.h"
#include "cc_plat.h"
#include "cc_sram_map.h"
#include "cc_rng_plat.h"
#include "cc_util_rpmb_adaptor.h"
#include "cc_lib_common.h"
#include "cc_hal_axi_ctrl.h"
#include "cc_util_int_defs.h"
#ifdef CC_SUPPORT_FIPS
#include "cc_pal_cert.h"
#include "cc_fips.h"
#include "cc_fips_defs.h"
#endif

#ifdef CC_SUPPORT_CH_CERT
#include "cc_pal_cert.h"
#include "cc_chinese_cert.h"
#include "cc_chinese_cert_defs.h"
#endif

/************************ Defines ********************************************/
#define CC_CPP_INTERRUPT_ENABLE_MASK                    \
        (1 << CC_HOST_RGF_IRR_REE_KS_OPERATION_INDICATION_BIT_SHIFT)

#ifdef CC_SUPPORT_FIPS
#define CC_GPR0_INTERRUPT_ENABLE_MASK                    \
        (1 << CC_HOST_RGF_IRR_GPR0_INT_BIT_SHIFT)
#endif
/************************ Extern *********************************************/
/* resets the low resolution secure timer */
extern void CC_UtilResetLowResTimer(void);
/* interrupthandler function */
extern void CC_InterruptHandler(void);

/************************ Global Data ****************************************/
CC_PalMutex CCSymCryptoMutex;
CC_PalMutex CCAsymCryptoMutex;
CC_PalMutex CCRndCryptoMutex;
CC_PalMutex CCFipsMutex;
CC_PalMutex CCChCertMutex;
CC_PalMutex *pCCRndCryptoMutex;
CC_PalMutex *pCCGenVecMutex;

/************************ Private Functions **********************************/
static CClibRetCode_t InitHukRma(void *p_rng)
{
    uint32_t regVal = 0, lcsVal = 0;
    uint32_t kdrValues[CC_AES_KDR_MAX_SIZE_WORDS];
    CCError_t error = CC_OK;
    uint32_t i = 0;

    /* Read LCS */
    regVal = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, LCS_REG));
    lcsVal = CC_REG_FLD_GET(0, LCS_REG, LCS_REG, regVal);

    /* if it is not LCS == RMA return */
    if (lcsVal != CC_LCS_RMA_LCS) {
        return CC_LIB_RET_OK;
    }
    else{ // in case lcs == RMA set the KDR
        error = CC_RndGenerateVector(p_rng,
                                     (unsigned char *)kdrValues, sizeof(kdrValues));
        if (error != CC_OK) {
            return CC_LIB_RET_EINVAL;
        }
        /* set the random value to the KDR register */
        for (i = 0; i < CC_AES_KDR_MAX_SIZE_WORDS; i++){
            CC_HAL_WRITE_REGISTER(
                    CC_REG_OFFSET(HOST_RGF, HOST_SHADOW_HUK_REG), kdrValues[i]);
        }
    }

    return CC_LIB_RET_OK;
}


static void ClearSram(void)
{
    uint32_t regVal = 0, lcsVal = 0;

    /* Read LCS */
    regVal = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, LCS_REG));
    lcsVal = CC_REG_FLD_GET(0, LCS_REG, LCS_REG, regVal);

    /* if it is not LCS == RMA or secure return */
    if ((lcsVal != CC_LCS_RMA_LCS) &&
            (lcsVal != CC_LCS_SECURE_LCS)) {
        return;
    }

    /* clear symmetric context from SRAM */
    _ClearSram(CC_SRAM_DRIVER_ADAPTOR_CONTEXT_CACHE_ADDR,
               CC_SRAM_DRIVER_ADAPTOR_CONTEXT_MAX_SIZE);
    /* clear PKA from SRAM */
    PkiClearAllPka();

    return;
}


static CCError_t RndStartupTest(void *p_rng,
        CCTrngWorkBuff_t  *pTrngWorkBuff/*in/out*/)
{
    /* error identifier definition */
    CCError_t error = CC_OK;
    CCRndState_t   *pRndState = NULL;
    CCTrngParams_t  trngParams;

    pRndState = (CCRndState_t *)p_rng;
    error = RNG_PLAT_SetUserRngParameters(pRndState, &trngParams);
    if (error != CC_SUCCESS) {
        return error;
    }

    /* call on Instantiation mode */
    error = LLF_RND_RunTrngStartupTest(&pRndState->trngState, &trngParams,
                                       (uint32_t*)pTrngWorkBuff);

    return error;
}

static CClibRetCode_t CC_OtpLoadingVerify(void)
{
    uint32_t regVal;
    uint32_t isTci = 0;
    uint32_t isPci = 0;

    /* Verify OTP_ERR_INT error is not set in HOST_RGF_IRR */
    regVal = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_RGF_IRR));
    regVal = CC_REG_FLD_GET(HOST_RGF, HOST_RGF_IRR, OTP_ERR_INT, regVal);
    if (regVal) {
        return CC_LIB_OTP_ERROR;
    }

    CC_UTIL_GET_LCS(regVal);

    if( (regVal == CC_LCS_DEVICE_MANUFACTURE_LCS) || (regVal == CC_LCS_SECURE_LCS) ) {
        /* Verify TCI/PCI configuration is valid (One and only one of the TCI/PCI bits is set) */
        CC_UTIL_IS_OTP_PCI_TCI_SET(isTci, OTP_SECOND_MANUFACTURE_FLAG, TCI);
        CC_UTIL_IS_OTP_PCI_TCI_SET(isPci, OTP_SECOND_MANUFACTURE_FLAG, PCI);

        if (isPci == isTci) {
            return CC_LIB_OTP_TCI_PCI_ERROR;
        }

        /* verify HUK error by reading ERR_HUK_ZERO_CNT in CC_LCS_REG_REG_OFFSET register
         * relevant only to DM or SE life cycle */
        CC_UTIL_IS_OTP_KEY_ERROR(regVal, HUK);
        if (regVal != 0) {
            return CC_LIB_OTP_HUK_ERROR;
        }
    }

    return CC_LIB_RET_OK;
}


/************************ Public Functions ***********************************/

/*!
 * Common TEE initialisations for both cold and warm boot.
 * This function is the place for CC initialisations that are required both
 * during CC_LibInit() and CC_PmResume()
 */
int CC_CommonInit(void)
{
    int rc = 0;

    /* verify OTP loading */
    rc = CC_OtpLoadingVerify();
    if (rc != CC_LIB_RET_OK) {
        return rc;
    }

#ifdef BIG__ENDIAN
    /* Set DMA endianness to big */
    CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_RGF_ENDIAN), 0xCCUL);
#else /* LITTLE__ENDIAN */
    CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_RGF_ENDIAN), 0x00UL);
#endif

    InitCompletion();

    return rc;
}


/*!
 * TEE (Trusted Execution Environment) entry point.
 * Init CryptoCell for TEE.
 *
 * @param [in] f_rng        - pointer to DRBG function
 * @param [in/out] p_rng   - Pointer to the random context
 *
 * \return CClibRetCode_t one of the error codes defined in cc_lib.h
 */
CClibRetCode_t CC_LibInit(CCRndGenerateVectWorkFunc_t *f_rng,
                          void                  *p_rng,
                          CCTrngWorkBuff_t      *pTrngWorkBuff,
                          CClibCertType_t       certType,
                          CCCertKatContext_t    *pCertCtx,
                          CCAxiFields_t         *pAxiFields)
{
    int rc = CC_LIB_RET_OK;
    uint32_t pidReg[CC_PID_SIZE_WORDS] = { 0 };
    uint32_t cidReg[CC_CID_SIZE_WORDS] = { 0 };
    uint32_t imrValue = 0;
    uint32_t imrMask = 0;
    uint32_t removedEngines;
    uint32_t fatalErrorIsSet = 0;
    uint32_t secureDisableIsSet = 0;

    const uint32_t pidVal[CC_PID_SIZE_WORDS] = { CC_PID_0_VAL,
            CC_PID_1_VAL,
            CC_PID_2_VAL,
            CC_PID_3_VAL & ~(CC_PID_3_IGNORE_MASK),
            CC_PID_4_VAL };

    const uint32_t cidVal[CC_CID_SIZE_WORDS] = { CC_CID_0_VAL,
            CC_CID_1_VAL,
            CC_CID_2_VAL,
            CC_CID_3_VAL };

    /* Check parameters */
    /* Pointers*/

    if (pTrngWorkBuff == NULL) {
        return CC_LIB_RET_EINVAL;
    }
    if ((f_rng == NULL) || (p_rng == NULL)) {
        return CC_LIB_RET_EINVAL;
    }
    if (pAxiFields == NULL) {
        return CC_LIB_RET_EINVAL;
    }

    /* Certification Type */
    if ((certType < CC_LIB_CERT_TYPE_NONE) || (certType > CC_LIB_CERT_TYPE_CHINESE)) {
        return CC_LIB_RET_EINVAL_CERT_TYPE;
    }

    rc = CC_PalInit();
    if (rc != CC_LIB_RET_OK) {
        rc = CC_LIB_RET_PAL;
        goto InitErr;
    }

    rc = CC_HalInit();
    if (rc != CC_LIB_RET_OK) {
        rc = CC_LIB_RET_HAL;
        goto InitErr1;
    }

    /* The function should refuse to operate if the Fatal Error bit is set */
    CC_UTIL_IS_FATAL_ERROR_SET(fatalErrorIsSet);
    if (fatalErrorIsSet == FATAL_ERROR_FLAG_SET) {
        rc = CC_LIB_FATAL_ERR_IS_LOCKED_ERR;
        goto InitErr2;
    }

    /* The function should initialize only the basic crypto modules
     *  if the secure disable indication is set */
    CC_UTIL_IS_SECURE_DISABLE_FLAG_SET(secureDisableIsSet);


    /* verify peripheral ID (PIDR) */
    pidReg[0] = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, PERIPHERAL_ID_0));
    pidReg[1] = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, PERIPHERAL_ID_1));
    pidReg[2] = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, PERIPHERAL_ID_2));
    /* The verification should skip the customer fields (REVAND ( bits [3:0]) and CMOD (bits [7:4]) in PIDR[3]) */
    pidReg[3] = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, PERIPHERAL_ID_3)) & ~(CC_PID_3_IGNORE_MASK);
    pidReg[4] = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, PERIPHERAL_ID_4));
    if (CC_PalMemCmp((uint8_t*)pidVal, (uint8_t*)pidReg, sizeof(pidVal)) != 0) {
        rc = CC_LIB_RET_EINVAL_PIDR;
        goto InitErr2;
    }

    /* verify component ID (CIDR) */
    cidReg[0] = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, COMPONENT_ID_0));
    cidReg[1] = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, COMPONENT_ID_1));
    cidReg[2] = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, COMPONENT_ID_2));
    cidReg[3] = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, COMPONENT_ID_3));
    if (CC_PalMemCmp((uint8_t*)cidVal, (uint8_t*)cidReg, sizeof(cidVal)) != 0) {
        rc = CC_LIB_RET_EINVAL_CIDR;
        goto InitErr2;
    }

    /* verify hw is configured to slim
     * verification is done by checking all engines and the OTP are enabled */
    removedEngines = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_REMOVE_INPUT_PINS));
    if (removedEngines != CC_HW_ENGINES_FULL_CONFIG) {
        rc = CC_LIB_INCORRECT_HW_VERSION_SLIM_VS_FULL;
        goto InitErr2;
    }

    /* reset low resolution secure timer */
    CC_UtilResetLowResTimer();

    /*wait for reset to be completed - by polling on the NVM idle register*/
    CC_LIB_WAIT_ON_NVM_IDLE_BIT();

    /* init interrupt and register interrupt handler */
    rc = CC_PalInitIrq(CC_InterruptHandler);
    if (rc != CC_LIB_RET_OK) {
        rc = CC_LIB_RET_PAL;
        goto InitErr2;
    }

    /* unmask appropriate interrupts */
    imrValue = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_RGF_IMR));

    CC_REG_FLD_SET(HOST_RGF, HOST_RGF_IMR, REE_KS_OPERATION_INDICATION_MASK, imrMask, 1);
    CC_REG_FLD_SET(HOST_RGF, HOST_RGF_IMR, AXIM_COMP_INT_MASK, imrMask, 1);
    CC_REG_FLD_SET(HOST_RGF, HOST_RGF_IMR, AXI_ERR_MASK, imrMask, 1);
    CC_REG_FLD_SET(HOST_RGF, HOST_RGF_IMR, RNG_INT_MASK, imrMask, 1);
#ifdef CC_SUPPORT_FIPS
    CC_REG_FLD_SET(HOST_RGF, HOST_RGF_IMR, GPR0_MASK, imrMask, 1);
#endif
    CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_RGF_IMR), imrValue & (~imrMask));

    /* init PAL wait for interrupt completion */
    CC_PalInitWaitInterruptComp(CC_HAL_IRQ_AXIM_COMPLETE);
    CC_PalInitWaitInterruptComp(CC_HAL_IRQ_RNG);

    /* set axi parameters */
    rc = CC_HalSetCacheParams (pAxiFields);
    if (rc != CC_LIB_RET_OK) {
        rc = CC_LIB_RET_CACHE_PARAMS_ERROR;
        goto InitErr3;
    }

    /* common initializations */
    rc = CC_CommonInit();
    if (rc != CC_LIB_RET_OK) {
        goto InitErr3;
    }

    rc = SymDriverAdaptorModuleInit();
    if (rc != CC_LIB_RET_OK) {
        rc = CC_LIB_RET_COMPLETION;  // check
        goto InitErr3;
    }

    if (secureDisableIsSet == CC_FALSE) {
        rc = RpmbSymDriverAdaptorModuleInit();
        if (rc != CC_LIB_RET_OK) {
            rc = CC_LIB_RET_COMPLETION;
            goto InitErr3;
        }
    }

    CC_PAL_PERF_INIT();

    /* clear SRAM sensitive data: PKA, TRNG source and symmetric context */
    ClearSram();

    if (secureDisableIsSet == CC_TRUE) {
        /* Secure Disable - can't run DRBG and FIPS and CERT tests */
        return CC_LIB_RET_OK;
    }

#ifdef CC_SUPPORT_FIPS
    rc = FipsSetState((certType == CC_LIB_CERT_TYPE_FIPS) ? CC_FIPS_STATE_SUPPORTED : CC_FIPS_STATE_NOT_SUPPORTED);
    if (rc != CC_OK) {
        rc = CC_LIB_RET_EFIPS;
        goto InitErr3;
    }
    rc = FipsRunPowerUpTest(f_rng, p_rng, pCertCtx);
    if (rc != CC_OK) {
        rc = CC_LIB_RET_EFIPS;
        goto InitErr;   /* do not terminate hal and pal, since CC api
            should work and return error */
    }
#endif

    /* Initialize RND module */
    CC_PalMemSetZero(p_rng, sizeof(CCRndState_t));
    *f_rng=NULL;

    rc = RndStartupTest(p_rng, pTrngWorkBuff);
    if (rc != CC_OK) {
        rc = CC_LIB_RET_RND_INST_ERR;
        goto InitErr3;
    }

    CC_PalMemSetZero(p_rng, sizeof(CCRndState_t));
    *f_rng=NULL;
    rc = CC_RndInstantiation(f_rng, p_rng, pTrngWorkBuff);
    if (rc != CC_OK) {
        rc = CC_LIB_RET_RND_INST_ERR;
        goto InitErr3;
    }

    *f_rng = CC_RndGenerateVector;

    /* in case of RMA LCS set the KDR to random value */
    rc = InitHukRma(p_rng);
    if (rc != 0) {
        rc = CC_LIB_RET_EINVAL;
        goto InitErr3;
    }

#ifdef CC_SUPPORT_CH_CERT
    rc = ChCertSetState((certType == CC_LIB_CERT_TYPE_CHINESE) ? CC_CH_CERT_STATE_SUPPORTED : CC_CH_CERT_STATE_NOT_SUPPORTED);
    if (rc != CC_OK) {
        rc = CC_LIB_RET_ECHCERT;
        goto InitErr3;
    }
    rc = ChCertRunPowerUpTest(pCertCtx);
    if (rc != CC_OK) {
        rc = CC_LIB_RET_ECHCERT;
        goto InitErr;   /* do not terminate hal and pal, since CC API should work and return error */
    }

    rc = CC_CH_CERT_CRYPTO_USAGE_SET_APPROVED();
    if (rc != CC_OK) {
        rc = CC_LIB_RET_ECHCERT;
        goto InitErr3;
    }
#else
    CC_UNUSED_PARAM(certType);
    CC_UNUSED_PARAM(pCertCtx);
#endif

#ifdef CC_SUPPORT_FIPS
    rc = FipsSetState(CC_FIPS_STATE_SUSPENDED);
    if (rc != CC_OK) {
        rc = CC_LIB_RET_EFIPS;
        goto InitErr3;
    }
    rc = CC_FIPS_CRYPTO_USAGE_SET_NON_APPROVED();
    if (rc != CC_OK) {
        rc = CC_LIB_RET_EFIPS;
        goto InitErr3;
    }
#endif  // CC_SUPPORT_FIPS

return CC_LIB_RET_OK;

InitErr3:
    CC_PalFinishIrq();

InitErr2:
    CC_HalTerminate();

InitErr1:
    CC_PalTerminate();

InitErr:
    return (CClibRetCode_t)rc;
}

/*!
 * Common TEE finalisations for both cold and warm boot.
 * This function is the place for CC finalisations that are required both
 * during CC_LibFini() and CC_PmSuspend()
 */
void CC_CommonFini(void)
{
    return;
}

/*!
 * TEE (Trusted Execution Environment) exit point.
 * Finalize CryptoCell for TEE operation, release associated resources.
 *                                                                    .
 * @f_rng[in]      - Pointer to the DRBG function.
 * @p_rng[in/out]  - Pointer to the RND context buffer.
 */
void CC_LibFini(CCRndGenerateVectWorkFunc_t *f_rng, void *p_rng)
{
    uint32_t imrValue;
    uint32_t mask;

    /* common finalisations */
    CC_CommonFini();

    CC_RndUnInstantiation(f_rng, p_rng);
    SymDriverAdaptorModuleTerminate();
    RpmbSymDriverAdaptorModuleTerminate();

    /* mask appropriate interrupts and finish interrupt handling */
    imrValue = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_RGF_IMR));
    mask = imrValue | CC_CPP_INTERRUPT_ENABLE_MASK;
#ifdef CC_SUPPORT_FIPS
    mask |= CC_GPR0_INTERRUPT_ENABLE_MASK;
#endif
    CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_RGF_IMR), mask);

    CC_PalFinishWaitInterruptComp(CC_HAL_IRQ_AXIM_COMPLETE);
    CC_PalFinishWaitInterruptComp(CC_HAL_IRQ_RNG);

    CC_PalFinishIrq();

    CC_HalTerminate();
    CC_PalTerminate();
    CC_PAL_PERF_FIN();
}

