/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */



/************* Include Files ****************/
#include "cc_pal_init.h"
#include "cc_pal_dma_plat.h"
#include "cc_pal_log.h"
#include "dx_reg_base_host.h"
#include "cc_pal_mutex.h"
#include "cc_pal_mem.h"
#include "cc_pal_abort.h"
#include "cc_pal_dma_plat.h"
#include "cc_pal_pm.h"
#include "cc_pal_interrupt_ctrl.h"

extern CC_PalMutex CCSymCryptoMutex;
extern CC_PalMutex CCAsymCryptoMutex;
extern CC_PalMutex *pCCRndCryptoMutex;
extern CC_PalMutex CCRndCryptoMutex;
#ifndef CC_IOT
    #ifdef CC_SUPPORT_FULL_PROJECT
    extern CC_PalMutex *pCCGenVecMutex;
    extern CC_PalMutex CCFipsMutex;
    #else // SLIM
    extern CC_PalMutex CCChCertMutex;
    #endif
#endif

#ifdef CC_IOT
extern CC_PalMutex CCApbFilteringRegMutex;
#endif

/**
 * @brief   PAL layer entry point.
 *          The function initializes customer platform sub components,
 *           such as memory mapping used later by CRYS to get physical contiguous memory.
 *
 *
 * @return Virtual start address of contiguous memory
 */
int CC_PalInit(void)
{
    int rc = 0;

    CC_PalLogInit();

#ifndef CMPU_UTIL
    rc = CC_PalDmaInit(PAL_WORKSPACE_MEM_SIZE, PAL_WORKSPACE_MEM_BASE_ADDR);
    if (rc != 0) {
        CC_PAL_LOG_ERR("Failed CC_PalDmaInit 0x%x", rc);
        return 1;
    }
#endif

#ifdef CC_IOT
    /* Initialize power management module */
    CC_PalPowerSaveModeInit();
#endif

    /* Initialize mutex that protects shared memory and crypto access */
    rc = CC_PalMutexCreate(&CCSymCryptoMutex);
    if (rc != 0) {
        CC_PalAbort("Fail to create SYM mutex\n");
    }
    /* Initialize mutex that protects shared memory and crypto access */
    rc = CC_PalMutexCreate(&CCAsymCryptoMutex);
    if (rc != 0) {
        CC_PalAbort("Fail to create ASYM mutex\n");
    }
    /* Initialize mutex that protects shared memory and crypto access */
    rc = CC_PalMutexCreate(&CCRndCryptoMutex);
    if (rc != 0) {
        CC_PalAbort("Fail to create RND mutex\n");
    }

    pCCRndCryptoMutex = &CCRndCryptoMutex;
#ifndef CC_IOT
    #ifdef CC_SUPPORT_FULL_PROJECT
    /* Initialize mutex that protects fips access */
    rc = CC_PalMutexCreate(&CCFipsMutex);
    if (rc != 0) {
        CC_PalAbort("Fail to create FIPS mutex\n");
    }

    pCCGenVecMutex = &CCRndCryptoMutex;
    #else //SLIM
    /* Initialize mutex that protects Chinese certification access */
    rc = CC_PalMutexCreate(&CCChCertMutex);
    if (rc != 0) {
        CC_PalAbort("Fail to create Chinese Certification mutex\n");
    }
    #endif
#endif

#ifdef CC_IOT
    /* Initialize mutex that protects APBC access */
    rc = CC_PalMutexCreate(&CCApbFilteringRegMutex);
    if (rc != 0) {
        CC_PalAbort("Fail to create APBC mutex\n");
    }
#endif

    return 0;
}


/**
 * @brief   PAL layer entry point.
 *          The function initializes customer platform sub components,
 *           such as memory mapping used later by CRYS to get physical contiguous memory.
 *
 *
 * @return None
 */
void CC_PalTerminate(void)
{
    CCError_t err = 0;

#ifndef CMPU_UTIL
    CC_PalDmaTerminate();
#endif

    err = CC_PalMutexDestroy(&CCSymCryptoMutex);
    if (err != 0){
        CC_PAL_LOG_DEBUG("failed to destroy mutex CCSymCryptoMutex\n");
    }
    CC_PalMemSetZero(&CCSymCryptoMutex, sizeof(CC_PalMutex));

    err = CC_PalMutexDestroy(&CCAsymCryptoMutex);
    if (err != 0){
        CC_PAL_LOG_DEBUG("failed to destroy mutex CCAsymCryptoMutex\n");
    }
    CC_PalMemSetZero(&CCAsymCryptoMutex, sizeof(CC_PalMutex));

    err = CC_PalMutexDestroy(&CCRndCryptoMutex);
    if (err != 0){
        CC_PAL_LOG_DEBUG("failed to destroy mutex CCRndCryptoMutex\n");
    }
    CC_PalMemSetZero(&CCRndCryptoMutex, sizeof(CC_PalMutex));

#ifndef CC_IOT
    #ifdef CC_SUPPORT_FULL_PROJECT
    err = CC_PalMutexDestroy(&CCFipsMutex);
    if (err != 0){
        CC_PAL_LOG_DEBUG("failed to destroy mutex CCFipsMutex\n");
    }
    CC_PalMemSetZero(&CCFipsMutex, sizeof(CC_PalMutex));
    #else// SLIM
    err = CC_PalMutexDestroy(&CCChCertMutex);
    if (err != 0){
        CC_PAL_LOG_DEBUG("failed to destroy mutex CCChCertMutex\n");
    }
    CC_PalMemSetZero(&CCChCertMutex, sizeof(CC_PalMutex));
    #endif
#endif

#ifdef CC_IOT
    err = CC_PalMutexDestroy(&CCApbFilteringRegMutex);
    if (err != 0){
        CC_PAL_LOG_DEBUG("failed to destroy mutex CCApbFilteringRegMutex\n");
    }
    CC_PalMemSetZero(&CCApbFilteringRegMutex, sizeof(CC_PalMutex));
#endif
}
