/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include <string.h>
#include <unistd.h>

#include "cc_lib.h"
#include "cc_regs.h"
#include "test_proj.h"
#include "test_proj_map.h"
#include "test_proj_cclib.h"
#include "tests_log.h"
#include "tests_utils.h"
#include "test_pal_mem.h"

#ifdef CC_SUPPORT_FIPS
#include "cc_fips.h"
#endif

#ifdef CC_SUPPORT_CH_CERT
#include "cc_chinese_cert.h"
#endif

#ifdef CC_SUPPORT_FULL_PROJECT
#include "cc_rnd_common.h"
#include "cc_rnd.h"
#include "test_pal_mem.h"
//#include "ree_include/dx_host.h"
#include "tee_include/dx_host.h"
#include "test_proj_rnd.h"
#endif

#define NOT_INITIATED   0
#define INITIATED       1

/* This counter keeps track of init vs fin. to better understand when a test calls init/fin twice in a row. */
/* This potentially can save a lot of debugging time */
static int init_ctr = 0;

CCError_t CC_RndGenerateVectorKAT(void *rngState_vptr, uint8_t *out_ptr, /*out*/
                            size_t outSizeBytes); /*in*/

#ifdef CC_SUPPORT_FULL_PROJECT
CCRndState_t *pRndState_proj;
CCRndGenerateVectWorkFunc_t pRndFunc_proj;
CCTrngWorkBuff_t  *pTrngWorkBuff_proj;
int Test_Proj_CC_LibInit_Wrap(void){
    CCAxiFields_t  axiFields;
    int rc;

    /* Allocate buffers*/
    CCCertKatContext_t *certCtx = NULL;

   /* set cache parameters */
   axiFields.AXIM_ACE_CONST.bitField.ARDOMAIN = 0x0;
   axiFields.AXIM_ACE_CONST.bitField.AWDOMAIN = 0x0;
   axiFields.AXIM_ACE_CONST.bitField.ARBAR = 0x0;
   axiFields.AXIM_ACE_CONST.bitField.AWBAR = 0x0;
   axiFields.AXIM_ACE_CONST.bitField.ARSNOOP = 0x0;
   axiFields.AXIM_ACE_CONST.bitField.AWSNOOP_NOT_ALIGNED = 0x0;
   axiFields.AXIM_ACE_CONST.bitField.AWSNOOP_ALIGNED = 0x0;
   axiFields.AXIM_ACE_CONST.bitField.AWADDR_NOT_MASKED = 0x0;
   axiFields.AXIM_ACE_CONST.bitField.AWLEN_VAL = 0x0;

   axiFields.AXIM_CACHE_PARAMS.bitField.ARCACHE = 0x0;
   axiFields.AXIM_CACHE_PARAMS.bitField.AWCACHE = 0x0;
   axiFields.AXIM_CACHE_PARAMS.bitField.AWCACHE_LAST = 0x0;

    if (init_ctr != NOT_INITIATED) {
        TEST_LOG_ERROR("Init is called twice in a row\n");
        return 1;
    }
    init_ctr = INITIATED;

    pTrngWorkBuff_proj = (CCTrngWorkBuff_t *)Test_PalDMAContigBufferAlloc(sizeof(CCTrngWorkBuff_t));
    certCtx = (CCCertKatContext_t *)Test_PalDMAContigBufferAlloc(sizeof(CCCertKatContext_t));
    if ( (pTrngWorkBuff_proj == NULL) || (certCtx == NULL)) {
        return 1;
    }
    pRndState_proj = (CCRndState_t *)Test_PalDMAContigBufferAlloc(sizeof(CCRndState_t));
    if (pRndState_proj == NULL) {
        return 1;
    }

    /* Assign drbg function to certification context */
#ifdef CC_SUPPORT_CH_CERT
    certCtx->fipsSm2Ctx.f_rng = CC_RndGenerateVector;
    certCtx->fipsSm2Ctx.p_rng = pRndState_proj;
#endif
    /* set REE error value to be REE ok, same value as CC_FIPS_SYNC_REE_STATUS|CC_FIPS_SYNC_MODULE_OK */
    for (int i = 0; i < TEST_PROJ_RND_TRNG_FE_RETRY; i++) {
        /* in case of CC_LibInit random failure enable more than 1 run */
        rc = CC_LibInit(&pRndFunc_proj, pRndState_proj, pTrngWorkBuff_proj, CC_LIB_CERT_TYPE_NONE, certCtx, &axiFields);
        if(rc != CC_LIB_RET_RND_INST_ERR) {
            break;
        }
        TEST_LOG_ERROR("CC_LIB_RET_RND_INST_ERR CC_LibInit error, try to rerun");
    }
    if (rc != 0) {
        TEST_LOG_ERROR("Failed to CC_LibInit 0x%x", rc);
        init_ctr = NOT_INITIATED;
        Test_PalDMAContigBufferFree(pRndState_proj);
        Test_PalDMAContigBufferFree(pTrngWorkBuff_proj);
        goto End;
    }

#ifdef CC_SUPPORT_FIPS
    rc = Test_ProjReeMap();
    if (rc != 0) {
        TEST_LOG_ERROR("Failed to Test_ProjReeMap 0x%x", rc);
    }

    if (rc == 0) {
        rc = Test_ProjSetReeFipsError((0x4|0x0), CC_FIPS_STATE_NOT_SUPPORTED);
    }
#endif /* CC_SUPPORT_FIPS */

End:
    Test_PalDMAContigBufferFree(certCtx);
    return rc;
}
#else
int Test_Proj_CC_LibInit_Wrap(void)
{
    int rc;
    CCCertKatContext_t *certCtx = NULL;
    CCAxiFields_t  axiFields;
#ifdef CC_SUPPORT_CH_CERT
    uint8_t tmpState; /* State cannot be NULL */
#endif

    if (init_ctr != NOT_INITIATED) {
        TEST_LOG_ERROR("Init is called twice in a row\n");
        return 1;
    }
    init_ctr = INITIATED;

    certCtx = (CCCertKatContext_t *) Test_PalDMAContigBufferAlloc(sizeof(CCCertKatContext_t));
    if (certCtx == NULL) {
        return 1;
    }

    /* set cache parameters */
    axiFields.AXIM_ACE_CONST.bitField.ARDOMAIN = 0x0;
    axiFields.AXIM_ACE_CONST.bitField.AWDOMAIN = 0x0;
    axiFields.AXIM_ACE_CONST.bitField.ARBAR = 0x0;
    axiFields.AXIM_ACE_CONST.bitField.AWBAR = 0x0;
    axiFields.AXIM_ACE_CONST.bitField.ARSNOOP = 0x0;
    axiFields.AXIM_ACE_CONST.bitField.AWSNOOP_NOT_ALIGNED = 0x0;
    axiFields.AXIM_ACE_CONST.bitField.AWSNOOP_ALIGNED = 0x0;
    axiFields.AXIM_ACE_CONST.bitField.AWADDR_NOT_MASKED = 0x0;
    axiFields.AXIM_ACE_CONST.bitField.AWLEN_VAL = 0x0;

    axiFields.AXIM_CACHE_PARAMS.bitField.ARCACHE = 0x0;
    axiFields.AXIM_CACHE_PARAMS.bitField.AWCACHE = 0x0;
    axiFields.AXIM_CACHE_PARAMS.bitField.AWCACHE_LAST = 0x0;

#ifdef CC_SUPPORT_CH_CERT
    /* Assign drbg function to certification context */
    certCtx->fipsSm2Ctx.f_rng = CC_RndGenerateVectorKAT;
    certCtx->fipsSm2Ctx.p_rng = (void *)&tmpState;
#endif
    /* set REE error value to be REE ok, same value as CC_FIPS_SYNC_REE_STATUS|CC_FIPS_SYNC_MODULE_OK */
    rc = CC_LibInit(false, certCtx, &axiFields);
    Test_PalDMAContigBufferFree(certCtx);

    return rc;
}
#endif /* CC_SUPPORT_FULL_PROJECT */

#ifdef CC_SUPPORT_FULL_PROJECT
void Test_Proj_CC_LibFini_Wrap(void)
{
    if (init_ctr != INITIATED) {
        TEST_LOG_ERROR("trying to call finish function on a uninitialized proj lib\n");
        do { init_ctr = INITIATED; } while (init_ctr == INITIATED);
        return;
    }
    init_ctr = NOT_INITIATED;

#ifdef CC_SUPPORT_FIPS
    /* set REE error value to be REE ok, same value as CC_FIPS_SYNC_REE_STATUS|CC_FIPS_SYNC_MODULE_OK */
    Test_ProjReeUnmap();
#endif /* CC_SUPPORT_FIPS */
    CC_LibFini(&pRndFunc_proj, pRndState_proj);
    Test_PalDMAContigBufferFree(pRndState_proj);
    Test_PalDMAContigBufferFree(pTrngWorkBuff_proj);
 }

#ifdef CC_SUPPORT_FIPS
int Test_ProjSetReeFipsError(uint32_t reeError, CCFipsState_t expfipsState)
{
    uint32_t rc;
    CCFipsState_t fipsState;
    uint32_t maxRetries = 20;
    TEST_WRITE_REE_REG(CC_REG_OFFSET(HOST_RGF, HOST_GPR), (unsigned int)(reeError));

    TEST_LOG_DEBUG("waiting for fips stat to be %d\n", expfipsState);
    do {
        rc = CC_FipsStateGet(&fipsState, NULL);
        if (rc != 0) {
            return 1;
        }
        usleep(100);    // wait 100 milisecond
        TEST_LOG_DEBUG("fips stat is %d\n", fipsState);
    }while ((fipsState != expfipsState) && (maxRetries-- > 0));
    if ((maxRetries == 0) && (fipsState != expfipsState)) {
        return 1;
    }
    TEST_LOG_INFO("done OK\n");
    return 0;
}
#endif /* CC_SUPPORT_FIPS */
#else
void Test_Proj_CC_LibFini_Wrap(void)
{
    if (init_ctr != INITIATED) {
        TEST_LOG_ERROR("trying to call finish function on a uninitialized proj lib\n");
        do { init_ctr = INITIATED; } while (init_ctr == INITIATED);
        return;
    }
    init_ctr = NOT_INITIATED;

    /* set REE error value to be REE ok, same value as CC_FIPS_SYNC_REE_STATUS|CC_FIPS_SYNC_MODULE_OK */
    CC_LibFini();
}
#endif /* CC_SUPPORT_FIPS */

CCError_t CC_RndGenerateVectorKAT(void *rngState_vptr, uint8_t *out_ptr, /*out*/
                            size_t outSizeBytes) /*in*/
{
    TEST_UNUSED(rngState_vptr);
    Tests_InitRand();
    Tests_FillRandBuf(out_ptr, outSizeBytes);
    return CC_OK;
}
