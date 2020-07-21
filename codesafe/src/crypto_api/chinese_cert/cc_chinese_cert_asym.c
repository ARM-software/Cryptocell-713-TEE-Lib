/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include "cc_chinese_cert.h"
#include "cc_chinese_cert_defs.h"
#include "cc_chinese_cert_asym_data.h"
#include "cc_pal_types.h"
#include "cc_pal_mem.h"
#include "cc_sm2.h"
#include "cc_ecpki_build.h"
#include "cc_ecpki_domain_sm2.h"

/*********************** Definitions ***********************/
#define CH_CERT_PUT_ASYM_MAX_TEST_DATA_SIZE     64
#define CH_CERT_ASYM_MAX_TEST_KEY_SIZE          64
#define CH_CERT_ASYM_PUT_MAX_TEST_ID_SIZE       32


/************************* Structs *************************/
typedef struct _ChCertSm2Data {
    uint8_t         publicKey[CH_CERT_PUT_ASYM_MAX_TEST_DATA_SIZE + 1];
    size_t          publicKeySize;
    uint8_t         privateKey[CH_CERT_PUT_ASYM_MAX_TEST_DATA_SIZE];
    size_t          privateKeySize;
    const char      id[CH_CERT_ASYM_PUT_MAX_TEST_ID_SIZE];
    size_t          id_len;
    uint8_t         dataIn[CH_CERT_ASYM_MAX_TEST_KEY_SIZE];
    size_t          dataInSize;
    size_t          dataOutSize;
    CCChCertError_t error;
} ChCertSm2Data;


/*** Test data tables ***/

/*********************** SM2 ***********************/
static const ChCertSm2Data ChCertSm2DataTable[] = {
        { CH_CERT_SM2_PUBLIC_KEY1, CH_CERT_SM2_PUBLIC_KEY1_SIZE, CH_CERT_SM2_PRIVATE_KEY1, CH_CERT_SM2_PRIVATE_KEY1_SIZE, CH_CERT_SM2_ID_A1, CH_CERT_SM2_ID_A1_SIZE, CH_CERT_SM2_SIGN_INPUT1, CH_CERT_SM2_SIGN_INPUT1_SIZE, CH_CERT_SM2_SIGN_OUT1_SIZE, CC_TEE_CH_CERT_ERROR_SM2_SIGN_PUT},
};
#define CH_CERT_SM2_NUM_OF_TESTS        (sizeof(ChCertSm2DataTable) / sizeof(ChCertSm2Data))


/*********************** SM2 CONDITIONAL ***********************/
CCError_t CC_ChCertSm2ConditionalTest(CCRndGenerateVectWorkFunc_t f_rng,
                                      void                        *p_rng,
                                      CCEcpkiUserPrivKey_t    *pUserPrivKey,
                                      CCEcpkiUserPublKey_t    *pUserPublKey,
                                      CCSm2KeyGenCHCertContext_t  *pCHCertCtx)
{

    CCError_t error = CC_OK;
    CCChCertError_t  chCertError = CC_TEE_CH_CERT_ERROR_OK;
    ChCertSm2Data*  sm2Data = NULL;
    uint32_t        msgDigest[CC_SM3_RESULT_SIZE_IN_WORDS];
    size_t          msgDigestSize = CC_SM3_RESULT_SIZE_IN_WORDS;

    /* actual output */
    size_t  sm2SignResultSizeActual = CH_CERT_SM2_SIGN_OUT1_SIZE;
    uint8_t sm2SignResultBuffActual[CH_CERT_SM2_SIGN_OUT1_SIZE];

    sm2Data = (ChCertSm2Data*)&ChCertSm2DataTable[0];
    error = CC_Sm2ComputeMessageDigest(pUserPublKey, sm2Data->id, sm2Data->id_len, sm2Data->dataIn, sm2Data->dataInSize,
                                       pCHCertCtx->workBuff,
                                       sizeof(pCHCertCtx->workBuff),
                                       msgDigest, &msgDigestSize );
    if (error != CC_OK) {
        chCertError = CC_TEE_CH_CERT_ERROR_SM2_KEY_GEN_COND;
        goto End;
    }

    error =  CC_Sm2Sign ( f_rng,
                          p_rng,
                          pUserPrivKey,
                          msgDigest,
                          msgDigestSize,
                          sm2SignResultBuffActual,
                          &sm2SignResultSizeActual );
    if (error != CC_OK) {
        chCertError = CC_TEE_CH_CERT_ERROR_SM2_KEY_GEN_COND;
        goto End;
    }

    error = CC_Sm2Verify(pUserPublKey, sm2SignResultBuffActual, sm2SignResultSizeActual, msgDigest, msgDigestSize);
    if (error != CC_OK) {
        chCertError = CC_TEE_CH_CERT_ERROR_SM2_KEY_GEN_COND;
        goto End;
    }

    ChCertSetTrace(CC_CH_CERT_TRACE_SM2_COND);

End:
    if (chCertError != CC_TEE_CH_CERT_ERROR_OK) {
        ChCertSetError(chCertError);
        error = CC_CH_CERT_ERROR;
    }
    return error;
}/* END OF CC_ChinieseCertSm2ConditionalTest */


/*********************** SM2 KAT ***********************/


CCChCertError_t CC_ChCertSm2SignVerify(CCSm2FipsKatContext_t *certSm2Ctx)
{
    CCError_t error = CC_OK;
    ChCertSm2Data*  sm2Data = NULL;
    uint32_t        i;
    uint32_t        msgDigest[CC_SM3_RESULT_SIZE_IN_WORDS];
    size_t          msgDigestSize = CC_SM3_RESULT_SIZE_IN_WORDS;
    size_t          workBufferSize = 2 + CC_SM2_MODULE_LENGTH_IN_BYTES*4 + CC_SM2_ORDER_LENGTH_IN_BYTES*2 + CERT_SM2_DEFAULT_INPUT_AND_ID_SIZE;
    CCEcpkiUserPublKey_t    publicKey;
    CCEcpkiUserPrivKey_t    privateKey;

    /* actual output */
    size_t  sm2SignResultSizeActual = CH_CERT_SM2_SIGN_OUT1_SIZE;
    uint8_t sm2SignResultBuffActual[CH_CERT_SM2_SIGN_OUT1_SIZE];

    for (i = 0; i < CH_CERT_SM2_NUM_OF_TESTS; ++i) {
        sm2Data = (ChCertSm2Data*)&ChCertSm2DataTable[i];
        error = CC_EcpkiPublKeyBuildAndCheck (CC_EcpkiGetSm2Domain(), sm2Data->publicKey, sm2Data->publicKeySize,
                                              CheckPointersAndSizesOnly, &publicKey, NULL);
        if (error != CC_OK) {
            return sm2Data->error;
        }

        error = CC_EcpkiPrivKeyBuild(CC_EcpkiGetSm2Domain(), sm2Data->privateKey,  sm2Data->privateKeySize, &privateKey);
        if (error != CC_OK) {
            return sm2Data->error;
        }
        error = CC_Sm2ComputeMessageDigest(&publicKey, sm2Data->id, sm2Data->id_len, sm2Data->dataIn, sm2Data->dataInSize,
                                           certSm2Ctx->workBuff,
                                           workBufferSize,
                                           msgDigest, &msgDigestSize );
        if (error != CC_OK) {
            return sm2Data->error;
        }

        error =  CC_Sm2Sign ( certSm2Ctx->f_rng,
                              certSm2Ctx->p_rng,
                              &privateKey,
                              msgDigest,
                              msgDigestSize,
                              sm2SignResultBuffActual,
                              &sm2SignResultSizeActual );
        if (error != CC_OK) {
            return sm2Data->error;
        }

        error = CC_Sm2Verify(&publicKey, sm2SignResultBuffActual, sm2SignResultSizeActual, msgDigest, msgDigestSize);
        if (error != CC_OK) {
            return sm2Data->error;
        }
    }

    ChCertSetTrace(CC_CH_CERT_TRACE_SM2_PUT);

    return CC_TEE_CH_CERT_ERROR_OK;
}



CCChCertError_t CC_ChCertSm2RunTests(CCCertKatContext_t  *pCertCtx){
    CCError_t error = CC_OK;
    error = CC_ChCertSm2SignVerify(&(pCertCtx->fipsSm2Ctx));
    if (error != CC_OK) {
        return CC_TEE_CH_CERT_ERROR_SM2_SIGN_PUT;
    }

    return error;
}
