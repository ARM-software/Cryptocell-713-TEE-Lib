/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef  _CC_CH_CERT_DEFS_H
#define  _CC_CH_CERT_DEFS_H

#include "cc_chinese_cert.h"
#include "cc_chinese_cert_error.h"
#include "cc_cert_ctx.h"
#include "cc_ecpki_domain_sm2.h"

typedef enum CCChCertTrace_t {
    CC_CH_CERT_TRACE_NONE           = 0x0,
    CC_CH_CERT_TRACE_SM4_PUT        = 0x1,
    CC_CH_CERT_TRACE_SM3_PUT        = 0x2,
    CC_CH_CERT_TRACE_SM2_PUT        = 0x4,
    CC_CH_CERT_TRACE_SM2_COND       = 0x8,
    CC_CH_CERT_TRACE_RESERVE32B     = INT32_MAX
}CCChCertTrace_t;

typedef enum CC_ChCertSyncStatus{
    CC_CH_CERT_SYNC_MODULE_OK          = 0x0,
    CC_CH_CERT_SYNC_MODULE_ERROR       = 0x1,
    CC_CH_CERT_SYNC_REE_STATUS         = 0x4,
    CC_CH_CERT_SYNC_TEE_STATUS         = 0x8,
    CC_CH_CERT_SYNC_STATUS_RESERVE32B  = INT32_MAX
}CCChCertSyncStatus_t;

#ifdef CC_SUPPORT_CH_CERT

typedef struct CC_ChCertStateData {
    CCChCertState_t state;
    CCChCertError_t error;
    CCChCertTrace_t trace;
}CCChCertStateData_t;

// used for every Chinese API. If CH_CERT error is on, return with CH_CERT error code
#define CHECK_AND_RETURN_ERR_UPON_CH_CERT_ERROR() {\
    CCChCertState_t   chCertState; \
    if (ChCertGetRawState(&chCertState) != CC_OK) {\
        return CC_CH_CERT_ERROR;\
    }\
    if ((chCertState & CC_CH_CERT_STATE_ERROR) || !(chCertState & CC_CH_CERT_STATE_CRYPTO_APPROVED)) {\
        return CC_CH_CERT_ERROR;\
    }\
}

// used for Chinese API that returns void. If CH_CERT error is on, return with no operation
#define CHECK_AND_RETURN_UPON_CH_CERT_ERROR() {\
    CCChCertState_t   chCertState; \
    if (ChCertGetRawState(&chCertState) != CC_OK) {\
        return;\
    }\
    if ((chCertState & CC_CH_CERT_STATE_ERROR) || !(chCertState & CC_CH_CERT_STATE_CRYPTO_APPROVED)) {\
        return;\
    }\
}

// used for conditional testing. If CH_CERT state is not CH_CERT_SUPPORT return with OK
#define CHECK_AND_RETURN_UPON_CH_CERT_STATE() {\
    CCChCertState_t   chCertState; \
    if (ChCertGetRawState(&chCertState) != CC_OK) {\
        return CC_CH_CERT_ERROR;\
    }\
    if (!(chCertState & CC_CH_CERT_STATE_SUPPORTED)) {\
        return CC_OK;\
    }\
}

#define CHECK_CH_CERT_SUPPORTED(supported) {\
    CCChCertState_t   chCertState; \
    supported = ((ChCertGetRawState(&chCertState) != CC_OK) || (chCertState & CC_CH_CERT_STATE_SUPPORTED)); \
}


CCChCertError_t ChCertGetTrace(CCChCertTrace_t  *pChCertTrace);    /*!< [out]The chCert Trace of the library. */
CCChCertError_t ChCertSetState(CCChCertState_t  chCertState);      /*!< [in] Sets the chCert State of the library. */
CCError_t ChCertGetRawState(CCChCertState_t *pChCertState);        /*!< [out] The chCert State of the library. */
CCError_t ChCertRevertState(CCChCertState_t chCertState);          /*!< [in] The chCert State that should be reverted. */
CCChCertError_t ChCertSetError(CCChCertError_t  chCertError);      /*!< [in] Sets the chCert Error of the library. */
CCChCertError_t ChCertSetTrace(CCChCertTrace_t  chCertTrace);      /*!< [in] Sets the chCert Trace of the library. */

CCChCertError_t ChCertRunPowerUpTest(CCCertKatContext_t  *pCertCtx);
CCChCertError_t CC_ChCertSm4RunTests(void);
CCChCertError_t CC_ChCertSm3RunTests(void);
CCChCertError_t CC_ChCertSm2RunTests(CCCertKatContext_t  *pCertCtx);
CCError_t CC_ChCertSm2ConditionalTest(CCRndGenerateVectWorkFunc_t f_rng,
                                      void                        *p_rng,
                                      CCEcpkiUserPrivKey_t    *pUserPrivKey,
                                      CCEcpkiUserPublKey_t    *pUserPublKey,
                                      CCSm2KeyGenCHCertContext_t  *pFipsCtx);
/* Validate generated key by conditional test in case of SM2 domain */
#define CH_CERT_KEY_GEN_VALIDATE(f_rng, p_rng, pUserPrivKey, pUserPublKey, pCHCertCtx)  \
        (pDomain == CC_EcpkiGetSm2Domain())? CC_ChCertSm2ConditionalTest(f_rng, p_rng, pUserPrivKey, pUserPublKey, pCHCertCtx) : (CC_OK)


#else  // CC_SUPPORT_CH_CERT
//empty macro since CH_CERT not supported
#define CHECK_AND_RETURN_ERR_UPON_CH_CERT_ERROR()
#define CHECK_AND_RETURN_UPON_CH_CERT_ERROR()
#define CHECK_AND_RETURN_UPON_CH_CERT_STATE()
#define CHECK_CH_CERT_SUPPORTED(supported) {supported = false;}
#define CH_CERT_KEY_GEN_VALIDATE(f_rng, p_rng, pUserPrivKey, pUserPublKey, pCHCertCtx)   (CC_UNUSED_PARAM(f_rng),CC_UNUSED_PARAM(p_rng),CC_OK)
#endif  // CC_SUPPORT_CH_CERT
#endif  // _CC_CH_CERT_DEFS_H

