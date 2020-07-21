/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef  _CC_FIPS_DEFS_H
#define  _CC_FIPS_DEFS_H


#include "cc_cert_ctx.h"
#ifdef CC_SUPPORT_FULL_PROJECT
#include "cc_fips_error.h"
#include "cc_fips.h"
#include "cc_fips_rsa_defs.h"
#include "cc_fips_ecc_defs.h"
#endif

typedef enum CCFipsTrace_t {
        CC_FIPS_TRACE_NONE              = 0x0,
        CC_FIPS_TRACE_AES_PUT           = 0x1,
        CC_FIPS_TRACE_AESCCM_PUT        = 0x2,
        CC_FIPS_TRACE_DES_PUT           = 0x4,
        CC_FIPS_TRACE_HASH_PUT          = 0x8,
        CC_FIPS_TRACE_HMAC_PUT          = 0x10,
        CC_FIPS_TRACE_RSA_PUT           = 0x20,
        CC_FIPS_TRACE_ECDSA_PUT         = 0x40,
        CC_FIPS_TRACE_DH_PUT            = 0x80,
        CC_FIPS_TRACE_ECDH_PUT          = 0x100,
        CC_FIPS_TRACE_PRNG_PUT          = 0x200,
        CC_FIPS_TRACE_RSA_COND          = 0x400,
        CC_FIPS_TRACE_ECC_COND          = 0x800,
        CC_FIPS_TRACE_PRNG_CONT         = 0x1000,
        CC_FIPS_TRACE_AESGCM_PUT        = 0x2000,
        CC_FIPS_TRACE_RESERVE32B        = INT32_MAX
}CCFipsTrace_t;

typedef enum CC_FipsSyncStatus{
	CC_FIPS_SYNC_MODULE_OK 		= 0x0,
	CC_FIPS_SYNC_MODULE_ERROR 	= 0x1,
	CC_FIPS_SYNC_REE_STATUS 	= 0x4,
	CC_FIPS_SYNC_TEE_STATUS 	= 0x8,
	CC_FIPS_SYNC_STATUS_RESERVE32B 	= INT32_MAX
}CCFipsSyncStatus_t;

#ifdef CC_SUPPORT_FIPS

typedef struct CC_FipsStateData {
	CCFipsState_t state;
	CCFipsError_t error;
	CCFipsTrace_t trace;
}CCFipsStateData_t;

// used for every CC API. If FIPS error is on, return with FIPS error code
#define CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR() {\
	CCFipsState_t	fipsState; \
	if (FipsGetRawState(&fipsState) != CC_OK) {\
		return CC_FIPS_ERROR;\
	}\
	if ((fipsState & CC_FIPS_STATE_ERROR) || !(fipsState & CC_FIPS_STATE_CRYPTO_APPROVED)) {\
                return CC_FIPS_ERROR;\
	}\
}

// used for CC API that returns void. If FIPS error is on, return with no operation
#define CHECK_AND_RETURN_UPON_FIPS_ERROR() {\
        CCFipsState_t	fipsState; \
        if (FipsGetRawState(&fipsState) != CC_OK) {\
                return;\
        }\
	if ((fipsState & CC_FIPS_STATE_ERROR) || !(fipsState & CC_FIPS_STATE_CRYPTO_APPROVED)) {\
                return;\
        }\
}

// used for conditional testing. If FIPS state is not FIPS_SUPPORT return with OK
#define CHECK_AND_RETURN_UPON_FIPS_STATE() {\
	CCFipsState_t	fipsState; \
	if (FipsGetRawState(&fipsState) != CC_OK) {\
		return CC_FIPS_ERROR;\
	}\
	if (!(fipsState & CC_FIPS_STATE_SUPPORTED)) {\
		return CC_OK;\
	}\
}

#define CHECK_FIPS_SUPPORTED(supported) {\
	CCFipsState_t	fipsState; \
	supported = ((FipsGetRawState(&fipsState) != CC_OK) || (fipsState & CC_FIPS_STATE_SUPPORTED)); \
}

#define FIPS_RSA_VALIDATE(f_rng,p_rng,pCcUserPrivKey,pCcUserPubKey,pFipsCtx) \
                        CC_FipsRsaConditionalTest(f_rng,p_rng,pCcUserPrivKey,pCcUserPubKey,pFipsCtx)

#define FIPS_ECC_VALIDATE(f_rng,p_rng, pUserPrivKey, pUserPublKey, pFipsCtx)  \
			CC_FipsEccConditionalTest(f_rng,p_rng, pUserPrivKey, pUserPublKey, pFipsCtx)

#define CC_FIPS_SET_RND_CONT_ERR() {\
        CCFipsState_t	fipsState; \
        if ((FipsGetRawState(&fipsState) != CC_OK) || (fipsState & CC_FIPS_STATE_SUPPORTED)) {\
                (void)FipsSetError(CC_TEE_FIPS_ERROR_PRNG_CONT);\
        }\
}


CCError_t FipsNotifyUponTeeStatus(CCFipsError_t  fipsError); /*!< [in] Notify REE about the fips Error. */
CCError_t FipsSetReeStatus(CCFipsReeStatus_t status); /*!< [in] Sets the fips REE status in TEE FIPS error. */
CCFipsError_t FipsGetTrace(CCFipsTrace_t  *pFipsTrace);  /*!< [out]The fips Trace of the library. */
CCFipsError_t FipsSetState(CCFipsState_t  fipsState);  /*!< [in] Sets the fips State of the library. */
CCError_t FipsGetRawState(CCFipsState_t *pFipsState); /*!< [out] The fips State of the library. */
CCError_t FipsRevertState(CCFipsState_t fipsState);   /*!< [in] The fips State that should be reverted. */
CCFipsError_t FipsSetError(CCFipsError_t  fipsError);  /*!< [in] Sets the fips Error of the library. */
CCFipsError_t FipsSetTrace(CCFipsTrace_t  fipsTrace);  /*!< [in] Sets the fips Trace of the library. */

CCFipsError_t FipsRunPowerUpTest(CCRndGenerateVectWorkFunc_t *f_rng, void *p_rng, CCCertKatContext_t  *pCertCtx);
CCFipsError_t CC_FipsAesRunTests(void);
CCFipsError_t CC_FipsAesCcmRunTests(void);
CCFipsError_t CC_FipsAesGcmRunTests(void);
CCFipsError_t CC_FipsDesRunTests(void);
CCFipsError_t CC_FipsHashRunTests(void);
CCFipsError_t CC_FipsHmacRunTests(void);

#else  // CC_SUPPORT_FIPS
//empty macro since FIPS not supported
#define CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR()
#define CHECK_AND_RETURN_UPON_FIPS_ERROR()
#define CHECK_AND_RETURN_UPON_FIPS_STATE()
#define CHECK_FIPS_SUPPORTED(supported) {supported = false;}
#define FIPS_RSA_VALIDATE(f_rng,p_rng,pCcUserPrivKey,pCcUserPubKey,pFipsCtx)  (CC_OK)
#define FIPS_ECC_VALIDATE(f_rng,p_rng, pUserPrivKey, pUserPublKey, pFipsCtx)  (CC_UNUSED_PARAM(f_rng),CC_UNUSED_PARAM(p_rng),CC_OK)
#define CC_FIPS_SET_RND_CONT_ERR()

#endif  // CC_SUPPORT_FIPS
#endif  // _CC_FIPS_DEFS_H

