/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include "cc_pal_types.h"
#include "cc_pal_mutex.h"
#include "cc_pal_abort.h"
#include "cc_chinese_cert.h"

#include "cc_pal_cert.h"
#include "cc_chinese_cert_defs.h"
#include "cc_regs.h"
#include "cc_hal.h"
#include "cc_general_defs.h"

extern CC_PalMutex CCChCertMutex;


CCError_t CC_ChCertCryptoUsageStateSet(CCChCertCryptoUsageState_t state)
{
    CCError_t error = CC_OK;
    CCChCertState_t chCertState = 0;

    error = CC_ChCertStateGet(&chCertState);
    if (error != CC_OK) {
        return error;
    }

    if (state == CC_TEE_CH_CERT_CRYPTO_USAGE_STATE_NON_APPROVED) {
        error = ChCertRevertState(CC_CH_CERT_STATE_CRYPTO_APPROVED);
    }
    else {
        error = ChCertSetState(CC_CH_CERT_STATE_CRYPTO_APPROVED);
    }

    return error;
}

CCError_t CC_ChCertErrorGet(CCChCertError_t *pChCertError)
{
    CCError_t error = CC_OK;

    if (pChCertError == NULL) {
        return CC_FAIL;
    }

    error = CC_PalMutexLock(&CCChCertMutex, CC_INFINITE);
    if (error != CC_OK) {
        CC_PalAbort("Fail to acquire mutex\n");
    }

    error = CC_PalCertGetError(pChCertError);

    if (CC_PalMutexUnlock(&CCChCertMutex) != CC_OK) {
        CC_PalAbort("Fail to release mutex\n");
    }

    return error;
}


CCError_t CC_ChCertStateGet(CCChCertState_t *pChCertState)
{
    CCError_t       error = CC_OK;
    CCChCertState_t palChCertState = 0;


    if (pChCertState == NULL) {
        return CC_FAIL;
    }

    error = CC_PalMutexLock(&CCChCertMutex, CC_INFINITE);
    if (error != CC_OK) {
        CC_PalAbort("Fail to acquire mutex\n");
    }

    error = CC_PalCertGetState(&palChCertState);

    if (CC_PalMutexUnlock(&CCChCertMutex) != CC_OK) {
        CC_PalAbort("Fail to release mutex\n");
    }

    if (error != CC_OK) {
        return error;
    }

    if (palChCertState & CC_CH_CERT_STATE_ERROR) {
        *pChCertState = CC_CH_CERT_STATE_ERROR;
    }
    else if (palChCertState & CC_CH_CERT_STATE_SUPPORTED) {
        *pChCertState = CC_CH_CERT_STATE_SUPPORTED;
    }
    else {
        *pChCertState = CC_CH_CERT_STATE_NOT_SUPPORTED;
    }

    return error;
}

