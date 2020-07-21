/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include "cc_pal_cert.h"
#include "cc_pal_types.h"
#include "cc_hal_plat.h"
#include "cc_regs.h"
#include "cc_pal_mutex.h"
#include "cc_pal_abort.h"
#include "cc_chinese_cert.h"
#include "cc_chinese_cert_defs.h"


extern CC_PalMutex CCChCertMutex;

CCError_t ChCertSetState(CCChCertState_t chCertState)
{
    CCError_t error = CC_OK;
    CCChCertState_t prevChCertState = 0;

    error = CC_PalMutexLock(&CCChCertMutex, CC_INFINITE);
    if (error != CC_OK) {
        CC_PalAbort("Fail to acquire mutex\n");
    }

    error = CC_PalCertGetState(&prevChCertState);
    if (error != CC_OK) {
        goto End;
    }

    chCertState |= prevChCertState;

    error = CC_PalCertSetState(chCertState);
    if (error != CC_OK) {
        goto End;
    }

End:
    if (CC_PalMutexUnlock(&CCChCertMutex) != CC_OK) {
        CC_PalAbort("Fail to release mutex\n");
    }

    return error;
}

CCError_t ChCertGetRawState(CCChCertState_t *pChCertState)
{
    CCError_t   error = CC_OK;

    if (pChCertState == NULL) {
        return CC_FAIL;
    }

    error = CC_PalMutexLock(&CCChCertMutex, CC_INFINITE);
    if (error != CC_OK) {
        CC_PalAbort("Fail to acquire mutex\n");
    }

    error = CC_PalCertGetState(pChCertState);

    if (CC_PalMutexUnlock(&CCChCertMutex) != CC_OK) {
        CC_PalAbort("Fail to release mutex\n");
    }

    return error;
}

CCError_t ChCertRevertState(CCChCertState_t chCertState)
{
    CCError_t error = CC_OK;
    CCChCertState_t prevChCertState = 0;

    if (chCertState != CC_CH_CERT_STATE_CRYPTO_APPROVED) {
        return CC_CH_CERT_ERROR;
    }

    error = CC_PalMutexLock(&CCChCertMutex, CC_INFINITE);
    if (error != CC_OK) {
        CC_PalAbort("Fail to acquire mutex\n");
    }

    error = CC_PalCertGetState(&prevChCertState);
    if (error != CC_OK) {
        goto End;
    }

    prevChCertState &= ~chCertState;

    error = CC_PalCertSetState(prevChCertState);
    if (error != CC_OK) {
        goto End;
    }

End:
    if (CC_PalMutexUnlock(&CCChCertMutex) != CC_OK) {
        CC_PalAbort("Fail to release mutex\n");
    }

    return error;
}

CCError_t ChCertSetError(CCChCertError_t chCertError)
{
    CCError_t error = CC_OK;
    CCChCertError_t  currentChCertError;

    if (chCertError == CC_TEE_CH_CERT_ERROR_OK) {
        return CC_CH_CERT_ERROR;
    }

    error = CC_PalMutexLock(&CCChCertMutex, CC_INFINITE);
    if (error != CC_OK) {
        CC_PalAbort("Fail to acquire mutex\n");
    }

    error = CC_PalCertGetError(&currentChCertError);
    if (error != CC_OK) {
        goto End;
    }
    if (currentChCertError != CC_TEE_CH_CERT_ERROR_OK) {
            goto End;
    }

    error = CC_PalCertSetError(chCertError);
    if (error != CC_OK) {
        goto End;
    }

    error = CC_PalCertSetState(CC_CH_CERT_STATE_ERROR);
    if (error != CC_OK) {
        goto End;
    }

End:
    if (CC_PalMutexUnlock(&CCChCertMutex) != CC_OK) {
        CC_PalAbort("Fail to release mutex\n");
    }

    return error;
}

CCError_t ChCertSetTrace(CCChCertTrace_t chCertTrace)
{
    CCError_t error = CC_OK;

    error = CC_PalMutexLock(&CCChCertMutex, CC_INFINITE);
    if (error != CC_OK) {
        CC_PalAbort("Fail to acquire mutex\n");
    }

    error = CC_PalCertSetTrace(chCertTrace);

    if (CC_PalMutexUnlock(&CCChCertMutex) != CC_OK) {
        CC_PalAbort("Fail to release mutex\n");
    }

    return error;
}

CCError_t ChCertGetTrace(CCChCertTrace_t *pChCertTrace)
{
    CCError_t error = CC_OK;

    if (pChCertTrace == NULL) {
        return CC_FAIL;
    }

    error = CC_PalMutexLock(&CCChCertMutex, CC_INFINITE);
    if (error != CC_OK) {
        CC_PalAbort("Fail to acquire mutex\n");
    }

    error = CC_PalCertGetTrace(pChCertTrace);

    if (CC_PalMutexUnlock(&CCChCertMutex) != CC_OK) {
        CC_PalAbort("Fail to release mutex\n");
    }

    return error;
}

CCError_t ChCertRunPowerUpTest(CCCertKatContext_t  *pCertCtx)
{
    CCChCertError_t ChCertErr = CC_TEE_CH_CERT_ERROR_OK;

    /* check ptr validity */
    if (pCertCtx == NULL) {
        ChCertErr = CC_TEE_CH_CERT_ERROR_GENERAL;
        goto End;
    }

    /* SM4 KATs */
    ChCertErr = CC_ChCertSm4RunTests();
    if (ChCertErr != CC_TEE_CH_CERT_ERROR_OK) {
        goto End;
    }

    /* SM3 KATs */
    ChCertErr = CC_ChCertSm3RunTests();
    if (ChCertErr != CC_TEE_CH_CERT_ERROR_OK) {
        goto End;
    }

    /* SM2 KATs */
    ChCertErr = CC_ChCertSm2RunTests(pCertCtx);
    if (ChCertErr != CC_TEE_CH_CERT_ERROR_OK) {
        goto End;
    }

End:
    if (ChCertErr != CC_TEE_CH_CERT_ERROR_OK) {
        ChCertSetError(ChCertErr);
        return CC_CH_CERT_MODULE_ERROR_BASE;
    }

    return CC_OK;
}

