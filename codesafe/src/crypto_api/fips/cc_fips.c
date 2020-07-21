/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include "cc_pal_types.h"
#include "cc_pal_mutex.h"
#include "cc_pal_abort.h"
#include "cc_des.h"
#include "cc_fips.h"

#include "cc_pal_cert.h"
#include "cc_fips_defs.h"
#include "cc_regs.h"
#include "cc_hal.h"
#include "cc_general_defs.h"

extern CC_PalMutex CCFipsMutex;


CCError_t CC_FipsCryptoUsageStateSet(CCFipsCryptoUsageState_t state)
{
        CCError_t error = CC_OK;
        CCFipsState_t fipsState = 0;

        error = CC_FipsStateGet(&fipsState, NULL);
        if (error != CC_OK) {
                return error;
        }

        if (fipsState != CC_FIPS_STATE_SUSPENDED) {
                return CC_FIPS_ERROR;
        }

        if (state == CC_TEE_FIPS_CRYPTO_USAGE_STATE_NON_APPROVED) {
                error = FipsRevertState(CC_FIPS_STATE_CRYPTO_APPROVED);
        }
        else {
                error = FipsSetState(CC_FIPS_STATE_CRYPTO_APPROVED);
        }

        return error;
}

CCError_t CC_FipsErrorGet(CCFipsError_t *pFipsError)
{
        CCError_t error = CC_OK;

	if (pFipsError == NULL) {
		return CC_FAIL;
	}

	error = CC_PalMutexLock(&CCFipsMutex, CC_INFINITE);
	if (error != CC_OK) {
		CC_PalAbort("Fail to acquire mutex\n");
	}

	error = CC_PalCertGetError(pFipsError);

	if (CC_PalMutexUnlock(&CCFipsMutex) != CC_OK) {
		CC_PalAbort("Fail to release mutex\n");
	}

	return error;
}


CCError_t CC_FipsStateGet(CCFipsState_t *pFipsState, bool *pIsDeviceZeroized)
{
        CCError_t 	error = CC_OK;
	uint32_t 	regVal = 0;
	uint32_t 	lcsVal = 0;
        CCFipsState_t palFipsState = 0;


	if (pFipsState == NULL) {
		return CC_FAIL;
	}

	error = CC_PalMutexLock(&CCFipsMutex, CC_INFINITE);
	if (error != CC_OK) {
		CC_PalAbort("Fail to acquire mutex\n");
	}

        error = CC_PalCertGetState(&palFipsState);
	if (pIsDeviceZeroized != NULL) {
		/* Read LCS */
		regVal = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, LCS_REG));
		lcsVal = CC_REG_FLD_GET(0, LCS_REG, LCS_REG, regVal);
		*pIsDeviceZeroized = ((lcsVal == CC_LCS_RMA_LCS)? true: false);
	}

	if (CC_PalMutexUnlock(&CCFipsMutex) != CC_OK) {
		CC_PalAbort("Fail to release mutex\n");
	}

        if (error != CC_OK) {
                return error;
        }

        if (palFipsState & CC_FIPS_STATE_ERROR) {
                *pFipsState = CC_FIPS_STATE_ERROR;
        }
        else if (palFipsState & CC_FIPS_STATE_SUSPENDED) {
                *pFipsState = CC_FIPS_STATE_SUSPENDED;
        }
        else if (palFipsState & CC_FIPS_STATE_SUPPORTED) {
                *pFipsState = CC_FIPS_STATE_SUPPORTED;
        }
        else {
                *pFipsState = CC_FIPS_STATE_NOT_SUPPORTED;
        }

	return error;
}

CCError_t CC_FipsIrqHandle(void)
{
	uint32_t regVal;
	uint32_t rc;

	regVal = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, GPR_HOST));
	if (regVal == (CC_FIPS_SYNC_REE_STATUS | CC_FIPS_SYNC_MODULE_OK)) {
		rc = FipsSetReeStatus(CC_TEE_FIPS_REE_STATUS_OK);
	} else {
		rc = FipsSetReeStatus(CC_TEE_FIPS_REE_STATUS_ERROR);
	}
	return rc;
}
