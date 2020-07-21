/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include <unistd.h>
#include <pthread.h>

#include "cc_pal_cert.h"
#include "cc_pal_types.h"
#include "cc_pal_mem.h"
#include "cc_hal.h"
#include "cc_registers.h"
#include "cc_regs.h"


#ifdef CC_SUPPORT_CH_CERT
#include "cc_chinese_cert_defs.h"
#endif

#ifdef CC_SUPPORT_FIPS
#include "cc_fips_defs.h"
#endif

#ifdef CC_SUPPORT_CH_CERT
CCChCertStateData_t   gStateData = { CC_CH_CERT_STATE_CRYPTO_APPROVED, CC_TEE_CH_CERT_ERROR_OK, CC_CH_CERT_TRACE_NONE };
#endif

#ifdef CC_SUPPORT_FIPS
CCFipsStateData_t 	gStateData = { CC_FIPS_STATE_CRYPTO_APPROVED, CC_TEE_FIPS_ERROR_OK, CC_FIPS_TRACE_NONE };
#endif


CCError_t CC_PalCertGetState(uint32_t *pCertState)
{
	*pCertState = gStateData.state;

	return CC_OK;
}


CCError_t CC_PalCertGetError(uint32_t *pCertError)
{
	*pCertError = gStateData.error;

	return CC_OK;
}


CCError_t CC_PalCertGetTrace(uint32_t *pCertTrace)
{
	*pCertTrace = gStateData.trace;

	return CC_OK;
}

CCError_t CC_PalCertSetState(uint32_t certState)
{
	gStateData.state = certState;

	return CC_OK;
}

CCError_t CC_PalCertSetError(uint32_t certError)
{
	gStateData.error = certError;

	return CC_OK;
}

CCError_t CC_PalCertSetTrace(uint32_t certTrace)
{
	gStateData.trace = (gStateData.trace | certTrace);

	return CC_OK;
}

