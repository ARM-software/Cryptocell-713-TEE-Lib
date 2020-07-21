/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include "cc_pal_log.h"
#include "cc_pal_types.h"
#include "cc_pal_mem.h"
#include "cc_dh.h"
#include "cc_fips.h"
#include "cc_fips_error.h"
#include "cc_fips_defs.h"
#include "cc_fips_dh_kat_data.h"

/* KAT test for DH.  */
CCFipsError_t CC_FipsDhKat(CCDhFipsKat_t    *pFipsCtx)
{
        CCError_t			rc;
        CCFipsError_t			fipsRc = CC_TEE_FIPS_ERROR_OK;
        CCDhUserPubKey_t		*pUsrPubKey;
	CCDhPrimeData_t		*pPrimeData;
	uint8_t				*pSecretBuff;
	size_t				secretBuffSize;


	if (pFipsCtx == NULL) {
                return CC_TEE_FIPS_ERROR_DH_PUT;
	}

	pUsrPubKey = &pFipsCtx->pubKey;
	pPrimeData = &pFipsCtx->primeData;
	pSecretBuff = pFipsCtx->secretBuff;
	secretBuffSize = sizeof(pFipsCtx->secretBuff);

        // Generate secrete key
	rc = CC_DhGetSecretKey((uint8_t *)fipsDhKat2048InitiatorPrivKey,
                                  sizeof(fipsDhKat2048InitiatorPrivKey),
                                  (uint8_t *)fipsDhKat2048ResponderPubKey,
                                  sizeof(fipsDhKat2048ResponderPubKey),
                                  (uint8_t *)fipsDhKat2048PrimeP,
                                  sizeof(fipsDhKat2048PrimeP),
                                  pUsrPubKey,
                                  pPrimeData,
                                  pSecretBuff,
                                  &secretBuffSize);
        if ((rc!=CC_OK) || (secretBuffSize != sizeof(pFipsCtx->secretBuff))) {
                fipsRc = CC_TEE_FIPS_ERROR_DH_PUT;
		goto End;
	}

	// Verify secret is the same as expected
	rc = CC_PalMemCmp((uint8_t *)fipsDhKat2048Secret, pSecretBuff, secretBuffSize);
	if (rc != CC_OK) {
                fipsRc = CC_TEE_FIPS_ERROR_DH_PUT;
		goto End;
	}

	FipsSetTrace(CC_FIPS_TRACE_DH_PUT);

End:
	CC_PalMemSetZero(pFipsCtx, sizeof(CCDhFipsKat_t));
        return fipsRc;
}


