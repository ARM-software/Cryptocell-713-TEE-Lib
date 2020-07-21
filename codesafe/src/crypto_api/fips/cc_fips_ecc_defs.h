/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef  _CC_FIPS_ECC_DEFS_H
#define  _CC_FIPS_ECC_DEFS_H

#include "cc_rnd_common.h"
#include "cc_ecpki_types.h"
#include "cc_ecpki_ecdsa.h"


CCError_t CC_FipsEccConditionalTest(CCRndGenerateVectWorkFunc_t f_rng,
                void                   *p_rng,
				CCEcpkiUserPrivKey_t   *pUserPrivKey,
				CCEcpkiUserPublKey_t   *pUserPublKey,
				CCEcpkiKgFipsContext_t   *pFipsCtx);


CCFipsError_t CC_FipsEcdsaKat(CCRndGenerateVectWorkFunc_t *f_rng,
                void                   *p_rng,
			    CCEcdsaFipsKatContext_t    *pFipsCtx);


CCFipsError_t CC_FipsEcdhKat(CCEcdhFipsKatContext_t    *pFipsCtx);

#endif  // _CC_FIPS_ECC_DEFS_H

