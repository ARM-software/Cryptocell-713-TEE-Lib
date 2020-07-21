/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef  _CC_FIPS_RSA_DEFS_H
#define  _CC_FIPS_RSA_DEFS_H


#include "cc_rnd_common.h"
#include "cc_rsa_types.h"
#include "cc_rsa_schemes.h"


/*****************************************************************************/
/**
 * The function runs the conditional test for RSA key generation
 *
 *
 * @param f_rng          - pointer to DRBG function
 * @param p_rng          - Pointer to the random context
 * @param pCcUserPrivKey - pointer to the private key data structure
 * @param pCcUserPubKey  - pointer to the public key data structure
 * @param pFipsCtx  - pointer to RSA fips structure used for conditional test
 *
 * @return CCError_t
 */
CCError_t CC_FipsRsaConditionalTest(CCRndGenerateVectWorkFunc_t f_rng,
                void                *p_rng,
				CCRsaUserPrivKey_t 	*pCcUserPrivKey,
				CCRsaUserPubKey_t  	*pCcUserPubKey,
				CCRsaKgFipsContext_t    *pFipsCtx);



/*****************************************************************************/
/**
 * The function runs the conditional test for RSA key generation
 *
 *
 * @param f_rng          - pointer to DRBG function
 * @param p_rng          - Pointer to the random context
 * @param pFipsCtx  - pointer to RSA fips structure used for KAT test
 *
 * @return CCError_t
 */
CCFipsError_t CC_FipsRsaKat(CCRndGenerateVectWorkFunc_t *f_rng,
            void                *p_rng,
			CCRsaFipsKatContext_t    *pFipsCtx);


#endif  // _CC_FIPS_RSA_DEFS_H

