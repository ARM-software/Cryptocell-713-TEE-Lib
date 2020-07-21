/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include "cc_pal_log.h"
#include "cc_pal_types.h"
#include "cc_pal_mem.h"
#include "cc_rnd_common.h"
#include "cc_ecpki_types.h"
#include "cc_ecpki_build.h"
#include "cc_ecpki_domain.h"
#include "cc_ecpki_local.h"
#include "cc_ecpki_dh.h"
#include "cc_ecpki_ecdsa.h"
#include "cc_fips.h"
#include "cc_fips_error.h"
#include "cc_fips_defs.h"
#include "cc_fips_ecc_defs.h"
#include "cc_fips_ecdsa_kat_data.h"
#include "cc_fips_ecdh_kat_data.h"
#include "cc_common.h"

#define FIPS_ECC_DOMAIN_TYPE  		CC_ECPKI_DomainID_secp256r1

#define FIPS_ECC_HASH_MODE  		CC_ECPKI_AFTER_HASH_SHA256_mode
#define FIPS_ECC_SIGNED_DATA_SIZE   	(2*CC_ECPKI_ORDER_MAX_LENGTH_IN_WORDS*CC_32BIT_WORD_SIZE)

typedef uint8_t        FipsEccSignedData_t[FIPS_ECC_SIGNED_DATA_SIZE];

static const	uint8_t           eccFipsDataIn[CC_HASH_SHA256_DIGEST_SIZE_IN_BYTES] = {
	 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	 0x10, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};



/* Conditional test for ECC.  Use SECP-256R1 curve */
CCError_t CC_FipsEccConditionalTest(CCRndGenerateVectWorkFunc_t f_rng,
                    void                   *p_rng,
					CCEcpkiUserPrivKey_t   *pUserPrivKey,
					CCEcpkiUserPublKey_t   *pUserPublKey,
					CCEcpkiKgFipsContext_t   *pFipsCtx)
{

        CCError_t 			rc = CC_OK;
        CCFipsError_t 			fipsRc = CC_TEE_FIPS_ERROR_GENERAL;
        size_t				dataSignOutSize = sizeof(FipsEccSignedData_t);
	CCEcdsaSignUserContext_t	*pSignUserContext;
	CCEcdsaVerifyUserContext_t  *pVerifyUserContext;
	FipsEccSignedData_t    		*pDataSignOut;

	CHECK_AND_RETURN_UPON_FIPS_STATE();

        if (pFipsCtx == NULL) {
                rc = CC_FIPS_ERROR;
		goto End;
	}
        if ((pUserPrivKey == NULL) ||
	    (pUserPublKey == NULL)) {
                rc = CC_FIPS_ERROR;
		goto End;
	}

	pDataSignOut = (FipsEccSignedData_t *)pFipsCtx->signBuff;
	pSignUserContext = &(pFipsCtx->operationCtx.signCtx);

	// Generate signature
        rc = CC_EcdsaSign(f_rng, p_rng, pSignUserContext, pUserPrivKey,
				FIPS_ECC_HASH_MODE,
				(uint8_t *)eccFipsDataIn, sizeof(eccFipsDataIn),
				(uint8_t *)pDataSignOut, &dataSignOutSize);
        if (rc!=CC_OK) {
                fipsRc = CC_TEE_FIPS_ERROR_ECDSA_SIGN_COND;
		goto End;
	}

	// Verify signature data is diffenet than the input
	rc = CC_PalMemCmp(eccFipsDataIn, pDataSignOut, sizeof(eccFipsDataIn));
	if (rc == CC_OK) {
		rc = 1;
                fipsRc = CC_TEE_FIPS_ERROR_ECDSA_SIGN_COND;
		goto End;
	}

	CC_PalMemSetZero(pSignUserContext, sizeof(CCEcdsaSignUserContext_t));
	pVerifyUserContext = (CCEcdsaVerifyUserContext_t *)(&pFipsCtx->operationCtx.verifyCtx);

        // Verify the signature
	rc = CC_EcdsaVerify (pVerifyUserContext, pUserPublKey,
				FIPS_ECC_HASH_MODE,
				(uint8_t *)pDataSignOut, dataSignOutSize,
				(uint8_t *)eccFipsDataIn, sizeof(eccFipsDataIn));
	if (rc!=CC_OK) {
                fipsRc = CC_TEE_FIPS_ERROR_ECDSA_VERIFY_COND;
		goto End;
	}
	FipsSetTrace(CC_FIPS_TRACE_ECC_COND);

End:
	if (rc != CC_OK) {
	    FipsSetError(fipsRc);
	    return CC_FIPS_ERROR;
	}
	return rc;

}/* END OF CC_FipsEccConditionalTest */


/* KAT test for ECC. Use SECP-256R1 curve */
CCFipsError_t CC_FipsEcdsaKat(CCRndGenerateVectWorkFunc_t *f_rng,
                void                       *p_rng,
			    CCEcdsaFipsKatContext_t    *pFipsCtx)
{
        CCError_t			rc;
        CCFipsError_t                  fipsRc = CC_TEE_FIPS_ERROR_OK;
	CCEcpkiUserPublKey_t    	*pUserPublKey;
	CCEcpkiUserPrivKey_t  	*pUserPrivKey;
	CCEcpkiBuildTempData_t 	*pTempBuff;
	CCEcdsaSignUserContext_t	*pSignUserContext;
	CCEcdsaVerifyUserContext_t	*pVerifyUserContext;
	uint8_t				*pDataSignOut;
	size_t 				dataSignOutSize;
	uint32_t			ephemeralKey[CC_ECPKI_FIPS_ORDER_LENGTH/CC_32BIT_WORD_SIZE];


	if (pFipsCtx == NULL) {
                return CC_TEE_FIPS_ERROR_GENERAL;
	}

	pUserPrivKey = &pFipsCtx->keyContextData.userSignData.PrivKey;
	pSignUserContext = &pFipsCtx->keyContextData.userSignData.signCtx;
	pDataSignOut = pFipsCtx->signBuff;
	dataSignOutSize = sizeof(pFipsCtx->signBuff);

        // Build ptivate key for sign opeartion
	rc = CC_EcpkiPrivKeyBuild(CC_EcpkiGetEcDomain(FIPS_ECC_DOMAIN_TYPE),
				      (uint8_t *)fipsEcdsaR256r1KatPrivKey,
				      sizeof(fipsEcdsaR256r1KatPrivKey),
				      pUserPrivKey);
        if (rc!=CC_OK) {
                fipsRc = CC_TEE_FIPS_ERROR_ECDSA_SIGN_PUT;
		goto End;
	}

	rc = CC_CommonReverseMemcpy((uint8_t *)ephemeralKey, (uint8_t *)fipsEcdsaR256r1KatEphemeralKey, sizeof(fipsEcdsaR256r1KatEphemeralKey));
        if (rc!=CC_OK) {
                fipsRc = CC_TEE_FIPS_ERROR_ECDSA_SIGN_PUT;
		goto End;
	}

        // Use non-integrated sign operation to be able to use ephemeral key
        rc = EcdsaSignInit( pSignUserContext, pUserPrivKey,
				CC_ECPKI_HASH_SHA256_mode);
        if (rc!=CC_OK) {
                fipsRc = CC_TEE_FIPS_ERROR_ECDSA_SIGN_PUT;
		goto End;
	}

        rc = EcdsaSignUpdate(pSignUserContext,
			(uint8_t *)fipsEcdsaR256r1KatDataIn, sizeof(fipsEcdsaR256r1KatDataIn));
        if (rc!=CC_OK) {
                fipsRc = CC_TEE_FIPS_ERROR_ECDSA_SIGN_PUT;
		goto End;
	}

        rc = EcdsaSignFinishInt(pSignUserContext, *f_rng, p_rng,
                                (uint8_t *)pDataSignOut, &dataSignOutSize, 0, ephemeralKey);
        if (rc!=CC_OK) {
                fipsRc = CC_TEE_FIPS_ERROR_ECDSA_SIGN_PUT;
		goto End;
	}

	// Verify signature is the same as expected
	rc = CC_PalMemCmp((uint8_t *)fipsEcdsaR256r1KatSignature, pDataSignOut, sizeof(fipsEcdsaR256r1KatSignature));
	if (rc != CC_OK) {
                fipsRc = CC_TEE_FIPS_ERROR_ECDSA_SIGN_PUT;
		goto End;
	}

	CC_PalMemSetZero((uint8_t *)&pFipsCtx->keyContextData, sizeof(pFipsCtx->keyContextData));
	pUserPublKey = &pFipsCtx->keyContextData.userVerifyData.PublKey;
	pTempBuff = &pFipsCtx->keyContextData.userVerifyData.buildOrVerify.tempData;
	pVerifyUserContext = &pFipsCtx->keyContextData.userVerifyData.buildOrVerify.verifyCtx;

        // Build public key for verify operation
	rc = CC_EcpkiPubKeyBuildAndFullCheck(CC_EcpkiGetEcDomain(FIPS_ECC_DOMAIN_TYPE),
					       (uint8_t *)fipsEcdsaR256r1KatPubKey,
					       sizeof(fipsEcdsaR256r1KatPubKey),
					       pUserPublKey,
					       pTempBuff);
        if (rc!=CC_OK) {
                fipsRc = CC_TEE_FIPS_ERROR_ECDSA_VERIFY_PUT;
		goto End;
	}

	// Verify the signature
	rc = CC_EcdsaVerify(pVerifyUserContext, pUserPublKey,
				CC_ECPKI_HASH_SHA256_mode,
				(uint8_t *)pDataSignOut, dataSignOutSize,
				(uint8_t *)fipsEcdsaR256r1KatDataIn, sizeof(fipsEcdsaR256r1KatDataIn));
	if (rc!=CC_OK) {
                fipsRc = CC_TEE_FIPS_ERROR_ECDSA_VERIFY_PUT;
		goto End;
	}

	FipsSetTrace(CC_FIPS_TRACE_ECDSA_PUT);

End:
	CC_PalMemSetZero(p_rng, sizeof(CCRndState_t));
    *f_rng=NULL;
	CC_PalMemSetZero(pFipsCtx, sizeof(CCEcdsaFipsKatContext_t));
    return fipsRc;
}


/* KAT test for ECDH.  */
CCFipsError_t CC_FipsEcdhKat(CCEcdhFipsKatContext_t    *pFipsCtx)
{
        CCError_t	        rc;
        CCFipsError_t	        fipsRc = CC_TEE_FIPS_ERROR_OK;
        CCEcpkiUserPublKey_t *pPartnerPublKey;
	CCEcpkiUserPrivKey_t *pUserPrivKey;
	CCEcdhTempData_t     *pEcdhTempBuff;
	CCEcpkiBuildTempData_t  *pEcpkiTempBuff;
	uint8_t			 *pSecretBuff;
	size_t		 	  secretBuffSize;


	if (pFipsCtx == NULL) {
                return CC_TEE_FIPS_ERROR_ECDH_PUT;
	}

	pPartnerPublKey = &pFipsCtx->pubKey;
	pUserPrivKey = &pFipsCtx->privKey;
	pEcdhTempBuff = &pFipsCtx->tmpData.ecdhTempBuff;
	pEcpkiTempBuff = &pFipsCtx->tmpData.ecpkiTempData;
	pSecretBuff = pFipsCtx->secretBuff;
	secretBuffSize = sizeof(pFipsCtx->secretBuff);

        // Build other pertner Public key
	rc = CC_EcpkiPubKeyBuildAndFullCheck(CC_EcpkiGetEcDomain(FIPS_ECC_DOMAIN_TYPE),
					       (uint8_t *)fipsEcdhR256r1KatPartnerPubKey,
					       sizeof(fipsEcdhR256r1KatPartnerPubKey),
					       pPartnerPublKey,
					       pEcpkiTempBuff);
	if (rc != CC_OK) {
                fipsRc = CC_TEE_FIPS_ERROR_ECDH_PUT;
		goto End;
	}

        // Build user private key
	rc = CC_EcpkiPrivKeyBuild(CC_EcpkiGetEcDomain(FIPS_ECC_DOMAIN_TYPE),
					(uint8_t *)fipsEcdhR256r1KatUserPrivKey,
					sizeof(fipsEcdhR256r1KatUserPrivKey),
					pUserPrivKey);
	if (rc != CC_OK) {
                fipsRc = CC_TEE_FIPS_ERROR_ECDH_PUT;
		goto End;
	}

        // Generate the secrete
	rc = CC_EcdhSvdpDh(pPartnerPublKey,
                               pUserPrivKey,
                               pSecretBuff,
                               &secretBuffSize,
                               pEcdhTempBuff);
        if ((rc!=CC_OK) || (secretBuffSize != sizeof(pFipsCtx->secretBuff))) {
                fipsRc = CC_TEE_FIPS_ERROR_ECDH_PUT;
		goto End;
	}

	// Verify secret is the same as expected
	rc = CC_PalMemCmp((uint8_t *)fipsEcdhR256r1KatSecret, pSecretBuff, secretBuffSize);
	if (rc != CC_OK) {
                fipsRc = CC_TEE_FIPS_ERROR_ECDH_PUT;
		goto End;
	}

	FipsSetTrace(CC_FIPS_TRACE_ECDH_PUT);

End:
	CC_PalMemSetZero(pFipsCtx, sizeof(CCEcdhFipsKatContext_t));
        return fipsRc;
}
