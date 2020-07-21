/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include "cc_pal_log.h"
#include "cc_pal_types.h"
#include "cc_pal_mem.h"
#include "cc_rsa_types.h"
#include "cc_rsa_build.h"
#include "cc_rsa_schemes.h"
#include "cc_fips.h"
#include "cc_fips_error.h"
#include "cc_fips_defs.h"
#include "cc_fips_rsa_defs.h"
#include "cc_fips_rsa_kat_data.h"


#define RSA_KAT_RND_STATE_ENCRYPTION  1
#define RSA_KAT_RND_STATE_SIGNATURE  2


// taken the smaller hash digest, after hash is not supported
#define FIPS_RSA_HASH_TYPE  	CC_RSA_HASH_SHA1_mode
// for scheme 2.1, dataIn size must be smaller than modulus size (minimum 512 bits) minus 2*hashDigest minuns 2
// this leads to 64-2*20-2 = 22 bytes of data in size; same size as CCRsaKgFipsContext_t->decBuff
#define FIPS_RSA_DATA_SIZE  	((CC_RSA_MIN_VALID_KEY_SIZE_VALUE_IN_BITS/CC_BITS_IN_BYTE) - 2*(CC_HASH_SHA1_DIGEST_SIZE_IN_BYTES) -2)  // total of 22


typedef uint8_t        FipsRsaDecrypedData_t[FIPS_RSA_DATA_SIZE];
typedef uint8_t        FipsRsaEncrypedData_t[CC_RSA_MAX_KEY_GENERATION_HW_SIZE_BITS/CC_BITS_IN_BYTE];

// input data for RSA conditional test - randomaly chossen
static const	uint8_t         rsaFipsDataIn[FIPS_RSA_DATA_SIZE] =
		{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		 0x10, 0x01, 0x02, 0x03, 0x04, 0x05 };



// The function performs RSA KAT encrypt & decrypt test according to test vectors
static CCFipsError_t fipsRsaKatEncryptTest(CCRndGenerateVectWorkFunc_t f_rng,
                               void *p_rng,
			                   CCRsaFipsKatContext_t    *pFipsCtx)
{
	uint32_t rc = CC_TEE_FIPS_ERROR_OK;
	CCRsaUserPubKey_t 	*pUserPubKey;
	CCRsaUserPrivKey_t   *pUserPrivKey;
	CCRsaPrimeData_t	*pPrimeData;
	uint8_t 		*pDataOutEnc;
	uint8_t 		*pDataOutDec;
	size_t 			outDataSize;
    CCRndState_t    * rndState_ptr;

	if ((pFipsCtx == NULL)) {
                return CC_TEE_FIPS_ERROR_GENERAL;
	}

	pUserPubKey = &pFipsCtx->userKey.userPubKey;
	pUserPrivKey = &pFipsCtx->userKey.userPrivKey;
	pPrimeData = &pFipsCtx->userContext.primData;
	pDataOutDec = pFipsCtx->userData.userOaepData.decBuff;
	pDataOutEnc = pFipsCtx->userData.userOaepData.encBuff;

        // Build public key for encryption
	rc = CC_RsaPubKeyBuild(pUserPubKey,
			   (uint8_t *)fipsRsaOaepKatPubExponent,
			   sizeof(fipsRsaOaepKatPubExponent),
			   (uint8_t *)fipsRsaOaepKat2048Modulus,
			   sizeof(fipsRsaOaepKat2048Modulus));
	if (rc != CC_OK) {
		return CC_TEE_FIPS_ERROR_RSA_ENC_PUT;
	}

	// Encrypt known data
	rndState_ptr = (CCRndState_t *)p_rng;
    if (rndState_ptr == NULL)
    {
        return CC_TEE_FIPS_ERROR_GENERAL;
    }
	rndState_ptr->StateFlag = RSA_KAT_RND_STATE_ENCRYPTION;
	rc = CC_RsaOaepEncrypt(f_rng,
	                p_rng,
					pUserPubKey,
					pPrimeData,
					FIPS_RSA_HASH_TYPE,
					NULL, 0,
					CC_PKCS1_MGF1,
					(uint8_t *)fipsRsaOaepKatDataIn,sizeof(fipsRsaOaepKatDataIn),
					pDataOutEnc);
	if (rc != CC_OK) {
		return CC_TEE_FIPS_ERROR_RSA_ENC_PUT;
	}

	// Verify encrypted data is as expected
	rc = CC_PalMemCmp((uint8_t *)fipsRsaOaepKat2048ExpEncryption, pDataOutEnc, sizeof(fipsRsaOaepKat2048ExpEncryption));
	if (rc != CC_OK) {
		return CC_TEE_FIPS_ERROR_RSA_ENC_PUT;
	}

        // Build private key for decrypt
	rc = CC_RsaPrivKeyBuild(pUserPrivKey,
				(uint8_t *)fipsRsaOaepKat2048PrivExpD,
				sizeof(fipsRsaOaepKat2048PrivExpD),
				(uint8_t *)fipsRsaOaepKatPubExponent,
				sizeof(fipsRsaOaepKatPubExponent),
				(uint8_t *)fipsRsaOaepKat2048Modulus,
				sizeof(fipsRsaOaepKat2048Modulus));
	if (rc != CC_OK) {
		return CC_TEE_FIPS_ERROR_RSA_DEC_PUT;
	}

	// Decrypt the encrypted data
	outDataSize = sizeof(fipsRsaOaepKatDataIn);
	rc = CC_RsaOaepDecrypt(pUserPrivKey,
					pPrimeData,
					FIPS_RSA_HASH_TYPE,
					NULL, 0,
					CC_PKCS1_MGF1,
					pDataOutEnc,sizeof(fipsRsaOaepKat2048Modulus),
					pDataOutDec, &outDataSize);
	if (rc != CC_OK) {
		return CC_TEE_FIPS_ERROR_RSA_DEC_PUT;
	}

	// Verify decrypted data equals to input
	rc = CC_PalMemCmp(fipsRsaOaepKatDataIn, pDataOutDec, sizeof(fipsRsaOaepKatDataIn));

        CC_PAL_LOG_ERR("rc=0x%x, size=%d, dataOut: 0x%x 0x%x 0x%x ... 0x%x, dataOutActual: 0x%x 0x%x 0x%x ... 0x%x\n", rc, (int)sizeof(fipsRsaOaepKatDataIn),
                (unsigned int)fipsRsaOaepKatDataIn[0], (unsigned int)fipsRsaOaepKatDataIn[1], (unsigned int)fipsRsaOaepKatDataIn[2], (unsigned int)fipsRsaOaepKatDataIn[sizeof(fipsRsaOaepKatDataIn)-1],
                (unsigned int)pDataOutDec[0], (unsigned int)pDataOutDec[1], (unsigned int)pDataOutDec[2], (unsigned int)pDataOutDec[sizeof(fipsRsaOaepKatDataIn)-1]);

	if (rc != CC_OK) {
		return CC_TEE_FIPS_ERROR_RSA_DEC_PUT;
	}

        return CC_TEE_FIPS_ERROR_OK;
}

// The function performs RSA KAT sign & verify test according to test vectors
static CCFipsError_t fipsRsaKatSignTest(CCRndGenerateVectWorkFunc_t f_rng,
                          void *p_rng,
			              CCRsaFipsKatContext_t    *pFipsCtx)
{
	uint32_t rc = CC_TEE_FIPS_ERROR_OK;
	CCRsaUserPubKey_t 	*pUserPubKey;
	CCRsaUserPrivKey_t   *pUserPrivKey;
	CCRsaPrivUserContext_t *pUserPrivContext;
	CCRsaPubUserContext_t  *pUserPubContext;
	uint8_t 		*pDataOutSign;
	size_t   		outDataSize;
    CCRndState_t    * rndState_ptr;

	if (pFipsCtx == NULL) {
                return CC_TEE_FIPS_ERROR_GENERAL;
	}

	pUserPubKey = &pFipsCtx->userKey.userPubKey;
	pUserPrivKey = &pFipsCtx->userKey.userPrivKey;
	pDataOutSign = pFipsCtx->userData.signBuff;
	pUserPrivContext = &pFipsCtx->userContext.userPrivContext;
	pUserPubContext = &pFipsCtx->userContext.userPubContext;
	CC_PalMemSetZero(pDataOutSign, sizeof(pFipsCtx->userData.signBuff));
	outDataSize = sizeof(pFipsCtx->userData.signBuff);

    rndState_ptr = (CCRndState_t *)p_rng;
    if (rndState_ptr == NULL)
    {
        return CC_TEE_FIPS_ERROR_GENERAL;
    }
	rndState_ptr->StateFlag = RSA_KAT_RND_STATE_SIGNATURE;

        // Build private key for sign operation
	rc = CC_RsaPrivKeyBuild(pUserPrivKey,
				(uint8_t *)fipsRsaPssKat2048PrivExponent,
				sizeof(fipsRsaPssKat2048PrivExponent),
				(uint8_t *)fipsRsaPssKatPubExponent,
				sizeof(fipsRsaPssKatPubExponent),
				(uint8_t *)fipsRsaPssKat2048Modulus,
				sizeof(fipsRsaPssKat2048Modulus));
	if (rc != CC_OK) {
		return CC_TEE_FIPS_ERROR_RSA_SIGN_PUT;
	}
        // Calculate signature
	rc  = CC_RsaPssSign(f_rng,
	            p_rng,
				pUserPrivContext,
				pUserPrivKey,
				FIPS_RSA_HASH_TYPE,
				CC_PKCS1_MGF1,
				sizeof(fipsRsaPssKatSalt),
				(uint8_t *)fipsRsaPssKatDataIn, sizeof(fipsRsaPssKatDataIn),
				pDataOutSign, &outDataSize);
	if (rc != CC_OK) {
		return CC_TEE_FIPS_ERROR_RSA_SIGN_PUT;
	}

	// Verify signature data is as expected
	rc = CC_PalMemCmp(fipsRsaPssKat2048ExpSignature, pDataOutSign, sizeof(fipsRsaPssKat2048ExpSignature));
	if (rc != CC_OK) {
		return CC_TEE_FIPS_ERROR_RSA_SIGN_PUT;
	}

        // Build private key for verify operation
	rc = CC_RsaPubKeyBuild(pUserPubKey,
			   (uint8_t *)fipsRsaPssKatPubExponent,
			   sizeof(fipsRsaPssKatPubExponent),
			   (uint8_t *)fipsRsaPssKat2048Modulus,
			   sizeof(fipsRsaPssKat2048Modulus));
	if (rc != CC_OK) {
		return CC_TEE_FIPS_ERROR_RSA_VERIFY_PUT;
	}

        // Verify signature
	rc  = CC_RsaPssVerify(pUserPubContext,
				   pUserPubKey,
				   FIPS_RSA_HASH_TYPE,
				   CC_PKCS1_MGF1,
				   sizeof(fipsRsaPssKatSalt),
				   (uint8_t *)fipsRsaPssKatDataIn, sizeof(fipsRsaPssKatDataIn),
				   pDataOutSign);
	if (rc != CC_OK) {
		return CC_TEE_FIPS_ERROR_RSA_VERIFY_PUT;
	}

        return CC_TEE_FIPS_ERROR_OK;
}


// The function is being called twice: once for encrypt and the second for sign
// the return vector is according to state flag
static CCError_t fipsRsaKatGenVector(void *rndState_vptr,
                                          unsigned char   *out_ptr,        /*out*/
                                          size_t    outSizeBytes)          /*in*/
{
	uint8_t* pFipsRsaOaepKatSeed = (uint8_t*)fipsRsaOaepKatSeed;
	CCRndState_t *rndState_ptr = NULL;
	if ((rndState_vptr == NULL) ||
            (out_ptr == NULL)) {
		return CC_FIPS_ERROR;
	}
	rndState_ptr = (CCRndState_t *)rndState_vptr;

	if (rndState_ptr->StateFlag == RSA_KAT_RND_STATE_ENCRYPTION) {
		if (outSizeBytes < sizeof(fipsRsaOaepKatSeed)) {
			return CC_FIPS_ERROR;
		}
		CC_PalMemCopy(out_ptr, pFipsRsaOaepKatSeed, sizeof(fipsRsaOaepKatSeed));
		return CC_OK;
	}
	if (rndState_ptr->StateFlag == RSA_KAT_RND_STATE_SIGNATURE) {
		if (outSizeBytes < sizeof(fipsRsaPssKatSalt)) {
			return CC_FIPS_ERROR;
		}
		CC_PalMemCopy(out_ptr, fipsRsaPssKatSalt, sizeof(fipsRsaPssKatSalt));
		return CC_OK;
	}
	return CC_FIPS_ERROR;
}

/* Conditional test for RSA. Use PKCS 2.1 for encrypt and decrypt */
CCError_t CC_FipsRsaConditionalTest(CCRndGenerateVectWorkFunc_t f_rng,
                void *p_rng,
				CCRsaUserPrivKey_t 	*pCcUserPrivKey,
				CCRsaUserPubKey_t  	*pCcUserPubKey,
				CCRsaKgFipsContext_t    *pFipsCtx)
{

        /* the error identifier */
        CCError_t 		rc = CC_OK;
        CCFipsError_t 		fipsRc = CC_TEE_FIPS_ERROR_GENERAL;
        uint32_t 		keySizeInBytes;
	size_t  		decDataSize;
	CCRsaPrimeData_t 	*pPrimeData;
	FipsRsaDecrypedData_t       *pDataDecOut;
	FipsRsaEncrypedData_t       *pDataEncOut;

	CHECK_AND_RETURN_UPON_FIPS_STATE();

        /* ...... checking the key database handle pointer .................... */
        if (pFipsCtx == NULL) {
                rc = CC_FIPS_ERROR;
		goto End;
	}
        if ((pCcUserPrivKey == NULL) ||
	    (pCcUserPubKey == NULL)) {
                rc = CC_FIPS_ERROR;
		goto End;
	}

	pPrimeData = &(pFipsCtx->primData);
	pDataDecOut = (FipsRsaDecrypedData_t *)pFipsCtx->decBuff;
	pDataEncOut = (FipsRsaEncrypedData_t *)pFipsCtx->encBuff;

	keySizeInBytes = ((((CCRsaPubKey_t *)(pCcUserPubKey->PublicKeyDbBuff))->nSizeInBits)/CC_BITS_IN_BYTE);

	// Encrypt known data
	rc = CC_RsaOaepEncrypt(f_rng, p_rng, pCcUserPubKey, pPrimeData,
					FIPS_RSA_HASH_TYPE,
					NULL, 0,
					CC_PKCS1_MGF1,
					(uint8_t *)rsaFipsDataIn,sizeof(rsaFipsDataIn),
					(uint8_t *)pDataEncOut);
	if (rc != CC_OK) {
                fipsRc = CC_TEE_FIPS_ERROR_RSA_ENC_COND;
		goto End;
	}

	// Verify encrypted data is diffenet than the input
	rc = CC_PalMemCmp((uint8_t *)rsaFipsDataIn, pDataEncOut, sizeof(rsaFipsDataIn));
	if (rc == CC_OK) {
                fipsRc = CC_TEE_FIPS_ERROR_RSA_ENC_COND;
		goto End;
	}

	// ecrypt th eencrypted data
	decDataSize = FIPS_RSA_DATA_SIZE;
	rc = CC_RsaOaepDecrypt(pCcUserPrivKey,
					pPrimeData,
					FIPS_RSA_HASH_TYPE,
					NULL, 0,
					CC_PKCS1_MGF1,
					(uint8_t *)pDataEncOut,keySizeInBytes,
					(uint8_t *)pDataDecOut, &decDataSize);
	if (rc != CC_OK) {
                fipsRc = CC_TEE_FIPS_ERROR_RSA_DEC_COND;
		goto End;
	}

	// Verify decrypted data equals to input
	rc = CC_PalMemCmp((uint8_t *)rsaFipsDataIn, pDataDecOut, sizeof(rsaFipsDataIn));
	if (rc != CC_OK) {
                fipsRc = CC_TEE_FIPS_ERROR_RSA_DEC_COND;
		goto End;
	}
	rc = FipsSetTrace(CC_FIPS_TRACE_RSA_COND);
	if (rc!=CC_OK) {
		rc = CC_FIPS_ERROR;
		goto End;
	}
End:
	if (rc != CC_OK) {
	    FipsSetError(fipsRc);
	    return CC_FIPS_ERROR;
	}
	return rc;

}/* END OF CC_FipsRsaConditionalTest */


// KAT for RSA:  use PKCS 2.1 for encrypt & decrypt, sign & verify
CCFipsError_t CC_FipsRsaKat(CCRndGenerateVectWorkFunc_t *f_rng, void *p_rng,
			    CCRsaFipsKatContext_t    *pFipsCtx)
{
        CCFipsError_t fipsRc = CC_TEE_FIPS_ERROR_OK;

        if ((f_rng == NULL) || (p_rng == NULL) || (pFipsCtx == NULL)) {
            return CC_TEE_FIPS_ERROR_GENERAL;
        }

        // set generate vector function, to return the expected vector according to test vectors
        *f_rng =  fipsRsaKatGenVector;


        // perform encrypt & decrypt test
        fipsRc = fipsRsaKatEncryptTest(*f_rng, p_rng, pFipsCtx);
        if (fipsRc != CC_TEE_FIPS_ERROR_OK) {
                goto End;
        }

        // perform sign & verify test
        fipsRc = fipsRsaKatSignTest(*f_rng, p_rng, pFipsCtx);
        if (fipsRc != CC_TEE_FIPS_ERROR_OK) {
                goto End;
        }

        FipsSetTrace(CC_FIPS_TRACE_RSA_PUT);

End:

        CC_PalMemSetZero(p_rng, sizeof(CCRndState_t));
        *f_rng = NULL;
    	CC_PalMemSetZero(pFipsCtx, sizeof(CCRsaFipsKatContext_t));

        return fipsRc;
} /* CC_FipsRsaKat */
