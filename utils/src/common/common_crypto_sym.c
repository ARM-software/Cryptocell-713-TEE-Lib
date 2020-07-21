/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/cmac.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include "cc_pal_types.h"
#include "common_crypto_sym.h"
#include "common_util_log.h"
#include "common_util_files.h"

/**
* @brief Encrypts (AES CTR) a given data and returns it.
*
* @param[in] pDataIn - the data to encrypt
* @param[in] dataInSize - the data size
* @param[in] pKey - the AES key
* @param[in] keySize - AES key size (must be one of the allowed AES key sizes)
* @param[in] pIV - IV (AES IV size is constant)
* @param[out] pEncBuff - the encrypted buffer
*/
/*********************************************************/
int32_t CC_CommonAesCtrEncrypt(uint8_t *pDataIn,
                               uint32_t dataInSize,
                               uint8_t *pKey,
                               uint32_t keySize,
                               uint8_t *pIV,
                               uint8_t *pEncBuff)
{
	AES_KEY key;
	uint8_t m_iv[AES_BLOCK_SIZE];
	uint8_t m_ecount_buf[AES_BLOCK_SIZE];
	uint32_t m_num = 0;
	int32_t ret = (-1);

	if ((NULL == pDataIn) ||
	    (NULL == pKey) ||
	    (NULL == pIV) ||
	    (NULL == pEncBuff)) {
		UTIL_LOG_ERR("ilegal input\n");
		return -1;
	}
	memcpy (m_iv, pIV, sizeof (m_iv));
	memset (m_ecount_buf, 0, sizeof (m_ecount_buf));

	/* Initialize an AES_KEY from raw key bytes */
	ret = AES_set_encrypt_key (pKey, keySize * 8, &key);
	if (ret != 0) {
		UTIL_LOG_ERR("\n AES_set_encrypt_key failed");
		return -1;
	}
	/* Encrypting data and sending it to the destination */
	AES_ctr128_encrypt (pDataIn, pEncBuff, dataInSize, &key, m_iv, m_ecount_buf, &m_num);

	return 0;
}

static int32_t CC_CommonReadPassword(char *strbuf, size_t strbufLen, int enc)
{
    int32_t ret = 0;
    int32_t i = 0;

    for (;;) {
        char buf[200] = { 0 };

        snprintf(buf, sizeof buf, "enter key %s password:", (enc) ? "encryption" : "decryption");
        strbuf[0] = '\0';
        i = EVP_read_pw_string(strbuf, strbufLen, buf, enc);
        if (i == 0) {
            if (strbuf[0] == '\0') {
                ret = 1;
                goto end;
            }
            break;
        }
        if (i < 0) {
            UTIL_LOG_ERR("bad password read\n");
            goto end;
        }
    }

end:

    return ret;
}
/**
* @brief The CC_CommonAesCbcDecrypt decrypts (AES CBC) a given data
*               and returns the decrypted buffer. data was encrypted using:
* 	"openssl enc -e -nosalt -aes-128-cbc -in <in_file,bin> -out <out_file.bin> -pass file:<pwd_file.txt>"
* @param[in] pwdFileName - file name for passsword to generate key and IV from
* @param[in] pEncBuff - the encrypted buffer- input buffer
* @param[in] encBuffSize - the encrypted buffer size
* @param[out] pDecBuff -the decrypted buffer.
*
* NOTE: pDecBuff - alocated size must be multiple of 16 bytes. same as encBuffSize
*/
/*********************************************************/
int32_t CC_CommonAesCbcDecrypt(char *pwdFileName,
                               uint8_t *pEncBuff,
                               uint32_t encBuffSize,
                               uint8_t *pDecBuff)
{
    char *pwdBuff = NULL;
    int32_t pwdBuffLen = 0;
    const EVP_CIPHER *cipher = NULL;
    const EVP_MD *dgst = NULL;
    uint8_t keyBuff[EVP_MAX_KEY_LENGTH] = {0x0};
    uint8_t ivBuff[EVP_MAX_KEY_LENGTH] = {0x0};
    AES_KEY aesKey;
    int32_t status = 1;
    static const size_t PWD_BUFF_SIZE = 512;

    if ((NULL == pEncBuff) ||
                    (NULL == pDecBuff)) {
        UTIL_LOG_ERR("ilegal input\n");
        return 1;
    }

    /* parse the passphrase for a given file */
    if ((NULL != pwdFileName)) {
        if (CC_CommonGetPassphrase(pwdFileName, (uint8_t**)&pwdBuff)) {
            UTIL_LOG_ERR("Failed to retrieve pwd\n");
            status = 1;
            goto END;
        }
        pwdBuffLen = strlen(pwdBuff);
    } else {
        pwdBuff = malloc(PWD_BUFF_SIZE);
        if (!pwdBuff) {
            UTIL_LOG_ERR("Failed to malloc pwdBuff\n");
            status = 1;
            goto END;
        }

        if (CC_CommonReadPassword(pwdBuff, PWD_BUFF_SIZE, 1)) {
            UTIL_LOG_ERR("Failed to CC_CommonReadPassword\n");
        }

        pwdBuffLen = strnlen(pwdBuff, PWD_BUFF_SIZE - 1);
    }

    /* get the IV and key from pwd */
    cipher = EVP_get_cipherbyname("aes-128-cbc");
    if (NULL == cipher) {
        UTIL_LOG_ERR("EVP_get_cipherbyname failed\n");
        status = 1;
        goto END;
    }

    dgst = EVP_get_digestbyname("md5");
    if (NULL == dgst) {
        UTIL_LOG_ERR("EVP_get_digestbyname failed\n");
        status = 1;
        goto END;
    }

    status = EVP_BytesToKey(cipher,
                            dgst,
                            NULL,
                            (uint8_t *) pwdBuff,
                            pwdBuffLen,
                            1,
                            keyBuff,
                            ivBuff);
    if (0 == status) {
        UTIL_LOG_ERR("EVP_BytesToKey failed\n");
        status = 1;
        goto END;
    }

    /* key and IV are ready, start decryption */
    memset (pDecBuff, 0, encBuffSize);  /* encBuffSize is multiple of 16 bytes */

    /* Initialize an AES_KEY from raw key bytes */
    status = AES_set_decrypt_key (keyBuff, 128, &aesKey);
    if (status != 0) {
        UTIL_LOG_ERR("\n AES_set_encrypt_key failed");
        status = 1;
        goto END;
    }
    /* Encrypting data and sending it to the destination */
    AES_cbc_encrypt(pEncBuff, pDecBuff, encBuffSize, &aesKey, ivBuff, AES_DECRYPT);

    status = 0;
END:
    if (pwdBuff != NULL) {
        free(pwdBuff);
    }
    return status;
}

/**
* @brief Encrypts AES CBC-MAC a given data
*               and returns the encrypted buffer.
*
* @param[in] pKey - key buffer
* @param[in] pIv - iv buffer
* @param[in] pBuff - the plaintext buffer
* @param[in] encBuffSize - the plaintext buffer size
* @param[in] pEncMacBuff -the encrypted - ciphertext buffer.
* @param[out] pEncMacBuff -the encrypted - ciphertext buffer.
*
*/
/*********************************************************/
int32_t CC_CommonAesCbcMacEncrypt(uint8_t *pKey,
                                  uint8_t *pIv,
                                  uint8_t *pBuff,
                                  uint32_t buffSize,
                                  uint32_t macSize,
                                  uint8_t *pEncMacBuff)
{
	AES_KEY aesKey;
	int32_t status = 1;
	uint8_t *pOutBuff = NULL;

	if ((NULL == pKey) ||
	    (NULL == pIv) ||
	    (NULL == pBuff) ||
	    (NULL == pEncMacBuff) ||
	    (0 == buffSize)) {
		UTIL_LOG_ERR("ilegal input\n");
		return 1;
	}

	memset (pEncMacBuff, 0, macSize);  /* buffSize is multiple of 16 bytes */

	pOutBuff = malloc(buffSize);
	if (NULL == pOutBuff) {
		UTIL_LOG_ERR("malloc failed\n");
		return 1;
	}

	/* Initialize an AES_KEY from raw key bytes */
	status = AES_set_encrypt_key(pKey, 128, &aesKey);
	if (status != 0) {
		UTIL_LOG_ERR("\n AES_set_encrypt_key failed");
		status = 1;
		goto END;
	}
	/* Encrypting data and sending it to the destination */
	AES_cbc_encrypt(pBuff, pOutBuff, buffSize, &aesKey, pIv, AES_ENCRYPT);
	memcpy(pEncMacBuff, pOutBuff, macSize);

	status = 0;
	END:
	if (pOutBuff != NULL) {
		free(pOutBuff);
	}
	return status;
}


/**
* @brief Encrypts (AES CCM) a given data and returns it.
*
* @param[in] pDataIn - the data to encrypt
* @param[in] dataInSize - the data size
* @param[in] pKey - the AES key
* @param[in] keySize - AES key size (must be one of the allowed AES key sizes)
* @param[out] pOutput - Output buffer
*/
/*********************************************************/
int32_t CC_CommonAesCcmEncrypt(uint8_t *keyBuf,
                               uint8_t *nonce,
                               uint32_t nonceLen,
                               uint8_t *aData,
                               uint32_t aDatalen,
                               uint8_t *plainTxt,
                               uint32_t plainTxtLen,
                               uint8_t *enBuff,
                               uint8_t *tagBuff,
                               uint32_t tagBuffLen)
{
	EVP_CIPHER_CTX ccm_ctx;
	int32_t outlen = 0;
	int32_t rc  = 0;

	if ((NULL == keyBuf) ||
	    (NULL == nonce) ||
	    (NULL == plainTxt) ||
	    (NULL == enBuff) ||
	    (NULL == tagBuff)) {
		UTIL_LOG_ERR( "invalid input pointers\n");
		return 1;
	}
	/* check legth validity*/
        if (enBuff != plainTxt) {
                memset(enBuff, 0, plainTxtLen);
        }
	memset(tagBuff, 0, tagBuffLen);


	EVP_CIPHER_CTX_init(&ccm_ctx);

	/* Set cipher type and mode */
	rc  = EVP_EncryptInit_ex(&ccm_ctx, EVP_aes_128_ccm(), NULL, NULL, NULL);
	if (rc != 1) {
		UTIL_LOG_ERR( "failed to EVP_EncryptInit_ex() for CCM cipher\n");
		rc = 1;
		goto ccmEnd;
	}
	/* Set nonce length if default 96 bits is not appropriate */
	rc  = EVP_CIPHER_CTX_ctrl(&ccm_ctx, EVP_CTRL_CCM_SET_IVLEN, nonceLen, NULL);
	if (rc != 1) {
		UTIL_LOG_ERR( "failed to EVP_CIPHER_CTX_ctrl() for nonce length\n");
		rc = 1;
		goto ccmEnd;
	}
	/* Set tag length */
	rc  = EVP_CIPHER_CTX_ctrl(&ccm_ctx, EVP_CTRL_CCM_SET_TAG, tagBuffLen, NULL);
	if (rc != 1) {
		UTIL_LOG_ERR( "failed to EVP_CIPHER_CTX_ctrl() for tag length\n");
		rc = 1;
		goto ccmEnd;
	}
	/* Initialise key and IV */
	UTIL_LOG_BYTE_BUFF("nonce", nonce, nonceLen);
	UTIL_LOG_BYTE_BUFF("keyBuf", keyBuf, 16);
	rc  = EVP_EncryptInit_ex(&ccm_ctx, NULL, NULL, keyBuf, nonce);
	if (rc != 1) {
		UTIL_LOG_ERR( "failed to EVP_EncryptInit_ex() for key and IV\n");
		rc = 1;
		goto ccmEnd;
	}
	if ((aDatalen>0) && (aData != NULL)) {
		/* Set plaintext length: only needed if AAD is used */
		rc  = EVP_EncryptUpdate(&ccm_ctx, NULL, &outlen, NULL, plainTxtLen);
		if (rc != 1) {
			UTIL_LOG_ERR( "failed to EVP_EncryptUpdate() for plaintext length\n");
			rc = 1;
			goto ccmEnd;
		}
		/* Zero or one call to specify any AAD */
		UTIL_LOG_BYTE_BUFF("aData", aData, aDatalen);
		rc  = EVP_EncryptUpdate(&ccm_ctx, NULL, &outlen, aData, aDatalen);
		if (rc != 1) {
			UTIL_LOG_ERR( "failed to EVP_EncryptUpdate() for AAD\n");
			rc = 1;
			goto ccmEnd;
		}
	}

	/* Encrypt plaintext: can only be called once */
	UTIL_LOG_BYTE_BUFF("plainTxt", plainTxt, CC_COMMON_MIN(plainTxtLen, 0x40));
	rc  = EVP_EncryptUpdate(&ccm_ctx, enBuff, &outlen, plainTxt, plainTxtLen);
	if (rc != 1) {
		UTIL_LOG_ERR( "failed to EVP_EncryptUpdate() for plaintext\n");
		rc = 1;
		goto ccmEnd;
	}
	if (outlen != (int32_t)plainTxtLen) {
		UTIL_LOG_ERR( "ccm encrypt size(%d) != palin text size(%d)\n", outlen, plainTxtLen);
		rc = 1;
		goto ccmEnd;
	}
	UTIL_LOG_BYTE_BUFF("enBuff", enBuff, CC_COMMON_MIN(outlen, 0x40));
	/* Finalise: note get no output for CCM */
	rc  = EVP_EncryptFinal_ex(&ccm_ctx, &enBuff[outlen], &outlen);
	if (rc != 1) {
		UTIL_LOG_ERR( "failed to EVP_EncryptFinal_ex()\n");
		rc = 1;
		goto ccmEnd;
	}
	/* Get tag */
	rc  = EVP_CIPHER_CTX_ctrl(&ccm_ctx, EVP_CTRL_CCM_GET_TAG, tagBuffLen, tagBuff);
	if (rc != 1) {
		UTIL_LOG_ERR( "failed to EVP_CIPHER_CTX_ctrl() to get the tag\n");
		rc = 1;
		goto ccmEnd;
	}
	UTIL_LOG_BYTE_BUFF("tagBuff", tagBuff, tagBuffLen);
	rc = 0;

	ccmEnd:

	EVP_CIPHER_CTX_cleanup(&ccm_ctx);
	return rc;
}



/**
* @brief Encrypts (AES CMAC) a given data and returns it.
*
* @param[in] pDataIn - the data to encrypt
* @param[in] dataInSize - the data size
* @param[in] pKey - the AES key
* @param[in] keySize - the key size in bytes
* @param[in] pOutput - Output buffer
*/
/*********************************************************/
int32_t CC_CommonAesCmacEncrypt(uint8_t *pDataIn,
                                uint32_t dataInSize,
                                uint8_t *pKey,
                                uint32_t keySize,
                                uint8_t *pOutput)
{
	CMAC_CTX *cmac_ctx = NULL;
	int32_t rc = 0;
	size_t tempOutSize = 0;

	if ((NULL == pKey) ||
	    (NULL == pDataIn) ||
	    (NULL == pOutput) ||
	    ((keySize != AES_BLOCK_SIZE) && (keySize != (AES_BLOCK_SIZE*2)))) {
		UTIL_LOG_ERR( "Ilegal parameters\n");
		return 1;
	}
	cmac_ctx = CMAC_CTX_new();
	if (NULL == cmac_ctx) {
		UTIL_LOG_ERR( "failed to CMAC_CTX_new\n");
		return 1;
	}
	memset(pOutput, 0, AES_BLOCK_SIZE);
	if (AES_BLOCK_SIZE == keySize) {
		rc = CMAC_Init(cmac_ctx, pKey, AES_BLOCK_SIZE, EVP_aes_128_cbc(), 0);
	} else {
		rc = CMAC_Init(cmac_ctx, pKey, AES_BLOCK_SIZE*2, EVP_aes_256_cbc(), 0);
	}
	if (rc != 1) {
		UTIL_LOG_ERR( "failed to CMAC_Init\n");
		rc = 2;
		goto cmacEnd;
	}
	rc = CMAC_Update(cmac_ctx, pDataIn, dataInSize);
	if (rc != 1) {
		UTIL_LOG_ERR( "failed to CMAC_Update\n");
		rc = 3;
		goto cmacEnd;
	}
	rc = CMAC_Final(cmac_ctx, pOutput, &tempOutSize);
	if (rc != 1) {
		UTIL_LOG_ERR( "failed to CMAC_Final\n");
		rc = 4;
		goto cmacEnd;
	}
	rc = 0;
	cmacEnd:
	if (cmac_ctx != NULL) {
		CMAC_CTX_free(cmac_ctx);
	}
	return rc;
}


/**
 * @brief Calculates HASH on a given buffer, and returns the digest
 *
 * @param[in] pPemDecryted - the decrypted public key (input data for HASH)
 * @param[out] pHash - the HASH SHA 256 calculated on the data
 *
 */
/*********************************************************/
int32_t CC_CommonCalcHash(uint8_t *pPemDecryted,
                          uint32_t pemDecryptedSize,
                          uint8_t *pHash,
                          uint32_t hashSize)
{

	uint8_t hash[HASH_SHA256_DIGEST_SIZE_IN_BYTES];

	/* Verify no NULL pointers */
	if ((pPemDecryted == NULL) ||
	    (pHash == NULL)) {
		UTIL_LOG_ERR("Illegal parameters \n");
		return -1;
	}

	/* verify the size is correct */
	if ((hashSize != HASH_SHA256_DIGEST_SIZE_IN_BYTES) && (hashSize != HASH_SHA256_DIGEST_SIZE_IN_BYTES/2)) {
		UTIL_LOG_ERR("The digest size is incorrect it can either be %d or %d, given digest size is %d\n", HASH_SHA256_DIGEST_SIZE_IN_BYTES, HASH_SHA256_DIGEST_SIZE_IN_BYTES/2, hashSize);
		return -1;
	}

	/* Calculate the hash */
	SHA256(pPemDecryted, pemDecryptedSize,hash);

	/* copy the hash according to requested size */
	memcpy(pHash, hash, hashSize);
	return 0;

}


/**
 * @brief Calculates HASH on a given buffer, and returns the digest
 *
 * @param[in] pPemDecryted - the decrypted public key (input data for HASH)
 * @param[out] pHash - the HASH SHA 256 calculated on the data
 *
 */
/*********************************************************/
int32_t CC_CommonCalcSha1(uint8_t *pDataIn, uint32_t dataInSize, uint8_t *pHash)
{
	uint8_t hash[HASH_SHA1_DIGEST_SIZE_IN_BYTES];

	/* Verify no NULL pointers */
	if ((pDataIn == NULL) ||
	    (pHash == NULL)) {
		UTIL_LOG_ERR("Illegal parameters \n");
		return -1;
	}

	/* Calculate the hash */
	SHA1(pDataIn, dataInSize, hash);

	/* copy the hash according to requested size */
	memcpy(pHash, hash, HASH_SHA1_DIGEST_SIZE_IN_BYTES);
	return 0;

}


/**
* @brief Encrypts (AES ECB) a given data and returns it.
*
* @param[in] pDataIn - the data to encrypt
* @param[in] dataInSize - the data size. currently support only size 16.
* @param[in] pKey - the AES key
* @param[in] keySize - AES key size (must be one of the allowed AES key sizes)
* @param[out] pEncBuff - the encrypted buffer
*/
/*********************************************************/
int32_t CC_CommonAesEcbEncrypt(uint8_t *pDataIn,
                               uint32_t dataInSize,
                               uint8_t *pKey,
                               uint32_t keySize,
                               uint8_t *pEncBuff)
{
	#define BITS_WITHIN_BYTE 8

	int rc = 0;
	AES_KEY encKey;

	if ((NULL == pDataIn) ||
	    (NULL == pKey) ||
	    (NULL == pEncBuff)) {
		UTIL_LOG_ERR("ilegal input\n");
		return 1;
	}

	if (dataInSize != 16) {
		UTIL_LOG_ERR("dataInSize must be 16\n");
		return 1;
	}

	UTIL_LOG_ERR("About to AES_set_encrypt_key\n");
	rc = AES_set_encrypt_key(pKey, (keySize*BITS_WITHIN_BYTE), &encKey);
	if (rc != 0) {
		UTIL_LOG_ERR("Failed AES_set_encrypt_key\n");
		return 1;
	}

	/* Encrypting data and sending it to the destination */
	UTIL_LOG_ERR("About to AES_ecb_encrypt byteCount\n");
	AES_ecb_encrypt(pDataIn, pEncBuff, &encKey, AES_ENCRYPT);

	return 0;
}


/**
* @brief Calculates HMAC with SHA256.
*
* @param[in] pDataIn - the data to encrypt
* @param[in] dataInSize - the data size
* @param[in] pKey - the AES key
* @param[in] keySize - AES key size (must be one of the allowed AES key sizes)
* @param[out] pResultBuff - the HMAC sha256 result buffer
*/
/*********************************************************/
int32_t CC_CommonHmac256(uint8_t *pKey,
                         uint32_t keySize,
                         uint8_t *pDataIn,
                         uint32_t dataInSize,
                         uint8_t *pResultBuff)
{
        unsigned int result_len = HASH_SHA256_DIGEST_SIZE_IN_BYTES;
        unsigned char result[HASH_SHA256_DIGEST_SIZE_IN_BYTES];

	if ((NULL == pDataIn) ||
	    (NULL == pKey) ||
	    (NULL == pResultBuff)) {
		UTIL_LOG_ERR("ilegal input\n");
		return 1;
	}
        memset(pResultBuff, 0, HASH_SHA256_DIGEST_SIZE_IN_BYTES);

	UTIL_LOG_BYTE_BUFF("pKey", pKey, keySize);
	UTIL_LOG_BYTE_BUFF("pDataIn", pDataIn, dataInSize);
	if (HMAC(EVP_sha256(), pKey, keySize, pDataIn, dataInSize, result, &result_len) != (unsigned char *)NULL) {
                memcpy(pResultBuff, result, HASH_SHA256_DIGEST_SIZE_IN_BYTES);
        }
	UTIL_LOG_BYTE_BUFF("pResultBuff", pResultBuff, HASH_SHA256_DIGEST_SIZE_IN_BYTES);

	return 0;
}


/**
* @brief performs CMAC key derivation for Kprov using openSSL library
*
* @param[in]  pKey & keySize - Kpicv key and its size
* 		lable & pContext & contextSize used to build the dataIn for derivation
* @param[out] pOutKey - Kprov
*
*/
/*********************************************************/
int CC_CommonAesCmacKeyDerivation(uint8_t *pKey,
                                  uint32_t keySize,
                                  uint8_t *pLabel,
                                  uint32_t labelSize,
                                  uint8_t *pContext,
                                  uint32_t contextSize,
                                  uint8_t *pOutKey,
                                  uint32_t outKeySize)
{
    int rc = 0;
    int index = 0;
    uint8_t *pDataIn = NULL;

    if ((pKey == NULL) ||
                    (keySize != AES_BLOCK_SIZE) ||
                    (pLabel == NULL) ||
                    (pContext == NULL) ||
                    (pOutKey == NULL) ||
                    (outKeySize != AES_BLOCK_SIZE)) {
        UTIL_LOG_ERR( "Invalid inputs\n");
        return (-1);
    }
    pDataIn = calloc(labelSize+contextSize+3, sizeof(char));  // +3 for: iteration, key size and 0x0
    if (pDataIn == NULL) {
        UTIL_LOG_ERR( "Failed calloc\n");
        return (-1);
    }

    /* Create the input to the CMAC derivation
           since key size is 16 bytes, we have 1 iteration for cmac  derivation*
           the data or the derivation:
           0x1 || label || 0x0 || context || size of derived key in bits */
    pDataIn[index++] = 0x1;
    memcpy(&pDataIn[index], pLabel, labelSize);
    index += labelSize;
    pDataIn[index++] = 0x0;
    memcpy(&pDataIn[index], pContext, contextSize);
    index += contextSize;
    pDataIn[index++] = outKeySize*CC_BITS_IN_BYTE; // size of the key in bits

    UTIL_LOG_BYTE_BUFF("pDataIn", pDataIn, index);
    UTIL_LOG_BYTE_BUFF("pKey", pKey, keySize);
    rc = CC_CommonAesCmacEncrypt(pDataIn, index,
                                 pKey, keySize, pOutKey);
    if (rc != 0) {
        UTIL_LOG_ERR( "failed to CC_CommonAesCmacEncrypt(), rc %d\n", rc);
        free(pDataIn);
        return (-1);
    }
    UTIL_LOG_BYTE_BUFF("pOutKey", pOutKey, outKeySize);
    free(pDataIn);
    return rc;
}



