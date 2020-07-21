/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _COMMON_CRYPTO_SYM_H
#define _COMMON_CRYPTO_SYM_H

#include <stdint.h>
#include "cc_crypto_defs.h"

#define CC_COMMON_CALC_CBC_ENCODE_SIZE(size)  (AES_BLOCK_SIZE + (((size + AES_BLOCK_SIZE)/AES_BLOCK_SIZE)*AES_BLOCK_SIZE))

#define CC_COMMON_MIN(a, b) ((a) < (b) ? (a) : (b))

/**
 * @brief The CC_CommonAesCtrEncrypt encrypts (AES CTR) a given data and returns it.
 *
 * @param[in] DataIn_ptr - the data to encrypt
 * @param[in] DataInSize - the data size
 * @param[in] Key_ptr - the AES key
 * @param[in] KeySize - AES key size (must be one of the allowed AES key sizes)
 * @param[in] IV_ptr - IV (AES IV size is constant)
 * @param[in] Output_ptr - Output buffer
 */
/*********************************************************/
int32_t CC_CommonAesCtrEncrypt(uint8_t *pDataIn,
                               uint32_t dataInSize,
                               uint8_t *pKey,
                               uint32_t keySize,
                               uint8_t *pIV,
                               uint8_t *pEncBuff);

/**
 * @brief The CC_CommonAesCbcDecrypt decrypts (AES CBC) a given data
 *               and returns the decrypted buffer.
 *
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
                               uint8_t *pDecBuff);

/**
 * @brief This function
 *
 * @param[in]
 *
 * @param[out]
 *
 * @return uint8_t -

 */
int32_t CC_CommonAesCcmEncrypt(uint8_t *keyBuf,
                               uint8_t *nonce,
                               uint32_t nonceLen,
                               uint8_t *aData,
                               uint32_t aDatalen,
                               uint8_t *plainTxt,
                               uint32_t plainTxtLen,
                               uint8_t *enBuff,
                               uint8_t *tagBuff,
                               uint32_t tagBuffLen);

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
                                uint8_t *pOutput);

/**
 * @brief The Common_CalcHash calculates HASH on the public key and Np using OpenSSL.
 *
 * @param[in] pPemDecryted - the decrypted public key (input data for HASH)
 * @param[out] pHash - the HASH SHA 256 calculated on the data
 *
 */
/*********************************************************/
int32_t CC_CommonCalcHash(uint8_t *pPemDecryted,
                          uint32_t pemDecryptedSize,
                          uint8_t *pHash,
                          uint32_t hashSize);

/**
 * @brief The Common_CalcHash calculates HASH on the public key and Np using OpenSSL.
 *
 * @param[in] pPemDecryted - the decrypted public key (input data for HASH)
 * @param[out] pHash - the HASH SHA 256 calculated on the data
 *
 */
/*********************************************************/
int32_t CC_CommonCalcSha1(uint8_t *pDataIn, uint32_t dataInSize, uint8_t *pHash);

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
                               uint8_t *pEncBuff);

/**
 * @brief Calculates HMAC with SHA256.
 *
 * @param[in] pDataIn - the data to encrypt
 * @param[in] dataInSize - the data size
 * @param[in] pKey - the AES key
 * @param[in] keySize - AES key size (must be one of the allowed AES key sizes)
 * @param[out] pResultBuff - the HMAC sha256 result buffer
 */
int32_t CC_CommonHmac256(uint8_t *pKey,
                         uint32_t keySize,
                         uint8_t *pDataIn,
                         uint32_t dataInSize,
                         uint8_t *pResultBuff);

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
                                  uint32_t outKeySize);
#endif
