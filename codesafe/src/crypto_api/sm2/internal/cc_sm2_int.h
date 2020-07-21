/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */
#ifndef _CC_SM2INT_H_
#define _CC_SM2INT_H_

/*!
@file
@brief This file defines the internal not exported SM2 functions.
@defgroup cc_sm2 CryptoCell APIs
@{
@ingroup cryptocell_sm2

 */

#include "cc_error.h"
#include "cc_ecpki_types.h"
#include "cc_rnd_common.h"
#include "cc_sm3_defs.h"
#include "cc_sm2.h"


/******************************************************************************
 *                Sm2ComputeMessageFromIdDigest
 ******************************************************************************/
/*!
@brief This function gets as an input the digest of id and calculates message digest.

    @param[in] id as a string.
    @param[in] id length in bytes.
    @param[in] A pointer to the message.
    @param[in] The message size in bytes.
    @param[in] The Working_buffer
    @param[in] The working buffer size should be at least idhlen + msglen
    @param[out] The output buffer.
    @param[out] The size of the output buffer in bytes.

@return CC_OK on success.
@return a non-zero value on failure as defined cc_ecpki_error.h or cc_hash_error.h.
*/

/******************************************************************************/

CCError_t Sm2ComputeMessageFromIdDigest (
        const uint8_t               *idh,           /*!< [in]        - A pointer to the id digest. */
        const size_t                idhlen,         /*!< [in]        - The size of the id digest in bytes. */
        const uint8_t               *msg,           /*!< [in]        - A pointer to the message. */
        const size_t                msglen,         /*!< [in]        - The size of the message in bytes. */
        uint8_t                     *working_buffer,/*!< [in]        - The working buffer */
        const size_t                wblength,       /*!< [in]        - The working buffer size should be at least idhlen + msglen*/
        uint32_t                    *out,           /*!< [out]       - A pointer to a buffer for the output. */
        size_t                      *outlen         /*!< [in/out]    - output length in words. */
);


/******************************************************************************
 *                Sm2ComputeIdDigest
 ******************************************************************************/
/*!
@brief This function calculates the id digest.

    @param[in] The data of the public key
    @param[in] id as a string.
    @param[in] id length in bytes.
    @param[in] The Working_buffer
    @param[in] The working buffer size The working buffer size should be at least 2 + idlen_bytes + modSizeInBytes*4 + ordSizeInBytes*2
    @param[out] The output buffer.
    @param[out] The size of the output buffer in bytes.

@return CC_OK on success.
@return A non-zero value on failure as defined cc_ecpki_error.h or cc_hash_error.h.
*/

/******************************************************************************/

CIMPORT_C CCError_t Sm2ComputeIdDigest (
        const CCEcpkiUserPublKey_t  *pUserPublKey,  /*!< [in]       - A pointer to the public key*/
        const char                  *id,            /*!< [in]       - A pointer to the id. */
        const size_t                idlen,          /*!< [in]       - The size of id in bytes. */
        uint8_t                     *working_buffer,/*!< [in]       - The working buffer */
        const size_t                wblen,          /*!< [in]       - The working buffer size should be at least 2 + idlen_bytes + modSizeInBytes*4 + ordSizeInBytes*2*/
        uint8_t                     *out,           /*!< [out]      - A pointer to a buffer for the output. */
        size_t                      *outlen         /*!< [in/out]   - output length in bytes. */
);


/******************************************************************************
 *                Sm2CalculateConfirmationTemplate
 ******************************************************************************/
/*!
@brief This function calculates the confirmation template.
Calculates Hash(xU || ZA || ZB || x1 || y1 || x2 || y2)), where xU is a shared secret value,
ZA, ZB are id digests, x1,y1, x2,y2 are the coordinates of the ephemeral public keys

    @param[in] A pointer to the key exchange context
    @param[out] The output buffer.
    @param[out] The size of the output buffer in bytes.

@return a non-zero value on failure@return CC_OK on success.
*/
/******************************************************************************/
CCError_t Sm2CalculateConfirmationTemplate (
        const CC_Sm2KeContext_t     *pSm2KeContext,/*!< [in]        - A pointer to the key exchange context*/
        uint8_t                     *conf_value,   /*!< [out]       - The confirmation value*/
        size_t                      *cvsize        /*!< [in/out]    - The confirmation value size*/
);



/******************************************************************************
 *                Sm2CalculateConfirmationValue
 ******************************************************************************/
/*!
@brief This function calculates the confirmation value.

    @param[in] A pointer to the key exchange context
    @param[in] can be 0x2 or 0x3.
    @param[out] The output buffer.
    @param[out] The size of the output buffer in bytes.

@return CC_OK on success.
@return A non-zero value on failure
*/
/******************************************************************************/
CCError_t Sm2CalculateConfirmationValue (
        const CC_Sm2KeContext_t     *pSm2KeContext,/*!< [in]        - A pointer to the key exchange context*/
        const uint8_t               prefix,        /*!< [in]        - can be 0x2 or 0x3. */
        const uint8_t               *conf_temp,    /*!< [in]        - confirmation template value */
        const size_t                conf_temp_size,/*!< [in]        - confirmation template value */
        uint8_t                     *conf_value,   /*!< [out]       - The confirmation value*/
        size_t                      *cvsize        /*!< [in/out]    - The confirmation value size*/
);

/******************************************************************************
 *                Sm2CalcKdfBlock
 ******************************************************************************/
/*!
@brief This function calculates the kdf block number ct.

    @param[in] A pointer to the key exchange context
    @param[in] value for concatenation.
    @param[out] The output buffer.
    @param[out] The size of the output buffer in bytes.

@return a non-zero value on failure@return CC_OK on success.
*/
/******************************************************************************/

CCError_t Sm2CalcKdfBlock (
        const CC_Sm2KeContext_t     *pSm2KeContext,     /*!< [in]        - A pointer to the key exchange context*/
        const uint32_t              ct,
        uint8_t                     *digest,            /*!< [out]       - The kdf block*/
        size_t                      *dsize              /*!< [in/out]    - The kdf block size*/
);


/***********      EcWrstSm2Sign function      **********************/
/**
 * @brief Generates ephemeral key
 *
 * @author yury kreimer (11/18/2018)
 *
 * Note: All data in buffers given with LE order of bytes and words and their sizes
 *       must be EC modulus size in words (with leading zeros)
 *
 * @return  CC_OK On success, otherwise indicates failure
 */
CCError_t EcWrstSm2Sign(
    CCRndGenerateVectWorkFunc_t     f_rng,                /*!< [in] Pointer to DRBG function*/
    void                            *p_rng,               /*!< [in/out] Pointer to the random context - the input to f_rng. */
    CCEcpkiPrivKey_t                *pSignPrivKey,        /*!< [in] Pointer to to signer private key structure. */
    uint32_t                        *pMsgRepres,          /*!< [in] The pointer to the message representative buffer.*/
    uint32_t                        *pSignR,              /*!< [in] Pointer to C-part of the signature (called also R-part). */
    uint32_t                        *pSignS,              /*!< [in] Pointer to D-part of the signature (called also S-part). */
    uint32_t                        *pTempBuff            /*!< [in] Pointer to temp buffer. the buffer size must be
                                             not less than (3*ModulusSizeInWords + CC_PKA_ECPKI_SCALAR_MUL_BUFF_MAX_LENGTH_IN_WORDS)*/
);



/***********      EcWrstSm2Verify function      **********************/
/**
 * @brief Verifies the signature.
 *
 * @author yury kreimer (11/18/2018)
 *
 * @return  CC_OK On success, otherwise indicates failure
 */
CCError_t EcWrstSm2Verify(
    CCEcpkiPublKey_t *pSignPublKey,     /*!< [in] Pointer to signer public key structure. */
    uint32_t  *pMsgRepres,              /*!< [in] The pointer to the message representative buffer.*/
    uint32_t   msgRepresSizeWords,      /*!< [in] Size of the message representative buffer in words.*/
    uint32_t  *pSignR,                  /*!< [in] Pointer to R-part of the signature (called also R-part). */
    uint32_t  *pSignS                   /*!< [in] Pointer to S-part of the signature (called also S-part). */
);

/**************************************************************************
 *                EcWrstSm2CalculateSharedSecret
 * *************************************************************************/
/*!

@brief Calculates shared secret
@return CC_OK on success.
@return A non-zero value on failure
 */

CCError_t EcWrstSm2CalculateSharedSecret (
        const CCEcpkiPublKey_t      *pPublicKey,                /*!< [in]   - A pointer to the public key exchange context.*/
        const CCEcpkiPointAffine_t  *pRandomPoint,              /*!< [in]   - A pointer to the random point from the second party. */
        const CCEcpkiDomain_t       *pDomain,                   /*!< [in]   - A pointer to the domain.    */
        const uint32_t              *t,                         /*!< [in]   - The t value.*/
        CCEcpkiPointAffine_t        *shared_secret              /*!< [out]  - shared secret output parameter */

);


/**************************************************************************
 *                EcWrstSm2CalculateRandom
 * *************************************************************************/
/*!

@brief Calculates a random point using PKA
@return CC_OK on success.
@return A non-zero value on failure
 */

CCError_t EcWrstSm2CalculateRandom (
        const CCEcpkiDomain_t       *pDomain,                   /*!< [in]   - A pointer to the domain.*/
        const CCEcpkiPrivKey_t      *pPrivateKey,                /*!< [in]  - A pointer to the private key .*/
        uint32_t                    *funcTmpBuff,               /*!< [in]   - A pointer to the functional buffer, shall be at least
                                                                              CC_PKA_ECPKI_SCALAR_MUL_BUFF_MAX_LENGTH_IN_WORDS length */
        const uint32_t              *pEphemKeyBuf,              /*!< [in]   - A random number between 0 and modulus -1*/
        CCEcpkiPointAffine_t        *pRandomPoint,              /*!< [out]  - A pointer to the output random point. */
        uint32_t                    *t                          /*!< [out]  - An output buffer for t*/

);




#endif /* _CC_SM2INT_H_ */
