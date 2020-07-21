/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */
#include "cc_sm3.h"
#include "cc_ecpki_domain_sm2.h"
#include "cc_ecpki_error.h"
#include "cc_common.h"
#include "cc_pal_mem.h"
#include "pka_hw_defs.h"
#include "pka_defs.h"
#include "pka_ec_wrst.h"
#include "pka_ec_wrst_dsa_verify_regs.h"
#include "pka_ec_wrst_glob_regs.h"
#include "pka.h"
#include "pki.h"
#include "ec_wrst_error.h"
#include "cc_sm2_int.h"



extern const int8_t regTemps[PKA_MAX_COUNT_OF_PHYS_MEM_REGS];

/* Local defintions */
#define CT_LEN_IN_BYTES             4
#define KDF_BUF_MAX_LEN_IN_BYTES    2 * CC_SM3_RESULT_SIZE_IN_BYTES +  \
                                    2 * CC_SM2_ORDER_LENGTH_IN_BYTES + \
                                    CT_LEN_IN_BYTES


/***********      Sm2CalcSignature function      **********************/
/**
 * @brief Sets data into SRAM and calculates Sm2 Signature.
 *
 * @author yury kreimer (11/18/2018)
 *
 * Note: All data in is given with LE order of words (LS word is left most).
 *
 * @return  CC_OK On success, otherwise indicates failure
 */
static CCError_t Sm2CalcSignature(
    const CCEcpkiDomain_t *pDomain, /*!< [in] Pointer to EC domain structure. */
    uint32_t  *pSignPrivKey,        /*!< [in] Pointer to signer private key structure. */
    uint32_t  *pMessRepres,         /*!< [in] The pointer to the message representative buffer.*/
    uint32_t  *pEphemPrivKey,       /*!< [in] pointer to private Ephemeral key buff. */
    uint32_t  *pEphemPublX,         /*!< [in] Pointer to X-coordinate of Ephemeral public. */
    uint32_t  *pSignR,              /*!< [in] Pointer to R-part of the signature (called also R-part). */
    uint32_t  *pSignS)              /*!< [in] Pointer to S-part of the signature (called also S-part). */
{
    CCError_t   err = CC_OK;
    uint32_t    status;
    uint32_t    pkaReqRegs = PKA_MAX_COUNT_OF_PHYS_MEM_REGS;
    size_t      ordSizeInBits, ordSizeInWords, modSizeInWords;
    uint8_t     pka_started = 0;

    /* define registers (ECC_REG_N=0, ECC_REG_NP=1) */
    uint8_t rR          = regTemps[2]; /*signR*/
    uint8_t rE          = regTemps[3]; /*message hash*/
    uint8_t rEphK       = regTemps[4]; /*ephemer.priv.key*/
    uint8_t rDA         = regTemps[5]; /*private. key (zD)*/
    uint8_t rDAinv      = regTemps[6];
    uint8_t rS          = regTemps[7]; /*signS*/
    uint8_t rT          = regTemps[8]; /*temporary*/

    /* no need in verifying input here, since this is static and is not visible outside of this file*/

    /* set EC domain parameters modulus and EC order sizes */
    /* Currently there is only one possible domain. This assignment is constant.
     * In the future we may have more than one domain. */
    ordSizeInBits  = pDomain->ordSizeInBits;
    ordSizeInWords = CALC_FULL_32BIT_WORDS(ordSizeInBits);
    modSizeInWords = CALC_FULL_32BIT_WORDS(pDomain->modSizeInBits);

    if ((ordSizeInWords != 8) || (modSizeInWords != 8)) {
        err = ECWRST_SCALAR_MULT_INVALID_MOD_ORDER_SIZE_ERROR;
        goto End;
    }
    /*  Init PKA for operations with EC order */
    err = PkaInitAndMutexLock(ordSizeInBits , &pkaReqRegs);
    if (err != CC_OK) {
        goto End;
    }

    pka_started = 1;

    /*   Set data into PKA registers  */
    /* Note: ignore false positive KW warning about explicit offset:      *
       sizes, given in the EC Domain, must be right                      */
    PkaCopyDataIntoPkaReg(ECC_REG_N, 1, pDomain->ecR/*src_ptr*/, ordSizeInWords);
    PkaCopyDataIntoPkaReg(ECC_REG_NP, 1, ((EcWrstDomain_t*)&(pDomain->llfBuff))->ordTag,
                          CC_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS);
    PkaCopyDataIntoPkaReg(rR, 1, pEphemPublX, modSizeInWords);

    PkaCopyDataIntoPkaReg(rE, 1, pMessRepres, CC_SM3_RESULT_SIZE_IN_WORDS);
    PKA_MOD_ADD_IM(LEN_ID_N_PKA_REG_BITS, rE, rE, 0);       /*rE:=e modn*/
    PkaCopyDataIntoPkaReg(rEphK, 1, pEphemPrivKey, ordSizeInWords);
    PkaCopyDataIntoPkaReg(rDA, 1, pSignPrivKey, ordSizeInWords);

    /* calculate s=((1+dA)^(-1)*(k-r*dA)) modn, return to A3 if s=0 */
    /* calculate: (e+x1) mod n */
    PKA_MOD_ADD_IM(LEN_ID_N_PKA_REG_BITS, rR, rR, 0);       /*rR:=x1 modn*/
    PKA_MOD_ADD(LEN_ID_N_PKA_REG_BITS, rR, rE, rR);         /*rR := (e + x1) mod n*/
    PKA_COMPARE_IM_STATUS(LEN_ID_MAX_BITS, rR, 0, status);   /*r<>0*/
    if(status == 1){
        err = ECWRST_DSA_SIGN_BAD_EPHEMER_KEY_TRY_AGAIN_ERROR;
        goto End;
    }
    PKA_MOD_ADD(LEN_ID_N_PKA_REG_BITS, rT, rR, rEphK);           /*rT:=r+k*/
    PKA_COMPARE_STATUS(LEN_ID_MAX_BITS, rT, ECC_REG_N, status);  /*r+k<>n*/
    if(status == 1){
        err = ECWRST_DSA_SIGN_BAD_EPHEMER_KEY_TRY_AGAIN_ERROR;
        goto End;
    }


    /* check (1+dA)^(-1) != 0 */
    PKA_MOD_ADD_IM(LEN_ID_N_PKA_REG_BITS, rDAinv, rDA, 1);
    PKA_MOD_INV_W_EXP(rDAinv, rDAinv, rT/*temp*/); /* inverse in constant time */
    PKA_MOD_MUL(0, rT, rDA, rR);
    PKA_MOD_SUB(1, rT, rEphK, rT);
    PKA_MOD_MUL(0, rS, rDAinv, rT);


    PKA_COMPARE_IM_STATUS(1, rS, 0, status);

    if(status == 1) {
        err = ECWRST_DSA_SIGN_BAD_EPHEMER_KEY_TRY_AGAIN_ERROR;
        goto End;
    }
    PkaCopyDataFromPkaReg(pSignR, ordSizeInWords, rR);
    PkaCopyDataFromPkaReg(pSignS, ordSizeInWords, rS);

End:
    if (pka_started)
        PkaFinishAndMutexUnlock(pkaReqRegs);
    return err;

}



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
    @param[out] The size of the output buffer in words.

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
        const size_t                wblen,          /*!< [in]        - The working buffer size should be at least idhlen + msglen*/
        uint32_t                    *out,           /*!< [out]       - A pointer to a buffer for the output. */
        size_t                      *outlen         /*!< [in/out]    - output length in words. */
)
{
    CCError_t err = CC_OK;
    size_t blen = 0;


    if ( NULL == idh ){
        err = CC_ECPKI_SM2_INVALID_ID_PTR;
        goto End;
    }

    if ( CC_SM3_RESULT_SIZE_IN_BYTES != idhlen ){
        err = CC_ECPKI_SM2_INVALID_ID_SIZE;
        goto End;
    }

    if ( NULL == msg ){
        err = CC_ECPKI_SM2_INVALID_IN_PARAM_PTR;
        goto End;
    }

    if ( 0 == msglen || msglen >= CC_SM2_MAX_MESSEGE_LEN){
        err = CC_ECPKI_SM2_INVALID_IN_PARAM_SIZE;
        goto End;
    }

    if ( NULL == working_buffer ) {
        err = CC_ECPKI_GEN_KEY_INVALID_TEMP_DATA_PTR_ERROR;
        goto End;
    }

    if ( NULL == out ) {
        err = CC_ECPKI_INVALID_OUT_HASH_PTR_ERROR;
        goto End;
    }

    if ( NULL == outlen || CC_SM3_RESULT_SIZE_IN_WORDS != *outlen ) {
        err = CC_ECPKI_INVALID_OUT_HASH_SIZE_ERROR;
        goto End;
    }

    blen = msglen + idhlen;
    if ( wblen < blen ) {
        err = CC_ECPKI_GEN_KEY_INVALID_TEMP_DATA_PTR_ERROR;
        goto End;
    }

    CC_PalMemSetZero(working_buffer, blen);
    CC_PalMemCopy( working_buffer, idh, idhlen);
    CC_PalMemCopy( working_buffer+idhlen, msg, msglen);

    if (CC_OK != (err = CC_Sm3(working_buffer, blen, (uint8_t*)out)))
        goto End;

    CC_CommonConvertLsbMsbBytesToLswMswWords (out, (uint8_t*)out, *outlen * 4);
    *outlen = CC_SM3_RESULT_SIZE_IN_WORDS;

End:
    if (NULL != working_buffer)
        CC_PalMemSet(working_buffer, 0, wblen);
    return err;
}




/******************************************************************************
 *                Sm2CalculateConfirmationTemplate
 ******************************************************************************/
/*!
@brief This function calculates the id digest.
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
)
{
    CCError_t                   err             = CC_OK;
    size_t                      ordSizeInBytes  = 0;
    const CCEcpkiDomain_t*      pDomain         = CC_EcpkiGetSm2Domain(); /* Currently the standard specifies only one possible domain for SM2. */

    uint8_t                     working_buffer[2 * CC_SM3_RESULT_SIZE_IN_BYTES + 5 * CC_SM2_ORDER_LENGTH_IN_BYTES];
    size_t                      wblen           = 2 * CC_SM3_RESULT_SIZE_IN_BYTES + 5 * CC_SM2_ORDER_LENGTH_IN_BYTES;
    const uint8_t*              Za              = 0;
    size_t                      Za_size         = 0;
    const uint8_t*              Zb              = 0;
    size_t                      Zb_size         = 0;

    /* Check input parameters */
    if ( conf_value == NULL ||
         *cvsize < CC_SM3_RESULT_SIZE_IN_BYTES ) {
        err = CC_ECPKI_INVALID_OUT_HASH_PTR_ERROR;
        goto End;
    }

    if ( pSm2KeContext == NULL ||
         pSm2KeContext->Z_value_size < CC_SM3_RESULT_SIZE_IN_BYTES ) {
        err = CC_ECPKI_SM2_INVALID_KE_CONTEXT_PTR;
        goto End;
    }


    if (pSm2KeContext->isInitiator) {
        Za = pSm2KeContext->Z;
        Za_size = pSm2KeContext->Z_value_size;
        Zb = pSm2KeContext->Z_remote;
        Zb_size = pSm2KeContext->Z_value_size;
    }
    else {
        Za = pSm2KeContext->Z_remote;
        Za_size = pSm2KeContext->Z_value_size;
        Zb = pSm2KeContext->Z;
        Zb_size = pSm2KeContext->Z_value_size;
    }

    /* Currently there is only one possible domain. This assignment is constant.
     * In the future we may have more than one domain. */
    ordSizeInBytes = CALC_FULL_BYTES(pDomain->ordSizeInBits);
    CC_PalMemSetZero(working_buffer, wblen );

    /*xU || ZA || ZB || x1 || y1 || x2 || y2*/
    CC_CommonReverseMemcpy      ( working_buffer,                                                         (uint8_t*)pSm2KeContext->V.x,                   ordSizeInBytes);
    CC_PalMemCopy               ( working_buffer +      ordSizeInBytes,                                   Za,                                             Za_size);
    CC_PalMemCopy               ( working_buffer +      ordSizeInBytes +     CC_SM3_RESULT_SIZE_IN_BYTES, Zb,                                             Zb_size);

    if (pSm2KeContext->isInitiator) {
        CC_CommonReverseMemcpy  ( working_buffer +      ordSizeInBytes + 2 * CC_SM3_RESULT_SIZE_IN_BYTES, (uint8_t*)pSm2KeContext->ephemeral_pub.x,       ordSizeInBytes);
        CC_CommonReverseMemcpy  ( working_buffer +  2 * ordSizeInBytes + 2 * CC_SM3_RESULT_SIZE_IN_BYTES, (uint8_t*)pSm2KeContext->ephemeral_pub.y,       ordSizeInBytes);
        CC_CommonReverseMemcpy  ( working_buffer +  3 * ordSizeInBytes + 2 * CC_SM3_RESULT_SIZE_IN_BYTES, (uint8_t*)pSm2KeContext->remote_ephemeral_pub.x,ordSizeInBytes);
        CC_CommonReverseMemcpy  ( working_buffer +  4 * ordSizeInBytes + 2 * CC_SM3_RESULT_SIZE_IN_BYTES, (uint8_t*)pSm2KeContext->remote_ephemeral_pub.y,ordSizeInBytes);
    }
    else {
        CC_CommonReverseMemcpy  ( working_buffer +      ordSizeInBytes + 2 * CC_SM3_RESULT_SIZE_IN_BYTES, (uint8_t*)pSm2KeContext->remote_ephemeral_pub.x,ordSizeInBytes);
        CC_CommonReverseMemcpy  ( working_buffer +  2 * ordSizeInBytes + 2 * CC_SM3_RESULT_SIZE_IN_BYTES, (uint8_t*)pSm2KeContext->remote_ephemeral_pub.y,ordSizeInBytes);
        CC_CommonReverseMemcpy  ( working_buffer +  3 * ordSizeInBytes + 2 * CC_SM3_RESULT_SIZE_IN_BYTES, (uint8_t*)pSm2KeContext->ephemeral_pub.x,       ordSizeInBytes);
        CC_CommonReverseMemcpy  ( working_buffer +  4 * ordSizeInBytes + 2 * CC_SM3_RESULT_SIZE_IN_BYTES, (uint8_t*)pSm2KeContext->ephemeral_pub.y,       ordSizeInBytes);
    }

    if (CC_OK != (err = CC_Sm3(working_buffer, wblen, conf_value)))
        goto End;
    *cvsize = CC_SM3_RESULT_SIZE_IN_BYTES;

End:
    CC_PalMemSet(working_buffer, 0, wblen);
    if (err != CC_OK && NULL != conf_value) {
       CC_PalMemSet(conf_value, 0, *cvsize);
    }
    return err;
}



/******************************************************************************
 *                Sm2CalculateConfirmationValue
 ******************************************************************************/
/*!
@brief This function calculates the id digest.

    @param[in] A pointer to the key exchange context
    @param[in] can be 0x2 or 0x3.
    @param[out] The output buffer.
    @param[out] The size of the output buffer in bytes.

@return a non-zero value on failure@return CC_OK on success.
*/
/******************************************************************************/
CCError_t Sm2CalculateConfirmationValue (
        const CC_Sm2KeContext_t     *pSm2KeContext,     /*!< [in]        - A pointer to the key exchange context*/
        const uint8_t               prefix,             /*!< [in]        - can be 0x2 or 0x3. */
        const uint8_t               *conf_template,     /*!< [in]        - conf_template. */
        const size_t                conf_template_size, /*!< [in]        - conf template_size */
        uint8_t                     *conf_value,        /*!< [out]       - The confirmation value*/
        size_t                      *cvsize             /*!< [in/out]    - The confirmation value size*/
)
{
    /*Hash(0x02 || yU || Hash(xU || ZA || ZB || x1 || y1 || x2 || y2))*/
    CCError_t                   err = CC_OK;
    size_t                      ordSizeInBytes = 0;
    const CCEcpkiDomain_t*      pDomain = CC_EcpkiGetSm2Domain(); /* Currently the standard specifies only one possible domain for SM2. */
    uint8_t                     working_buffer[1 + CC_SM3_RESULT_SIZE_IN_BYTES + CC_SM2_ORDER_LENGTH_IN_BYTES];
    size_t                      wblen = 1 + CC_SM3_RESULT_SIZE_IN_BYTES + CC_SM2_ORDER_LENGTH_IN_BYTES;

    /* Check input parameters */
    if ( pSm2KeContext == NULL ||
         pSm2KeContext->Z_value_size < CC_SM3_RESULT_SIZE_IN_BYTES ) {
        err = CC_ECPKI_SM2_INVALID_KE_CONTEXT_PTR;
        goto End;
    }

    if ( conf_template == NULL ) {
        err = CC_ECPKI_SM2_INVALID_IN_PARAM_PTR;
        goto End;
    }

    if ( conf_template_size != CC_SM3_RESULT_SIZE_IN_BYTES ) {
        err = CC_ECPKI_SM2_INVALID_IN_PARAM_SIZE;
        goto End;
    }

    if ( NULL == conf_value ||
         NULL == cvsize ||
         *cvsize < CC_SM3_RESULT_SIZE_IN_BYTES ) {
        err = CC_ECPKI_INVALID_OUT_HASH_PTR_ERROR;
        goto End;
    }

    CC_PalMemSetZero(working_buffer, wblen );

    /* Currently there is only one possible domain. This assignment is constant.
     * In the future we may have more than one domain. */
    ordSizeInBytes = CALC_FULL_BYTES(pDomain->ordSizeInBits);

    working_buffer[0] = prefix;
    CC_CommonReverseMemcpy      ( working_buffer + 1,                   (uint8_t*)pSm2KeContext->V.y,  ordSizeInBytes );
    CC_PalMemCopy               ( working_buffer + 1 + ordSizeInBytes,  conf_template,                 conf_template_size);

    if (CC_OK != (err = CC_Sm3(working_buffer, wblen, conf_value)))
        goto End;
    *cvsize = CC_SM3_RESULT_SIZE_IN_BYTES;

End:
    CC_PalMemSet(working_buffer, 0, wblen);
    return err;
}

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
)
{
    /* Hash(xV || yV || ZA || ZB || ct) */
    CCError_t                   err = CC_OK;
    size_t                      ordSizeInBytes = 0;
    size_t                      zSizeInBytes = 0;
    const CCEcpkiDomain_t*      pDomain = CC_EcpkiGetSm2Domain(); /* Currently the standard specifies only one possible domain for SM2. */
    uint8_t                     working_buffer[KDF_BUF_MAX_LEN_IN_BYTES];
    size_t                      wblen = 0;

    /* Check input parameters */
    if ( pSm2KeContext == NULL ||
         pSm2KeContext->Z_value_size < CC_SM3_RESULT_SIZE_IN_BYTES ) {
        err = CC_ECPKI_SM2_INVALID_KE_CONTEXT_PTR;
        goto End;
    }

    if ( NULL == digest ||
         NULL == dsize  ||
         *dsize < CC_SM3_RESULT_SIZE_IN_BYTES) {
        err = CC_ECPKI_INVALID_OUT_HASH_PTR_ERROR;
        goto End;
    }

    /* Currently there is only one possible domain. This assignment is constant.
     * In the future we may have more than one domain. */
    ordSizeInBytes = CALC_FULL_BYTES(pDomain->ordSizeInBits);
    zSizeInBytes = pSm2KeContext->Z_value_size;
    /* Calculate the actual buffer size to be digested */
    wblen = 2 * ordSizeInBytes + 2 * zSizeInBytes + CT_LEN_IN_BYTES;
    /* verify that the local buffer is sufficient */
    if(wblen > KDF_BUF_MAX_LEN_IN_BYTES) {
        err = CC_ECPKI_TEMP_BUFF_SIZE_ERROR;
        goto End;
    }

    /* reset working buffer */
    CC_PalMemSetZero(working_buffer, KDF_BUF_MAX_LEN_IN_BYTES);

    CC_CommonReverseMemcpy(working_buffer, (uint8_t*)pSm2KeContext->V.x, ordSizeInBytes);
    CC_CommonReverseMemcpy(working_buffer + ordSizeInBytes, (uint8_t*)pSm2KeContext->V.y, ordSizeInBytes);

    if (pSm2KeContext->isInitiator) {
        CC_PalMemCopy(working_buffer + ordSizeInBytes*2, pSm2KeContext->Z, zSizeInBytes);
        CC_PalMemCopy(working_buffer + ordSizeInBytes*2 + zSizeInBytes, pSm2KeContext->Z_remote, zSizeInBytes);
    }
    else {
        CC_PalMemCopy(working_buffer + ordSizeInBytes*2, pSm2KeContext->Z_remote, zSizeInBytes);
        CC_PalMemCopy(working_buffer + ordSizeInBytes*2 + zSizeInBytes, pSm2KeContext->Z, zSizeInBytes);
    }
    /* concatenate the ct to the end of the buffer */
    CC_CommonReverseMemcpy(working_buffer + ordSizeInBytes*2 + zSizeInBytes*2, (uint8_t*)&ct, CT_LEN_IN_BYTES);
    if (CC_OK != (err = CC_Sm3(working_buffer, wblen, digest))) {
        goto End;
    }
    *dsize = CC_SM3_RESULT_SIZE_IN_BYTES;

End:
    CC_PalMemSet(working_buffer, 0, KDF_BUF_MAX_LEN_IN_BYTES);
    return err;
}


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
    uint32_t                        *pTempBuff)           /*!< [in] Pointer to temp buffer. the buffer size must be
                                             not less than (4*ModulusSizeInWords + CC_PKA_ECPKI_SCALAR_MUL_BUFF_MAX_LENGTH_IN_WORDS)*/
{
    CCError_t err = CC_OK;
    const CCEcpkiDomain_t *pDomain = CC_EcpkiGetSm2Domain(); /* Currently the standard specifies only one possible domain for SM2. */
    size_t ordSizeInBits, ordSizeInWords, modSizeInWords;
    /* pointers to result EC point coordinates x, y */
    uint32_t *pEphemPublX, *pEphemPublY, *pEphemKeyBuf, *pMaxVect;
    uint32_t *funcTmpBuff;
    uint32_t countTries = 0;

    /* check input parameters */
    if ( NULL == f_rng) {
        err = CC_ECPKI_INVALID_RND_FUNC_PTR_ERROR;
        goto End;
    }

    if (pSignPrivKey == NULL) {
        err = CC_ECDSA_SIGN_INVALID_USER_PRIV_KEY_PTR_ERROR;
        goto End;
    }

    if ( pMsgRepres == NULL ){
        err = CC_ECPKI_INVALID_IN_HASH_PTR_ERROR;
        goto End;
    }

    if (pSignR == NULL || pSignS == 0) {
        err = CC_ECPKI_SM2_INVALID_IN_PARAM_PTR;
        goto End;
    }

    if ( 0 == pTempBuff ) {
        err = CC_ECIES_INVALID_TEMP_DATA_PTR_ERROR;
        goto End;
    }

    /* set EC domain parameters modulus and EC order sizes */
    /* Currently there is only one possible domain. This assignment is constant.
     * In the future we may have more than one domain. */
    ordSizeInBits  = pDomain->ordSizeInBits;
    ordSizeInWords = CALC_FULL_32BIT_WORDS(ordSizeInBits);
    modSizeInWords = CALC_FULL_32BIT_WORDS(pDomain->modSizeInBits);

    if ((ordSizeInWords != CC_SM2_ORDER_LENGTH_IN_WORDS) || (modSizeInWords != CC_SM2_MODULE_LENGTH_IN_WORDS)) {
        err = ECWRST_SCALAR_MULT_INVALID_MOD_ORDER_SIZE_ERROR;
        goto End;
    }


    pEphemPublX = pTempBuff;
    pEphemKeyBuf = pEphemPublX + modSizeInWords;
    pEphemPublY = pEphemKeyBuf + ordSizeInWords;
    pMaxVect = pEphemPublY + modSizeInWords;

    while (1) {
        /*  Generate random ephemeral key   *
         * Note: Checking, that private ephemer.key  0 < k < EC order *
         * performed on LLF during scalar multiplication             */
        /* Set bytes MaxVect= EcOrder. */
        pMaxVect[ordSizeInWords-1] = 0; /*zero MSWord of maxVect*/
        CC_PalMemCopy(pMaxVect, pDomain->ecR, sizeof(uint32_t)*ordSizeInWords);
        pEphemKeyBuf[ordSizeInWords-1] = 0; /*zero MSWord*/
        err = CC_RndGenerateVectorInRange(
                f_rng, p_rng, ordSizeInBits, (uint8_t*)pMaxVect/* maxVect*/, (uint8_t*)pEphemKeyBuf);
        if (err) {
            goto End;
        }

        /* Calculate ephemeral public key               */
        funcTmpBuff = pMaxVect; /* because pMaxVect not needed yet */
        err = PkaEcWrstScalarMult(pDomain,
                                  pEphemKeyBuf/*scalar*/, ordSizeInWords, /*scalar size*/
                                  (uint32_t*)&pDomain->ecGx, (uint32_t*)&pDomain->ecGy, /*in point coordinates*/
                                  pEphemPublX/*C*/, pEphemPublY,  /*out point coordinates*/
                                  funcTmpBuff);
        if (err) {
            goto End;
        }

        /*  Calculate Signature S  */
        err = Sm2CalcSignature(pDomain, pSignPrivKey->PrivKey,
                               pMsgRepres, pEphemKeyBuf, pEphemPublX,
                               pSignR, pSignS);

        /* exit the program if an error occurs, beside the case of   *
         *  returned error message to try a new Ephemeral Key          */
        if(err && (err != ECWRST_DSA_SIGN_BAD_EPHEMER_KEY_TRY_AGAIN_ERROR)) {
            goto End;
        }

        /* if error is OK or count of tries > 100, then end the loop*/
        if((err == 0) || (countTries > 100)) {
            goto End;
        } else {
            countTries++;
        }

        break; /*if we are here go out from the infinite loop*/
    } /* End of while() */

End:
    return err;
}


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
    uint32_t  *pSignS)                  /*!< [in] Pointer to S-part of the signature (called also S-part). */
{
    CCError_t err = CC_OK;
    uint32_t pkaReqRegs = PKA_MAX_COUNT_OF_PHYS_MEM_REGS;
    const CCEcpkiDomain_t *pDomain = CC_EcpkiGetSm2Domain(); /* Currently the standard specifies only one possible domain for SM2. */

    EcWrstDomain_t *llfBuff = (EcWrstDomain_t*)&pSignPublKey->domain.llfBuff;
    size_t modSizeInBits, modSizeInWords, ordSizeInBits, ordSizeInWords;
    uint8_t pka_started = 0;



    /*if the public key object is NULL return an error*/
    if (pSignPublKey == NULL){
        err = CC_ECDSA_VERIFY_INVALID_SIGNER_PUBL_KEY_PTR_ERROR;
        goto End;
    }

    /* if the users MessageHash pointer is illegal return an error */
    if (pMsgRepres == NULL){
        err = CC_ECDSA_VERIFY_INVALID_MESSAGE_DATA_IN_PTR_ERROR;
        goto End;
    }

    if (msgRepresSizeWords != CC_SM3_RESULT_SIZE_IN_WORDS){
        err = CC_ECDSA_VERIFY_INVALID_MESSAGE_DATA_IN_SIZE_ERROR;
        goto End;
    }

    if ( NULL == pSignR || NULL == pSignS) {
        err = CC_ECDSA_SIGN_INVALID_SIGNATURE_OUT_PTR_ERROR;
        goto End;
    }

    /* set domain parameters.
     * Currently there is only one possible domain. This assignment is constant.
     * In the future we may have more than one domain. */
    modSizeInBits  = pDomain->modSizeInBits;
    modSizeInWords = CALC_FULL_32BIT_WORDS(modSizeInBits);
    ordSizeInBits  = pDomain->ordSizeInBits;
    ordSizeInWords = CALC_FULL_32BIT_WORDS(ordSizeInBits);

    err = PkaInitAndMutexLock(CC_MAX(ordSizeInBits, modSizeInBits), &pkaReqRegs);
    if (err != CC_OK) {
        goto End;
    }

    pka_started = 1;
    /* set order and modulus mod sizes */
    CC_HAL_WRITE_REGISTER(CC_REG_OFFSET (CRY_KERNEL, PKA_L0), ordSizeInBits);
    CC_HAL_WRITE_REGISTER(CC_REG_OFFSET (CRY_KERNEL, PKA_L2), modSizeInBits);

    /* Set input data into PKA registers */
    /* EC order and its Barrett tag */
    PkaCopyDataIntoPkaReg(ECC_REG_N/*dest_reg*/, 1, pDomain->ecR/*src_ptr*/, ordSizeInWords);
    PkaCopyDataIntoPkaReg(ECC_REG_NP, 1, ((EcWrstDomain_t*)&(pDomain->llfBuff))->ordTag, CC_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS);
    /* signature C, D */
    PkaCopyDataIntoPkaReg(EC_VERIFY_REG_C, 1, pSignR, ordSizeInWords);
    PkaCopyDataIntoPkaReg(EC_VERIFY_REG_D, 1, pSignS, ordSizeInWords);
    /* message representative EC_VERIFY_REG_F */
    PkaCopyDataIntoPkaReg(EC_VERIFY_REG_F, 1, pMsgRepres, msgRepresSizeWords);
    /* Load modulus and its Barrett tag */
    PkaCopyDataIntoPkaReg(EC_VERIFY_REG_TMP_N, 1, pDomain->ecP, modSizeInWords);
    PkaCopyDataIntoPkaReg(EC_VERIFY_REG_TMP_NP, 1, llfBuff->modTag, CC_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS);
    /* set pG */
    PkaCopyDataIntoPkaReg(EC_VERIFY_REG_P_GX, 1, pDomain->ecGx, modSizeInWords);
    PkaCopyDataIntoPkaReg(EC_VERIFY_REG_P_GY, 1, pDomain->ecGy, modSizeInWords);
    /* set pW */
    PkaCopyDataIntoPkaReg(EC_VERIFY_REG_P_WX, 1, pSignPublKey->x, modSizeInWords);
    PkaCopyDataIntoPkaReg(EC_VERIFY_REG_P_WY, 1, pSignPublKey->y, modSizeInWords);
    PkaCopyDataIntoPkaReg(ECC_REG_EC_A, 1, pDomain->ecA, modSizeInWords);

    /* Verify */
    err = PkaSm2EcdsaVerify();
    if ( CC_OK != err ) {
        goto End;
    }
End:
    if (pka_started)
        PkaFinishAndMutexUnlock(pkaReqRegs);
    return err;
}


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

)
{
    CCError_t err = CC_OK;
    uint32_t pkaReqRegs = PKA_MAX_COUNT_OF_PHYS_MEM_REGS;


    /* define registers (ECC_REG_N=0, ECC_REG_NP=1) */
    uint8_t rX                          = regTemps[2]; /*X - ephemeral public key x*/
    uint8_t rXbar                       = regTemps[3]; /*X1_bar or x2_bar*/
    uint8_t rTwoToOmegaMinusOne         = regTemps[4]; /*2^w-1*/
    uint8_t rTwoToOmega                 = regTemps[5]; /*2^w*/
    uint8_t rt                          = regTemps[6]; /*tA or tB*/
    uint8_t rEphemKeyBuf                = regTemps[7]; /*rA or rB*/
    uint8_t rPrivKeyBuf                 = regTemps[8]; /*private key*/


    /*domain related values*/
    /*omega = 127*/
    const uint32_t twoToOmega[CC_SM2_MODULE_LENGTH_IN_WORDS]           =
    {0x00000000, 0x00000000, 0x00000000, 0x80000000,
            0x00000000, 0x00000000, 0x00000000, 0x00000000};
    const uint32_t twoToOmegaMinusOne[CC_SM2_MODULE_LENGTH_IN_WORDS]   =
    {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x7FFFFFFF,
            0x00000000, 0x00000000, 0x00000000, 0x00000000};

    size_t ordSizeInBits, ordSizeInWords, modSizeInWords;

    if (NULL == pDomain) {
        err = CC_ECPKI_DOMAIN_PTR_ERROR;
        goto End;
    }

    if (NULL == pPrivateKey ){
        err = CC_ECIES_INVALID_PRIV_KEY_PTR_ERROR;
        goto End;
    }

    if (NULL == funcTmpBuff ){
        err = CC_ECPKI_BUILD_KEY_INVALID_TEMP_BUFF_PTR_ERROR;
        goto End;
    }

    if (NULL == pEphemKeyBuf ){
        err = CC_ECPKI_SM2_INVALID_EPHEMERAL_PRIV_IN_PTR;
        goto End;
    }

    if (NULL == pRandomPoint ){
        err = CC_ECPKI_SM2_INVALID_EPHEMERAL_PUB_OUT_PTR;
        goto End;
    }

    if (NULL == t ){
        err = CC_ECPKI_SM2_INVALID_CONTEXT;
        goto End;
    }


    /* set EC domain parameters modulus and EC order sizes */
    /* Currently there is only one possible domain. This assignment is constant.
     * In the future we may have more than one domain. */
    ordSizeInBits  = pDomain->ordSizeInBits;
    ordSizeInWords = CALC_FULL_32BIT_WORDS(ordSizeInBits);
    modSizeInWords = CALC_FULL_32BIT_WORDS(pDomain->modSizeInBits);

    err = PkaEcWrstScalarMult(pDomain,
                              pEphemKeyBuf/*scalar*/, ordSizeInWords, /*scalar size*/
                              (uint32_t*)&pDomain->ecGx, (uint32_t*)&pDomain->ecGy, /*in point coordinates*/
                              pRandomPoint->x/*C*/, pRandomPoint->y,  /*out point coordinates*/
                              funcTmpBuff);
    if (CC_OK != err) {
        goto End;
    }


    /*  Init PKA for operations with EC order */
    err = PkaInitAndMutexLock(ordSizeInBits , &pkaReqRegs);
    if (err != CC_OK) {
        goto End;
    }


    /*   Set data into PKA registers  */
    PkaCopyDataIntoPkaReg(ECC_REG_N, 1, pDomain->ecR/*src_ptr*/, ordSizeInWords);
    PkaCopyDataIntoPkaReg(ECC_REG_NP, 1, ((EcWrstDomain_t*)&(pDomain->llfBuff))->ordTag,
                          CC_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS);
    PkaCopyDataIntoPkaReg(rX, 1, pRandomPoint->x, ordSizeInWords);
    PkaCopyDataIntoPkaReg(rTwoToOmegaMinusOne, 1, twoToOmegaMinusOne/*src_ptr*/, ordSizeInWords);
    PkaCopyDataIntoPkaReg(rTwoToOmega, 1, twoToOmega/*src_ptr*/, ordSizeInWords);
    PkaCopyDataIntoPkaReg(rEphemKeyBuf, 1, pEphemKeyBuf/*src_ptr*/, ordSizeInWords);
    PkaCopyDataIntoPkaReg(rPrivKeyBuf, 1, pPrivateKey->PrivKey/*src_ptr*/, modSizeInWords);


    /*
    A4: calculate x1~=2^w+(x1 AND (2^w-1));
   */
    PKA_AND(LEN_ID_N_PKA_REG_BITS, rXbar, rX, rTwoToOmegaMinusOne);

    PKA_ADD(LEN_ID_N_PKA_REG_BITS, rXbar, rXbar, rTwoToOmega);
    /*
    A5: calculate tA=(dA+x1~*rA) modn;
   */
    PKA_MOD_MUL(LEN_ID_N_BITS, rt, rXbar, rEphemKeyBuf);
    PKA_MOD_ADD(LEN_ID_N_PKA_REG_BITS, rt, rt, rPrivKeyBuf);
    PkaCopyDataFromPkaReg(t, ordSizeInWords, rt);

    PkaFinishAndMutexUnlock(pkaReqRegs);

End:
    return err;
}

/**************************************************************************
 *                EcWrstSm2CalculateSharedSecret
 * *************************************************************************/
/*!

@brief Calculates the shared secret
@return CC_OK on success.
@return A non-zero value on failure
 */

CCError_t EcWrstSm2CalculateSharedSecret (
        const CCEcpkiPublKey_t      *pPublicKey,                /*!< [in]   - A pointer to the public key exchange context.*/
        const CCEcpkiPointAffine_t  *pRandomPoint,              /*!< [in]   - A pointer to the random point from the second party. */
        const CCEcpkiDomain_t       *pDomain,                   /*!< [in]   - A pointer to the domain.    */
        const uint32_t              *t,                         /*!< [in]   - The t value.*/
        CCEcpkiPointAffine_t        *shared_secret              /*!< [out]  - shared secret output parameter */

)
{
    CCError_t  err                      = CC_OK;
    uint32_t   pkaReqRegs               = PKA_MAX_COUNT_OF_PHYS_MEM_REGS;
    /* define registers (ECC_REG_N=0, ECC_REG_NP=1) */
    uint8_t rTwoToOmegaMinusOne         = regTemps[16]; /*2^w-1 parameter of the domain*/
    uint8_t rTwoToOmega                 = regTemps[17]; /*2^w* parameter of the domain */
    uint8_t rt                          = regTemps[18]; /*local t saved in context*/
    uint8_t rXbar                       = regTemps[19]; /*remote Xbar recalculated here */
    uint8_t rP_remote_x                 = regTemps[20]; /*x coordinate of the remote public key*/
    uint8_t rP_remote_y                 = regTemps[21]; /*y coordinate of the remote public key*/
    uint8_t rRandomPoint_x              = regTemps[22]; /*x coordinate of the random point received in the input*/
    uint8_t rRandomPoint_y              = regTemps[23]; /*x coordinate of the random point received in the input*/
    uint8_t rVx                         = regTemps[24]; /*Vx for party B or Ux for the party A*/
    uint8_t rVy                         = regTemps[25]; /*Vy for party B or Uy for the party A*/

    /*domain related values*/
    /*omega = 127*/
    const uint32_t twoToOmega[CC_SM2_MODULE_LENGTH_IN_WORDS]           =
    {0x00000000, 0x00000000, 0x00000000, 0x80000000,
            0x00000000, 0x00000000, 0x00000000, 0x00000000};
    const uint32_t twoToOmegaMinusOne[CC_SM2_MODULE_LENGTH_IN_WORDS]   =
    {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x7FFFFFFF,
            0x00000000, 0x00000000, 0x00000000, 0x00000000};

    size_t ordSizeInBits, ordSizeInWords, modSizeInWords, modSizeInBits;


    if (NULL == pPublicKey) {
        err = CC_ECIES_INVALID_PUBL_KEY_PTR_ERROR;
        goto End;
    }
    if (NULL == pRandomPoint) {
        err = CC_ECPKI_SM2_INVALID_EPHEMERAL_PUB_IN_PTR;
        goto End;
    }
    if (NULL == pDomain) {
        err = CC_ECPKI_DOMAIN_PTR_ERROR;
        goto End;
    }
    if (NULL == t) {
        err = CC_ECPKI_SM2_INVALID_CONTEXT;
        goto End;
    }
    if (NULL == shared_secret) {
        err = CC_ECPKI_SM2_INVALID_SHARED_SECRET_OUT_PTR;
        goto End;
    }

    /* set EC domain parameters modulus and EC order sizes */
    /* Currently there is only one possible domain. This assignment is constant.
     * In the future we may have more than one domain. */
    ordSizeInBits  = pDomain->ordSizeInBits;
    modSizeInBits  = pDomain->modSizeInBits;
    ordSizeInWords = CALC_FULL_32BIT_WORDS(ordSizeInBits);
    modSizeInWords = CALC_FULL_32BIT_WORDS(modSizeInBits);

    if ((ordSizeInWords > CC_SM2_ORDER_LENGTH_IN_WORDS) ||
            (modSizeInWords> CC_SM2_MODULE_LENGTH_IN_WORDS))
    {
        err = ECWRST_SCALAR_MULT_INVALID_MOD_ORDER_SIZE_ERROR;
        goto End;
    }


    /*  Init PKA for operations with EC order */
    err = PkaInitAndMutexLock(ordSizeInBits , &pkaReqRegs);
    if (err != CC_OK) {
        goto End;
    }


    /*   Set data into PKA registers  */
    PkaCopyDataIntoPkaReg(ECC_REG_N, 1, pDomain->ecR/*src_ptr*/, ordSizeInWords);
    PkaCopyDataIntoPkaReg(ECC_REG_NP, 1, ((EcWrstDomain_t*)&(pDomain->llfBuff))->ordTag,
                          CC_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS);

    /* Load modulus and its Barrett tag */
    PkaCopyDataIntoPkaReg(EC_VERIFY_REG_TMP_N, 1, pDomain->ecP, modSizeInWords);
    PkaCopyDataIntoPkaReg(EC_VERIFY_REG_TMP_NP, 1, ((EcWrstDomain_t*)&(pDomain->llfBuff))->modTag,
                          CC_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS);



    PkaCopyDataIntoPkaReg(rP_remote_x, 1, pPublicKey->x, modSizeInWords);
    PkaCopyDataIntoPkaReg(rP_remote_y, 1, pPublicKey->y, modSizeInWords);
    PkaCopyDataIntoPkaReg(rRandomPoint_x, 1, pRandomPoint->x, ordSizeInWords);
    PkaCopyDataIntoPkaReg(rRandomPoint_y, 1, pRandomPoint->y, ordSizeInWords);
    PkaCopyDataIntoPkaReg(rTwoToOmegaMinusOne, 1, twoToOmegaMinusOne/*src_ptr*/, modSizeInWords);
    PkaCopyDataIntoPkaReg(rTwoToOmega, 1, twoToOmega/*src_ptr*/, ordSizeInWords);
    PkaCopyDataIntoPkaReg(rt, 1, t/*src_ptr*/, ordSizeInWords);
    PkaCopyDataIntoPkaReg(ECC_REG_EC_A, 1, pDomain->ecA, modSizeInWords);



    /*
    calculate x~=2^w+(x AND (2^w-1)); //on the received values
   */
    PKA_AND(LEN_ID_N_PKA_REG_BITS, rXbar, rRandomPoint_x, rTwoToOmegaMinusOne);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, rXbar, rXbar, rTwoToOmega);
    PKA_MOD_MUL(LEN_ID_N_BITS, rXbar, rt, rXbar);

    /* set PKA for operations according to ECC modulus    */
    PKA_CLEAR(LEN_ID_N_PKA_REG_BITS, PKA_REG_T0);
    PKA_CLEAR(LEN_ID_N_PKA_REG_BITS, PKA_REG_T1);
    PKA_WAIT_ON_PKA_DONE();
    CC_HAL_WRITE_REGISTER(CC_REG_OFFSET (CRY_KERNEL, PKA_L0), modSizeInBits);
    PKA_COPY(LEN_ID_N_PKA_REG_BITS, EC_VERIFY_REG_TMP, ECC_REG_N);
    PKA_COPY(LEN_ID_N_PKA_REG_BITS, ECC_REG_N, EC_VERIFY_REG_TMP_N);
    PKA_COPY(LEN_ID_N_PKA_REG_BITS, EC_VERIFY_REG_TMP_N, EC_VERIFY_REG_TMP); //swap mod<->ord
    PKA_COPY(LEN_ID_N_PKA_REG_BITS, ECC_REG_NP, EC_VERIFY_REG_TMP_NP);

        /* Auxiliary values: rn_X = X*ECC_REG_N */
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, ECC_REG_N4 , ECC_REG_N,   ECC_REG_N  );
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, ECC_REG_N4 , ECC_REG_N4, ECC_REG_N4);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, ECC_REG_N8 , ECC_REG_N4, ECC_REG_N4);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, ECC_REG_N12, ECC_REG_N8, ECC_REG_N4);

    /*
     *      Compute EC point  V=[h*tB]PA+[tBx1~]RA mod P =(xV, yV)
     *      Registers should be in that order 24,25, 18, 20, 21, 19, 22, 23
     *
    */

    err = PkaSum2ScalarMullt(
        rVx,
        rVy,
        rt,
        rP_remote_x,
        rP_remote_y,
        rXbar,
        rRandomPoint_x,
        rRandomPoint_y
    );

    if (err != CC_OK) {
        goto End;
    }

    PkaCopyDataFromPkaReg(shared_secret->x, ordSizeInWords, rVx);
    PkaCopyDataFromPkaReg(shared_secret->y, ordSizeInWords, rVy);

    PkaFinishAndMutexUnlock(pkaReqRegs);


End:
    return err;
}



/***********    PkaSm2EcdsaVerify   function      **********************/
/**
 * @brief This function performs verification of SM2 ECDSA signature using PKA.
 *
 * 1. Compute  h = d^-1,  h1 = f*h mod r,  h2 = c*h mod r.
 * 2. Compute  P(Xp,Yp) =  h1*G  + h2*W; c1 = Px mod r
 * 3. Compare  If  c1 != c,  then output "Invalid", else - "valid".
 *
 * Assuming: - PKA is initialized, all data is set into SRAM.
 *
 * @return  - On success CC_OK is returned, on failure an error code.
 */
CCError_t PkaSm2EcdsaVerify(void)
{
    CCError_t err = CC_OK;
    int32_t modSizeInBits, ordSizeInBits;
    uint32_t status1, status2;
    uint32_t temp_store_f[CC_SM2_MODULE_LENGTH_IN_WORDS]; //store the content of f for the usage after PkaSum2ScalarMullt is called
    /* Get sizes */
    ordSizeInBits = CC_HAL_READ_REGISTER(CC_REG_OFFSET (CRY_KERNEL, PKA_L0));
    modSizeInBits = CC_HAL_READ_REGISTER(CC_REG_OFFSET (CRY_KERNEL, PKA_L2));

    PkaCopyDataFromPkaReg(temp_store_f, CC_SM2_MODULE_LENGTH_IN_WORDS, EC_VERIFY_REG_F);


    /*  1. If  C or D (R and S) are not in interval [1,n-1] then the signature is  "invalid" */
    /* temporary set ECC_REG_N = ECC_REG_N - 1 for the following checking */
    PKA_FLIP_BIT0(LEN_ID_N_PKA_REG_BITS, ECC_REG_N, ECC_REG_N);

    /* check C */
    PKA_SUB_IM(LEN_ID_N_PKA_REG_BITS, RES_DISCARD, EC_VERIFY_REG_C, 1/*imm*/);
    PKA_GET_STATUS_CARRY(status1); /* if EC_VERIFY_REG_C >= 1, then status = 0 */
    PKA_SUB(LEN_ID_N_PKA_REG_BITS, RES_DISCARD, ECC_REG_N, EC_VERIFY_REG_C);
    PKA_GET_STATUS_CARRY(status2); /* if EC_VERIFY_REG_C <= ECC_REG_N, then status = 1 */
    if (status1 == 0 || status2 == 0) {
        err = ECWRST_DSA_VERIFY_CALC_SIGN_C_INVALID_ERROR;
        goto End;
    }

    /* check D */
    PKA_SUB_IM(LEN_ID_N_PKA_REG_BITS, RES_DISCARD, EC_VERIFY_REG_D, 1/*imm*/);
    PKA_GET_STATUS_CARRY(status1); /* if EC_VERIFY_REG_D >= 1, then status = 0 */
    PKA_SUB(LEN_ID_N_PKA_REG_BITS, RES_DISCARD, ECC_REG_N, EC_VERIFY_REG_D);
    PKA_GET_STATUS_CARRY(status2); /* if EC_VERIFY_REG_D <= EC_VERIFY_REG_R, then status = 1 */
    if (status1 == 0 || status2 == 0) {
        err = ECWRST_DSA_VERIFY_CALC_SIGN_D_INVALID_ERROR;
        goto End;
    }

    /* restore ECC_REG_N  */
    PKA_FLIP_BIT0(LEN_ID_N_PKA_REG_BITS, ECC_REG_N, ECC_REG_N);

    /* 2.2. t = r+s  mod n */
    PKA_MOD_ADD(LEN_ID_N_PKA_REG_BITS, EC_VERIFY_REG_H2/*Res*/, EC_VERIFY_REG_C/*OpA*/, EC_VERIFY_REG_D/*OpB*/);
    PKA_COPY(LEN_ID_N_PKA_REG_BITS, EC_VERIFY_REG_H1, EC_VERIFY_REG_D);


    /* set PKA for operations according to ECC modulus    */
    PKA_CLEAR(LEN_ID_N_PKA_REG_BITS, PKA_REG_T0);
    PKA_CLEAR(LEN_ID_N_PKA_REG_BITS, PKA_REG_T1);
    PKA_WAIT_ON_PKA_DONE();
    CC_HAL_WRITE_REGISTER(CC_REG_OFFSET (CRY_KERNEL, PKA_L0), modSizeInBits);
    PKA_COPY(LEN_ID_N_PKA_REG_BITS, EC_VERIFY_REG_TMP, ECC_REG_N);
    PKA_COPY(LEN_ID_N_PKA_REG_BITS, ECC_REG_N, EC_VERIFY_REG_TMP_N);
    PKA_COPY(LEN_ID_N_PKA_REG_BITS, EC_VERIFY_REG_TMP_N, EC_VERIFY_REG_TMP); //swap mod<->ord
    PKA_COPY(LEN_ID_N_PKA_REG_BITS, ECC_REG_NP, EC_VERIFY_REG_TMP_NP);

    /* Auxiliary values: rn_X = X*ECC_REG_N */
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, ECC_REG_N4 , ECC_REG_N,   ECC_REG_N  );
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, ECC_REG_N4 , ECC_REG_N4, ECC_REG_N4);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, ECC_REG_N8 , ECC_REG_N4, ECC_REG_N4);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, ECC_REG_N12, ECC_REG_N8, ECC_REG_N4);

    /* 3. Compute EC point  P1 =  h1*G + h2*W by mod P    */
    err = PkaSum2ScalarMullt(EC_VERIFY_REG_P_RX,
                             EC_VERIFY_REG_P_RY,
                             EC_VERIFY_REG_H1,
                             EC_VERIFY_REG_P_GX,
                             EC_VERIFY_REG_P_GY,
                             EC_VERIFY_REG_H2,
                             EC_VERIFY_REG_P_WX,
                             EC_VERIFY_REG_P_WY);
    if(err)
        goto End;

    /* 4. Normalize: C' = pRx mod r. Compare C' == C              */
    PKA_WAIT_ON_PKA_DONE();
    CC_HAL_WRITE_REGISTER(CC_REG_OFFSET (CRY_KERNEL, PKA_L0), ordSizeInBits);


    PKA_COPY(LEN_ID_N_PKA_REG_BITS, EC_VERIFY_REG_TMP, ECC_REG_N);
    PKA_COPY(LEN_ID_N_PKA_REG_BITS, ECC_REG_N, EC_VERIFY_REG_TMP_N);
    PKA_COPY(LEN_ID_N_PKA_REG_BITS, EC_VERIFY_REG_TMP_N, EC_VERIFY_REG_TMP); //swap mod<->ord
    PKA_COPY(LEN_ID_N_PKA_REG_BITS, ECC_REG_NP, EC_VERIFY_REG_TMP_NP);


    PkaCopyDataIntoPkaReg(EC_VERIFY_REG_F, 1, temp_store_f, CC_SM2_MODULE_LENGTH_IN_WORDS);
    PKA_MOD_ADD_IM(LEN_ID_N_PKA_REG_BITS, EC_VERIFY_REG_F/*Res*/, EC_VERIFY_REG_F, 0); /* f mod r */
    PKA_MOD_ADD(LEN_ID_N_PKA_REG_BITS, EC_VERIFY_REG_P_RX/*Res*/, EC_VERIFY_REG_P_RX, EC_VERIFY_REG_F);

    PKA_COMPARE_STATUS(LEN_ID_N_PKA_REG_BITS, EC_VERIFY_REG_P_RX, EC_VERIFY_REG_C, status1);
    if (status1 != 1) {
        err = ECWRST_DSA_VERIFY_CALC_SIGNATURE_IS_INVALID;
    }

End:
    CC_PalMemSetZero(temp_store_f, CC_SM2_MODULE_LENGTH_IN_WORDS);
    return err;

}
