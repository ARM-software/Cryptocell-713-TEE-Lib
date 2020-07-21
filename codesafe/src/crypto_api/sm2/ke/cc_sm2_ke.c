/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


/************* Include Files ****************/

#include "cc_pal_mem.h"
#include "cc_ecpki_error.h"
#include "cc_ecpki_local.h"
#include "cc_ecpki_types.h"
#include "cc_common.h"
#include "ec_wrst_error.h"
#include "cc_sm2.h"
#include "cc_sm2_int.h"
#include "cc_ecpki_domain_sm2.h"
#include "cc_ecpki_build.h"
#include "cc_util_int_defs.h"

/**************************************************************************
 *                    CC_Sm2KeyExchangeContext_init function
 **************************************************************************/
/*!
@brief The context initiation

@return CC_OK on success.
@return A non-zero value on failure

 */

CEXPORT_C CCError_t CC_Sm2KeyExchangeContext_init(
        CC_Sm2KeContext_t           *pCtx,              /*!< [in]        - The key exchange context to be initialized. */
        uint8_t                     *pWorkingBuffer,    /*!< [in]        - The working buffer */
        const size_t                wblen,              /*!< [in]        - The working buffer size should be at least
                                                                                  2 + modSizeInBytes*4 + ordSizeInBytes*2 +
                                                                                  max(remoteId, remoteIdLen) */
        CCEcpkiUserPublKey_t        *pPubKey,           /*!< [in]        - The data of the public key. */
        CCEcpkiUserPrivKey_t        *pPrivKey,          /*!< [in]        - The data of the private key. */
        CCEcpkiUserPublKey_t        *pRemoteUserPubKey, /*!< [in]        - The data of the remote public key. */
        const char                  *pId,                /*!< [in]         - A pointer to the id. */
        size_t                      idlen,              /*!< [in]        - The id size in bytes. */
        const char                  *pRemoteId,          /*!< [in]        - A pointer to an remote id. */
        size_t                      remoteIdLen,        /*!< [in]        - The remote id size in bytes. */
        uint8_t                     isInitiator,        /*!< [in]        - 1 if it is an initiator side. */
        uint8_t                     confRequired       /*!< [in]        - bit mask - 1st bit if we want conf, 2nd if the other part wants*/

)
{
    CCError_t err = CC_OK;
    size_t idMaxLen = 0;
    uint32_t regVal;

    if (NULL == pCtx) {
        err = CC_ECPKI_SM2_INVALID_KE_CONTEXT_PTR;
        goto End;
    }

    if (NULL == pPubKey) {
        err = CC_ECIES_INVALID_PUBL_KEY_PTR_ERROR;
        goto End;
    }

    if (NULL == pPrivKey) {
        err = CC_ECIES_INVALID_PRIV_KEY_PTR_ERROR;
        goto End;
    }

    if (NULL == pRemoteUserPubKey) {
        err = CC_ECIES_INVALID_PUBL_KEY_PTR_ERROR;
        goto End;
    }

    if (NULL == pId) {
        err = CC_ECPKI_SM2_INVALID_ID_PTR;
        goto End;
    }

    if (idlen == 0 || idlen > CC_SM2_MAX_ID_LEN_IN_BYTES) {
        err = CC_ECPKI_SM2_INVALID_ID_SIZE;
        goto End;
    }

    if (NULL == pRemoteId) {
        err = CC_ECPKI_SM2_INVALID_ID_PTR;
        goto End;
    }

    if (remoteIdLen == 0 || remoteIdLen > CC_SM2_MAX_ID_LEN_IN_BYTES) {
        err = CC_ECPKI_SM2_INVALID_ID_SIZE;
        goto End;
    }


    if ( NULL == pWorkingBuffer ) {
        err = CC_ECPKI_SM2_INVALID_IN_PARAM_PTR;
        goto End;
    }

    /* The function should refuse to operate if the secure disable bit is set */
    CC_UTIL_IS_SECURE_DISABLE_FLAG_SET(regVal);
    if (regVal == SECURE_DISABLE_FLAG_SET) {
        return CC_ECPKI_SM2_SD_ENABLED_ERR;
    }

    /* The function should refuse to operate if the Fatal Error bit is set */
    CC_UTIL_IS_FATAL_ERROR_SET(regVal);
    if (regVal == FATAL_ERROR_FLAG_SET) {
        return CC_ECPKI_SM2_FATAL_ERR_IS_LOCKED_ERR;
    }

    idMaxLen = (idlen > remoteIdLen)? idlen : remoteIdLen;
    if (wblen < 2 + CC_SM2_MODULE_LENGTH_IN_BYTES*4 + CC_SM2_ORDER_LENGTH_IN_BYTES*2
                                + idMaxLen) {
        err = CC_ECPKI_SM2_INVALID_IN_PARAM_SIZE;
        goto End;
    }


    CC_PalMemSetZero((void*)pCtx, sizeof(CC_Sm2KeContext_t));

    /* Set sizes of the buffers saved in the context */
    pCtx->Z_value_size = CC_SM3_RESULT_SIZE_IN_BYTES;
    pCtx->conf_value_size = CC_SM3_RESULT_SIZE_IN_BYTES;
    pCtx->idlen = idlen;
    pCtx->remoteIdLen = remoteIdLen;
    pCtx->conf_value_size = CC_SM3_RESULT_SIZE_IN_BYTES;

    /* Set pointers inside the context*/
    pCtx->pId = pId;
    pCtx->pRemoteId = pRemoteId;

    pCtx->isInitiator = isInitiator;

    /* Copy buffers of key to the context */
    CC_PalMemCopy (&pCtx->pubKey, pPubKey, sizeof (CCEcpkiUserPublKey_t) );
    CC_PalMemCopy (&pCtx->privKey, pPrivKey, sizeof (CCEcpkiUserPrivKey_t) );
    CC_PalMemCopy (&pCtx->remotePubKey, pRemoteUserPubKey, sizeof (CCEcpkiUserPublKey_t) );

    /* calculate id digest 𝐻256(𝐸𝑁𝑇𝐿𝐴||𝐼𝐷𝐴||𝑎||𝑏||𝑥𝐺||𝑦𝐺||𝑥𝐴||𝑦𝐴) */
    err =  Sm2ComputeIdDigest ( pPubKey, pId, idlen, pWorkingBuffer, wblen, pCtx->Z, &pCtx->Z_value_size  );
    if (CC_OK != err) {
        goto Cleanup;
    }
    err =  Sm2ComputeIdDigest ( pRemoteUserPubKey, pRemoteId, remoteIdLen, pWorkingBuffer, wblen, pCtx->Z_remote, &pCtx->Z_value_size  );
    if (CC_OK != err){
        goto Cleanup;
    }

    pCtx->confirmation = confRequired;

Cleanup:
    if (err != CC_OK && NULL != pCtx ){
        CC_PalMemSetZero( pCtx, sizeof (CC_Sm2KeContext_t));
    }
    CC_PalMemSetZero ( pWorkingBuffer, wblen );
End:
    return err;

}

/**************************************************************************
 *                    CC_Sm2KeyExchangeContext_cleanup
 * **************************************************************************/
/*!
@brief The context cleanup

@return CC_OK on success.

@param[in]  A pointer to a context structure.

 */
CEXPORT_C void CC_Sm2KeyExchangeContext_cleanup(
        CC_Sm2KeContext_t           *pCtx       /*!< [in]        - A pointer to a context structure. */
)
{
    if (NULL == pCtx) {
        return;
    }
   CC_PalMemSetZero(pCtx, sizeof(CC_Sm2KeContext_t));
}
/**************************************************************************
 *                    CC_Sm2Kdf
 **************************************************************************/
/*!
@brief The KDF

@return CC_OK on success.
@return A non-zero value on failure
 */

CEXPORT_C CCError_t CC_Sm2Kdf (
        const CC_Sm2KeContext_t     *pCtx,                  /*!< [in] A Pointer to a key exchange context.*/
        const size_t                SharedSecretSizeInBits, /*!< [in] The required size of the key . */
        uint8_t                     *pKeyOut,               /*!< [in] A Pointer to a buffer for the derived key. */
        size_t                      *pKeyOutSize            /*!< [in/out] A Pointer to the derived key size.*/
)
{
    CCError_t err = CC_OK;
    uint8_t cur_digest[CC_SM3_RESULT_SIZE_IN_BYTES];
    size_t blocks = 0;
    size_t bits_in_last_block = 0;
    size_t bytes_in_last_block = 0;
    uint32_t regVal;
    uint32_t ct;
    size_t out_block_size = CC_SM3_RESULT_SIZE_IN_BYTES;

    if ( NULL == pCtx ) {
        err = CC_ECPKI_SM2_INVALID_KE_CONTEXT_PTR;
        goto End;
    }

    if ( ( 0 == SharedSecretSizeInBits ) || ((SharedSecretSizeInBits % CC_BITS_IN_BYTE) != 0) ){
        err = CC_ECPKI_SM2_INVALID_IN_PARAM_SIZE;
        goto End;
    }

    if ( NULL == pKeyOutSize || *pKeyOutSize * CC_BITS_IN_BYTE < SharedSecretSizeInBits ) {
        err = CC_ECPKI_SM2_INVALID_OUT_PARAM_SIZE;
        goto End;
    }

    if ( NULL == pKeyOut ) {
        err = CC_ECPKI_INVALID_OUT_HASH_PTR_ERROR;
        goto End;
    }

    /* The function should refuse to operate if the secure disable bit is set */
    CC_UTIL_IS_SECURE_DISABLE_FLAG_SET(regVal);
    if (regVal == SECURE_DISABLE_FLAG_SET) {
        return CC_ECPKI_SM2_SD_ENABLED_ERR;
    }

    /* The function should refuse to operate if the Fatal Error bit is set */
    CC_UTIL_IS_FATAL_ERROR_SET(regVal);
    if (regVal == FATAL_ERROR_FLAG_SET) {
        return CC_ECPKI_SM2_FATAL_ERR_IS_LOCKED_ERR;
    }

    /*calculate number of blocks/SM3 digests*/
    blocks = ( SharedSecretSizeInBits + ( CC_SM3_RESULT_SIZE_IN_BITS - 1 ) ) / (CC_SM3_RESULT_SIZE_IN_BITS);
    bits_in_last_block = ((SharedSecretSizeInBits % CC_SM3_RESULT_SIZE_IN_BITS) == 0) ? CC_SM3_RESULT_SIZE_IN_BITS :  SharedSecretSizeInBits % CC_SM3_RESULT_SIZE_IN_BITS;
    bytes_in_last_block = (bits_in_last_block + CC_BITS_IN_BYTE - 1) / CC_BITS_IN_BYTE;

    for (ct = 1U; ct <= blocks; ct++) {
        Sm2CalcKdfBlock (pCtx, ct, cur_digest, &out_block_size);
        if (ct == blocks) {
            CC_PalMemCopy(pKeyOut + (ct-1)*CC_SM3_RESULT_SIZE_IN_BYTES, cur_digest, bytes_in_last_block);
            break;
        }
        CC_PalMemCopy(pKeyOut + (ct-1)*CC_SM3_RESULT_SIZE_IN_BYTES, cur_digest, CC_SM3_RESULT_SIZE_IN_BYTES);
    }

    *pKeyOutSize = (blocks-1) * CC_SM3_RESULT_SIZE_IN_BYTES + ((bits_in_last_block + CC_BITS_IN_BYTE - 1) / CC_BITS_IN_BYTE);

End:
    if (err!= CC_OK && NULL != pKeyOut && NULL != pKeyOutSize){
        CC_PalMemSetZero( pKeyOut, *pKeyOutSize);
    }
    return err;
}


/**************************************************************************
 *                    CC_Sm2CalculateECPoint
 * *************************************************************************/
/*!

@brief Calculates a random ECPoint

@return CC_OK on success.
@return A non-zero value on failure
 */

CEXPORT_C CCError_t CC_Sm2CalculateECPoint (
        CCRndGenerateVectWorkFunc_t f_rng,          /*!< [in]       - A pointer to DRBG function                            */
        void                        *p_rng,         /*!< [in/out]   - A pointer to the random context - the input to f_rng.     */
        CC_Sm2KeContext_t           *pCtx,          /*!< [in/out]   - A pointer to a KE context                             */
        CCEcpkiUserPublKey_t        *pRandomPoint   /*!< [out]      - The output random EC point as an ephemeral public key.*/
)
{

    CCError_t err = CC_OK;
    CCEcpkiBuildTempData_t  build_temp_data;
    uint8_t pub_key_buf[CC_SM2_ORDER_LENGTH_IN_BYTES*2+1];
    uint32_t regVal;

    const CCEcpkiDomain_t *pDomain = CC_EcpkiGetSm2Domain(); /* Currently the standard specifies only one possible domain for SM2. */
    size_t ordSizeInBits, ordSizeInWords, modSizeInWords;
    /* pointers to result EC point coordinates x, y */
    uint32_t *pEphemKeyBuf, *pMaxVect;
    uint32_t *funcTmpBuff;
    uint32_t pWorkingBuffer[CC_ECPKI_ORDER_MAX_LENGTH_IN_WORDS  +
                            CC_PKA_ECPKI_SCALAR_MUL_BUFF_MAX_LENGTH_IN_WORDS];

    if ( NULL == pCtx ) {
        err = CC_ECPKI_SM2_INVALID_KE_CONTEXT_PTR;
        goto End;
    }

    if ( NULL == f_rng) {
        err = CC_ECPKI_INVALID_RND_FUNC_PTR_ERROR;
        goto End;
    }


    if ( NULL == pRandomPoint) {
        err = CC_ECPKI_SM2_INVALID_EPHEMERAL_PUB_OUT_PTR;
        goto End;
    }

    /* The function should refuse to operate if the secure disable bit is set */
    CC_UTIL_IS_SECURE_DISABLE_FLAG_SET(regVal);
    if (regVal == SECURE_DISABLE_FLAG_SET) {
        return CC_ECPKI_SM2_SD_ENABLED_ERR;
    }

    /* The function should refuse to operate if the Fatal Error bit is set */
    CC_UTIL_IS_FATAL_ERROR_SET(regVal);
    if (regVal == FATAL_ERROR_FLAG_SET) {
        return CC_ECPKI_SM2_FATAL_ERR_IS_LOCKED_ERR;
    }

    /* set EC domain parameters modulus and EC order sizes */
    /* Currently there is only one possible domain. This assignment is constant.
     * In the future we may have more than one domain. */
    ordSizeInBits  = pDomain->ordSizeInBits;
    ordSizeInWords = CALC_FULL_32BIT_WORDS(ordSizeInBits);
    modSizeInWords = CALC_FULL_32BIT_WORDS(pDomain->modSizeInBits);

    if ((ordSizeInWords > CC_SM2_ORDER_LENGTH_IN_WORDS) ||
            (modSizeInWords> CC_SM2_MODULE_LENGTH_IN_WORDS)) {
        err = ECWRST_SCALAR_MULT_INVALID_MOD_ORDER_SIZE_ERROR;
        goto End;
    }

    pEphemKeyBuf    = pWorkingBuffer;
    pMaxVect        = pEphemKeyBuf + ordSizeInWords;


    /*  Generate random ephemeral key   *
     * Note: Checking, that private ephemer.key  0 < k < EC order *
     * performed on LLF during scalar multiplication             */
    /* Set bytes MaxVect= EcOrder. */

    pMaxVect[ordSizeInWords-1] = 0; /*zero MSWord of maxVect*/
    CC_PalMemCopy((uint8_t*)pMaxVect, (uint8_t*)pDomain->ecR, sizeof(uint32_t)*ordSizeInWords);
    pEphemKeyBuf[ordSizeInWords-1] = 0; /*zero MSWord*/
    err = CC_RndGenerateVectorInRange(
            f_rng, p_rng, ordSizeInBits, (uint8_t*)pMaxVect/* maxVect*/, (uint8_t*)pEphemKeyBuf);
    if (err) {
        goto Cleanup;
    }

    /* Calculate ephemeral public key               */
    funcTmpBuff = pMaxVect; /* because pMaxVect not needed yet */

    err = EcWrstSm2CalculateRandom (pDomain, (CCEcpkiPrivKey_t*)&pCtx->privKey.PrivKeyDbBuff,
                              funcTmpBuff, pEphemKeyBuf, &pCtx->ephemeral_pub, pCtx->t );
    if (err) {
        goto Cleanup;
    }


    pub_key_buf[0]=4; /*uncompressed*/
    err = CC_CommonConvertLswMswWordsToMsbLsbBytes(
                                                     pub_key_buf+1, ordSizeInWords*4,
                                                     pCtx->ephemeral_pub.x, ordSizeInWords*4);
    if (err) {
        goto Cleanup;
    }

    err = CC_CommonConvertLswMswWordsToMsbLsbBytes(
                                                     pub_key_buf+1+ordSizeInWords*4, ordSizeInWords*4,
                                                     pCtx->ephemeral_pub.y, ordSizeInWords*4);

    if (err) {
        goto Cleanup;
    }
    err = CC_EcpkiPublKeyBuildAndCheck (pDomain, pub_key_buf, 2*ordSizeInWords*4+1,
                                      0/*CheckPointersAndSizesOnly*/, pRandomPoint, &build_temp_data);
    if (err) {
        goto Cleanup;
    }

Cleanup:
    if (err != CC_OK && NULL != pCtx){
        CC_PalMemSetZero( pCtx, sizeof (CC_Sm2KeContext_t));
    }
    if (err != CC_OK && NULL != pRandomPoint){
        CC_PalMemSetZero( pRandomPoint, sizeof (CCEcpkiUserPublKey_t));
    }
    CC_PalMemSetZero( pWorkingBuffer, CC_ECPKI_ORDER_MAX_LENGTH_IN_WORDS  + CC_PKA_ECPKI_SCALAR_MUL_BUFF_MAX_LENGTH_IN_WORDS);
End:
    return err;
}




/**************************************************************************
 *                    CC_Sm2CalculateSharedSecret
 * *************************************************************************/
/*!

@brief Calculates shared secret and optionally the internal confirmation value and stores
   them into the context. Optionally calculates output confirmation value.

@return CC_OK on success.
@return A non-zero value on failure
 */

CEXPORT_C CCError_t CC_Sm2CalculateSharedSecret (
        CC_Sm2KeContext_t           *pCtx,                      /*!< [in/out]   - A pointer to the key exchange context.*/
        const CCEcpkiUserPublKey_t  *pRandomPoint,              /*!< [in]       - A pointer to the random point from the second party. */
        uint8_t                     *pConfirmationValueOut,     /*!< [out]      - The output confirmation value.*/
        size_t                      *pConfirmationValueOutSize  /*!< [in/out]   - A pointer to the output confirmation value size in bytes */
)
{

    CCError_t               err                   = CC_OK;
    CCEcpkiPublKey_t*       pRemotePubKey ;
    uint8_t                 int_conf_prefix       = 0;
    uint8_t                 out_conf_prefix       = 0;
    uint8_t                 conf_temp_buffer[CC_SM3_RESULT_SIZE_IN_BYTES];
    size_t                  conf_template_buffer_size = CC_SM3_RESULT_SIZE_IN_BYTES;
    CCEcpkiPublKey_t        *pEphPubKey = 0;
    uint32_t regVal;

    /*domain related values*/

    const CCEcpkiDomain_t *pDomain = CC_EcpkiGetSm2Domain(); /* Currently the standard specifies only one possible domain for SM2. */
    size_t ordSizeInBits, ordSizeInWords, modSizeInWords, modSizeInBits, ordSizeInBytes;

    if (NULL == pCtx) {
        err = CC_ECPKI_SM2_INVALID_KE_CONTEXT_PTR;
        goto End;
    }
    if (NULL == pRandomPoint) {
        err = CC_ECPKI_SM2_INVALID_EPHEMERAL_PUB_IN_PTR;
        goto End;
    }

    if (NULL == pConfirmationValueOut) {
        err = CC_ECPKI_SM2_INVALID_OUT_PARAM_PTR;
        goto End;
    }
    if ( (pConfirmationValueOutSize == NULL) || (CC_SM3_RESULT_SIZE_IN_BYTES > *pConfirmationValueOutSize) ) {
        err = CC_ECPKI_SM2_INVALID_OUT_PARAM_SIZE;
        goto End;
    }

    /* The function should refuse to operate if the secure disable bit is set */
    CC_UTIL_IS_SECURE_DISABLE_FLAG_SET(regVal);
    if (regVal == SECURE_DISABLE_FLAG_SET) {
        return CC_ECPKI_SM2_SD_ENABLED_ERR;
    }

    /* The function should refuse to operate if the Fatal Error bit is set */
    CC_UTIL_IS_FATAL_ERROR_SET(regVal);
    if (regVal == FATAL_ERROR_FLAG_SET) {
        return CC_ECPKI_SM2_FATAL_ERR_IS_LOCKED_ERR;
    }

    pRemotePubKey = (CCEcpkiPublKey_t *)&pCtx->remotePubKey.PublKeyDbBuff;
    pEphPubKey = (CCEcpkiPublKey_t *)&pRandomPoint->PublKeyDbBuff;
    /* set EC domain parameters modulus and EC order sizes */
    /* Currently there is only one possible domain. This assignment is constant.
     * In the future we may have more than one domain. */
    ordSizeInBits  = pDomain->ordSizeInBits;
    modSizeInBits  = pDomain->modSizeInBits;
    ordSizeInWords = CALC_FULL_32BIT_WORDS(ordSizeInBits);
    modSizeInWords = CALC_FULL_32BIT_WORDS(modSizeInBits);
    ordSizeInBytes = CALC_FULL_BYTES(ordSizeInBits);

    if ((ordSizeInWords > CC_SM2_ORDER_LENGTH_IN_WORDS) ||
            (modSizeInWords> CC_SM2_MODULE_LENGTH_IN_WORDS))
    {
        err = ECWRST_SCALAR_MULT_INVALID_MOD_ORDER_SIZE_ERROR;
        goto End;
    }


    CC_PalMemCopy( (uint8_t*)pCtx->remote_ephemeral_pub.x, (uint8_t*)pEphPubKey->x, ordSizeInBytes);
    CC_PalMemCopy( (uint8_t*)pCtx->remote_ephemeral_pub.y, (uint8_t*)pEphPubKey->y, ordSizeInBytes);


    err = EcWrstSm2CalculateSharedSecret (pRemotePubKey, &pCtx->remote_ephemeral_pub, pDomain, pCtx->t, &pCtx->V);
    if (CC_OK != err) {
        goto Cleanup;
    }


    if (pCtx->isInitiator){
        int_conf_prefix = 0x2;
        out_conf_prefix = 0x3;
    }
    else {
        int_conf_prefix = 0x3;
        out_conf_prefix = 0x2;
    }

    if (pCtx->confirmation != 0){
        err = Sm2CalculateConfirmationTemplate (pCtx, conf_temp_buffer, &conf_template_buffer_size);
        if (err != CC_OK) {
            goto Cleanup;
        }
    }

    if (pCtx->confirmation & 1) /*This party wants a confirmation from the second party*/
    {
        /*so generate the internal confirmation value and store it in the context*/
        err = Sm2CalculateConfirmationValue (pCtx, int_conf_prefix, conf_temp_buffer, conf_template_buffer_size,
                                          pCtx->conf_value, &pCtx->conf_value_size);
        if (err != CC_OK) {
            goto Cleanup;
        }

    }
    if (pCtx->confirmation & 2) /*The other party wants a confirmation from this party*/
    {
        /*so generate the out confirmation value and store it in the context*/
        err = Sm2CalculateConfirmationValue (pCtx, out_conf_prefix, conf_temp_buffer, conf_template_buffer_size,
                                          pConfirmationValueOut, pConfirmationValueOutSize);
        if (err != CC_OK) {
            goto Cleanup;
        }
    }

Cleanup:
    if (err != CC_OK && NULL != pCtx){
        CC_PalMemSetZero( pCtx, sizeof (CC_Sm2KeContext_t));
    }
    if ( (err != CC_OK) && (NULL != pConfirmationValueOut) && (NULL != pConfirmationValueOutSize)){
        CC_PalMemSetZero( pConfirmationValueOut, *pConfirmationValueOutSize);
    }
End:
    return err;
}



/**************************************************************************
 *                    CC_Sm2Confirmation
 * *************************************************************************/
/*!

@brief @brief verifies the confirmation value sent by other side with the one
calculated and stored in the context


@return CC_OK on success.
@return A non-zero value on failure
 */

CEXPORT_C CCError_t CC_Sm2Confirmation (
        const CC_Sm2KeContext_t     *pCtx,                      /*!< [in]       - Pointer to the key exchange context.*/
        const uint8_t               *pConfirmationValue,        /*!< [in]       - A pointer to a second party confirmation value. */
        const size_t                confirmationValueSize      /*!< [in]       - Second party confirmation size. */
)
{
    CCError_t err = CC_OK;
    if (NULL == pCtx) {
        err = CC_ECPKI_SM2_INVALID_KE_CONTEXT_PTR;
        goto End;
    }
    if (NULL == pConfirmationValue) {
        err = CC_ECPKI_SM2_INVALID_IN_PARAM_PTR;
        goto End;
    }

    if (CC_SM3_RESULT_SIZE_IN_BYTES != confirmationValueSize) {
        err = CC_ECPKI_SM2_INVALID_IN_PARAM_SIZE;
        goto End;
    }

    err = CC_PalMemCmp(pConfirmationValue, pCtx->conf_value, confirmationValueSize);
    if (err != 0) {
        err = CC_ECPKI_SM2_CONFIRMATION_FAILED;
        goto End;
    }
End:
    return err;
}

