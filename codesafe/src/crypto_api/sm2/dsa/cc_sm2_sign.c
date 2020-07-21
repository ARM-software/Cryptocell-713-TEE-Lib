/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


/************* Include Files ****************/


#include "cc_pal_mem.h"
#include "cc_ecpki_error.h"
#include "ec_wrst_error.h"
#include "cc_ecpki_local.h"
#include "cc_sm2.h"
#include "cc_sm2_int.h"
#include "cc_common.h"
#include "cc_rnd_common.h"
#include "cc_ecpki_domain_sm2.h"
#include "cc_util_int_defs.h"

/**************************************************************************
 *                  CC_Sm2Sign
 **************************************************************************/
/*!
@brief This function performs an SM2 sign operation in integrated form.

\note Using of HASH functions with HASH size greater than EC modulus size, is not recommended!.
Algorithm according to the Public key cryptographic algorithm SM2 based on elliptic curves. Part 2: Digital signature algorithm


The message data is a digest of a hash function.


@return CC_OK on success.
@return A non-zero value on failure as defined cc_ecpki_error.h, cc_hash_error.h or cc_rnd_error.h.


@param[in]      - A pointer to DRBG function
@param[in/out]  - A pointer to the random context - the input to f_rng.
@param[in]      - A pointer to a private key structure.
@param[in]      - A pointer to the hash of the input data.
@param[in]      - Size of the hash of the input data (in words).
@param[out      - Pointer to a buffer for output of signature.
@param[in/out]  - Pointer to the signature size. Used to pass the size of the SignatureOut buffer (in),
                    which must be >= 2 * OrderSizeInBytes. When the API returns, it is replaced with
                    the size of the actual signature (out).

@return <b>CCError_t
 */

CIMPORT_C CCError_t CC_Sm2Sign(
        CCRndGenerateVectWorkFunc_t f_rng,
        void                        *p_rng,
        const CCEcpkiUserPrivKey_t  *pSm2PrivKey,
        const uint32_t              *pHashInput,
        const size_t                 HashInputSize, //in words
        uint8_t                     *pSignatureOut,
        size_t                      *pSignatureOutSize
)
{
    CCError_t err = CC_OK;
    uint32_t *funcTmpBuff;
    const CCEcpkiDomain_t *pDomain = CC_EcpkiGetSm2Domain(); /* Currently the standard specifies only one possible domain for SM2. */
    CCEcpkiPrivKey_t *pPrivKey = 0;
    uint32_t pMessRepres[CC_SM3_RESULT_SIZE_IN_WORDS];
    size_t   ordSizeInBits, ordSizeInBytes, ordSizeInWords, modSizeInWords;
    uint32_t pWorkingBuffer[6*CC_ECPKI_ORDER_MAX_LENGTH_IN_WORDS + CC_PKA_ECPKI_SCALAR_MUL_BUFF_MAX_LENGTH_IN_WORDS];
    uint32_t *pSignR, *pSignS;
    uint32_t regVal;


    /*parameters validation*/
    if ( NULL == f_rng) {
        err = CC_ECPKI_INVALID_RND_FUNC_PTR_ERROR;
        goto End;
    }

    if (pSm2PrivKey == NULL) {
        err = CC_ECDSA_SIGN_INVALID_USER_PRIV_KEY_PTR_ERROR;
        goto End;
    }

    /* check the valid tag  */
    if (pSm2PrivKey->valid_tag != CC_ECPKI_PRIV_KEY_VALIDATION_TAG){
        err = CC_ECDSA_SIGN_USER_PRIV_KEY_VALIDATION_TAG_ERROR;
        goto End;
    }

    if ( pHashInput == NULL ){
        err = CC_ECPKI_INVALID_IN_HASH_PTR_ERROR;
        goto End;
    }

    if ( HashInputSize != CC_SM3_RESULT_SIZE_IN_WORDS ) {
        err = CC_ECPKI_INVALID_IN_HASH_SIZE_ERROR;
        goto End;
    }

    /* check the user's SignatureOut and SignatureOutSize pointers */
    if (pSignatureOut == NULL){
        err = CC_ECDSA_SIGN_INVALID_SIGNATURE_OUT_PTR_ERROR;
        goto End;
    }

    if ( (pSignatureOutSize == NULL) || ((*pSignatureOutSize) < CC_SM2_SIGNATURE_LENGTH_IN_BYTES) ){
        err = CC_ECDSA_SIGN_INVALID_SIGNATURE_OUT_SIZE_PTR_ERROR;
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

    /* Set EC domain parameters modulus and EC order sizes */
    /* Currently there is only one possible domain. This assignment is constant.
     * In the future we may have more than one domain. */
    ordSizeInBits  = pDomain->ordSizeInBits;
    ordSizeInWords = CALC_FULL_32BIT_WORDS(ordSizeInBits);
    modSizeInWords = CALC_FULL_32BIT_WORDS(pDomain->modSizeInBits);
    ordSizeInBytes = CALC_FULL_BYTES (ordSizeInBits);

    if ((ordSizeInWords != CC_SM2_ORDER_LENGTH_IN_WORDS) || (modSizeInWords != CC_SM2_MODULE_LENGTH_IN_WORDS)) {
        err = ECWRST_SCALAR_MULT_INVALID_MOD_ORDER_SIZE_ERROR;
        goto End;
    }

    pSignR = pWorkingBuffer;
    pSignS = pSignR + ordSizeInWords;
    funcTmpBuff = pSignS + ordSizeInWords;


    /* Set 0 to MessageRepresent buffer of length OrdSizeInWords */
    CC_PalMemSetZero(pMessRepres, CC_SM3_RESULT_SIZE_IN_WORDS);

    CC_CommonReverseMemcpy((uint8_t*)pMessRepres, (uint8_t*)(pHashInput),
                           CC_SM3_RESULT_SIZE_IN_BYTES);

    pPrivKey = ( CCEcpkiPrivKey_t *)&pSm2PrivKey->PrivKeyDbBuff;
    err =  EcWrstSm2Sign(
            f_rng, p_rng, pPrivKey,
            pMessRepres,
            pSignR, pSignS, funcTmpBuff);

    if (err != CC_OK) {
        err = CC_ECDSA_SIGN_SIGNING_ERROR;
        goto End;
    }
    /* Output the reversed C,D strings of length orderSizeInBytes */
    err = CC_CommonConvertLswMswWordsToMsbLsbBytes(
            pSignatureOut, ordSizeInBytes,
            pSignR, ordSizeInBytes);
    if (err != CC_OK) {
        err = CC_ECDSA_SIGN_INVALID_SIGNATURE_OUT_SIZE_ERROR;
        goto End;
    }

    err = CC_CommonConvertLswMswWordsToMsbLsbBytes(
            pSignatureOut + ordSizeInBytes, ordSizeInBytes,
            pSignS, ordSizeInBytes);
    if (err != CC_OK) {
        err = CC_ECDSA_SIGN_INVALID_SIGNATURE_OUT_SIZE_ERROR;
        goto End;
    }

    *pSignatureOutSize = 2*ordSizeInBytes;

End:
    /* clear the users context  */
    CC_PalMemSetZero(pWorkingBuffer, 6*CC_ECPKI_ORDER_MAX_LENGTH_IN_WORDS + CC_PKA_ECPKI_SCALAR_MUL_BUFF_MAX_LENGTH_IN_WORDS);
    return err;

}/* END OF CC_Sm2Sign */

