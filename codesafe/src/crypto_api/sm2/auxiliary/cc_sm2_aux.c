/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

/************* Include Files ****************/
#include "cc_sm2_int.h"
#include "cc_sm3.h"
#include "cc_sm2.h"
#include "cc_ecpki_domain_sm2.h"
#include "cc_ecpki_error.h"
#include "cc_ecpki_local.h"
#include "cc_common.h"
#include "cc_pal_mem.h"
#include "cc_util_int_defs.h"

/******************************************************************************
 *                CC_Sm2ComputeMessageDigest
 ******************************************************************************/
/*!
@brief This function calculates both the id  digest and the message digest.


    @param[in] The data of the public key
    @param[in] id as a string.
    @param[in] id length in bytes.
    @param[in] A pointer to the message.
    @param[in] The message size in bytes.
    @param[in] The Working_buffer
    @param[in] The working buffer size should be at least  The working buffer size should be at least
                                2 + idlen + modSizeInBytes*4 + ordSizeInBytes*2
                                + idlen + msglen
    @param[out] The output buffer.
    @param[out] The size of the output buffer in words.


@return CC_OK on success.
@return A non-zero value on failure as defined cc_ecpki_error.h or cc_hash_error.h.
*/

/******************************************************************************/

CIMPORT_C CCError_t CC_Sm2ComputeMessageDigest (
        const CCEcpkiUserPublKey_t  *pUserPublKey,  /*!< [in]        - A pointer to the public key*/
        const char                  *id,            /*!< [in]        - A pointer to the id. */
        const size_t                idlen,          /*!< [in]        - The size of id in bytes. */
        const uint8_t               *pMsg,          /*!< [in]        - A pointer to the message. */
        const size_t                msglen,         /*!< [in]        - The size of the message in bytes. */
        uint8_t                     *pWorkingBuffer,/*!< [in]        - The working buffer */
        const size_t                wblen,          /*!< [in]        - The working buffer size should be at least
                                                                            2 + modSizeInBytes*4 + ordSizeInBytes*2
                                                                            + idlen + msglen*/
        uint32_t                    *pOut,          /*!< [out]       - A pointer to a buffer for the output. */
        size_t                      *pOutLen        /*!< [in/out]    - A pointer to the output length in words. */
)
{
    CCError_t err = CC_OK;
    uint32_t    regVal;
    uint8_t idh[CC_SM3_RESULT_SIZE_IN_BYTES];
    size_t idhlen = CC_SM3_RESULT_SIZE_IN_BYTES ;

    if ( NULL == pUserPublKey){
        err = CC_ECDSA_VERIFY_INVALID_SIGNER_PUBL_KEY_PTR_ERROR;
        goto End;
    }

    if ( pUserPublKey->valid_tag != CC_ECPKI_PUBL_KEY_VALIDATION_TAG){
        err = CC_ECDSA_VERIFY_SIGNER_PUBL_KEY_VALIDATION_TAG_ERROR;
        goto End;
    }

    if ( NULL == id ){
        err = CC_ECPKI_SM2_INVALID_ID_PTR;
        goto End;
    }

    if ( 0 == idlen ){
        err = CC_ECPKI_SM2_INVALID_ID_SIZE;
        goto End;
    }

    if ( NULL == pMsg ){
        err = CC_ECPKI_SM2_INVALID_IN_PARAM_PTR;
        goto End;
    }

    if ( 0 == msglen || msglen >= CC_SM2_MAX_MESSEGE_LEN){
        err = CC_ECPKI_SM2_INVALID_IN_PARAM_SIZE;
        goto End;
    }

    if ( NULL == pWorkingBuffer ) {
        err = CC_ECPKI_GEN_KEY_INVALID_TEMP_DATA_PTR_ERROR;
        goto End;
    }

    if (wblen < 2 + CC_SM2_MODULE_LENGTH_IN_BYTES*4 + CC_SM2_ORDER_LENGTH_IN_BYTES*2
                                + idlen + msglen) {
        err = CC_ECPKI_GEN_KEY_INVALID_TEMP_DATA_PTR_ERROR;
        goto End;
    }

    if ( NULL == pOut ) {
        err = CC_ECPKI_INVALID_OUT_HASH_PTR_ERROR;
        goto End;
    }

    if ( (pOutLen == NULL) || ( CC_SM3_RESULT_SIZE_IN_WORDS != *pOutLen ) ) {
        err = CC_ECPKI_INVALID_OUT_HASH_SIZE_ERROR;
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

    err = Sm2ComputeIdDigest (pUserPublKey, id, idlen, pWorkingBuffer, wblen, idh, &idhlen );
    if (CC_OK != err)
        goto End;

    err = Sm2ComputeMessageFromIdDigest (idh, idhlen, pMsg, msglen, pWorkingBuffer, wblen, pOut, pOutLen );
    if (CC_OK != err)
        goto End;
End:
    CC_PalMemSetZero(idh, idhlen);
    return err;
}






/******************************************************************************
 *                Sm2ComputeIdDigest
 ******************************************************************************/
/*!
@brief This function calculates the id digest.

    @param[in] The data of the public key
    @param[in] id as a string.
    @param[in] id length in bytes.
    @param[in] The Working_buffer
    @param[in] The working buffer size The working buffer size should be at least
                    2 + idlen + modSizeInBytes*4 + ordSizeInBytes*2
    @param[out] The output buffer.
    @param[out] The size of the output buffer in bytes.

@return CC_OK on success.
@return A non-zero value on failure as defined cc_ecpki_error.h or cc_hash_error.h.
*/

/******************************************************************************/

CIMPORT_C CCError_t Sm2ComputeIdDigest (
        const CCEcpkiUserPublKey_t  *pUserPublKey,  /*!< [in]        - A pointer to the public key*/
        const char                  *id,            /*!< [in]        - A pointer to the id. */
        const size_t                idlen,          /*!< [in]        - The size of id in bytes. */
        uint8_t                     *working_buffer,/*!< [in]        - The working buffer */
        const size_t                wblen,          /*!< [in]        - The working buffer size should be at least
                                                                      2 + idlen + modSizeInBytes*4 + ordSizeInBytes*2*/
        uint8_t                     *out,           /*!< [out]       - A pointer to a buffer for the output. */
        size_t                      *outlen         /*!< [in/out]    - output length in bytes. */
)
{
    CCError_t err = CC_OK;
    CCEcpkiPublKey_t* pPubKey = 0;
    const CCEcpkiDomain_t* pDomain = CC_EcpkiGetSm2Domain(); /* Currently the standard specifies only one possible domain for SM2. */
    size_t modSizeInBytes;
    size_t ordSizeInBytes;
    size_t blen = 0;

    size_t idlen_bits = 0;

    if ( NULL == id ){
        err = CC_ECPKI_SM2_INVALID_ID_PTR;
        goto End;
    }

    if ( 0 == idlen || idlen > CC_SM2_MAX_ID_LEN_IN_BYTES){
        err = CC_ECPKI_SM2_INVALID_ID_SIZE;
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

    if ( CC_SM3_RESULT_SIZE_IN_BYTES != *outlen ) {
        err = CC_ECPKI_INVALID_OUT_HASH_SIZE_ERROR;
        goto End;
    }

    /* if the users public key pointer is NULL return an error */
    if (pUserPublKey == NULL){
        err =  CC_ECIES_INVALID_PUBL_KEY_PTR_ERROR;
        goto End;
    }

    /* if the users public key validation TAG is illegal return an error - the context is invalid */
    if (pUserPublKey->valid_tag != CC_ECPKI_PUBL_KEY_VALIDATION_TAG){
        err = CC_ECIES_INVALID_PUBL_KEY_TAG_ERROR;
        goto End;
    }

    /* Currently there is only one possible domain. This assignment is constant.
     * In the future we may have more than one domain. */
    modSizeInBytes = CALC_FULL_BYTES(pDomain->modSizeInBits);
    ordSizeInBytes = CALC_FULL_BYTES(pDomain->ordSizeInBits);
    idlen_bits = idlen * CC_BITS_IN_BYTE;

    blen = 2 + idlen + modSizeInBytes*4 + ordSizeInBytes*2;
    if ( wblen < blen ) {
        err = CC_ECPKI_GEN_KEY_INVALID_TEMP_DATA_PTR_ERROR;
        goto End;
    }
    CC_PalMemSetZero(working_buffer, blen );

    pPubKey = (CCEcpkiPublKey_t *)pUserPublKey->PublKeyDbBuff;
    CC_CommonReverseMemcpy( working_buffer, (uint8_t*)&idlen_bits, 2);
    CC_PalMemCopy( working_buffer + 2, (uint8_t*)id, idlen);
    CC_CommonReverseMemcpy( working_buffer + 2 + idlen,                                            (uint8_t*)pDomain->ecA, modSizeInBytes);
    CC_CommonReverseMemcpy( working_buffer + 2 + idlen +     modSizeInBytes,                       (uint8_t*)pDomain->ecB, modSizeInBytes);
    CC_CommonReverseMemcpy( working_buffer + 2 + idlen + 2 * modSizeInBytes,                       (uint8_t*)pDomain->ecGx, modSizeInBytes);
    CC_CommonReverseMemcpy( working_buffer + 2 + idlen + 3 * modSizeInBytes,                       (uint8_t*)pDomain->ecGy, modSizeInBytes);
    CC_CommonReverseMemcpy( working_buffer + 2 + idlen + 4 * modSizeInBytes,                       (uint8_t*)pPubKey->x, ordSizeInBytes);
    CC_CommonReverseMemcpy( working_buffer + 2 + idlen + 4 * modSizeInBytes + ordSizeInBytes,      (uint8_t*)pPubKey->y, ordSizeInBytes);

    if (CC_OK != (err = CC_Sm3(working_buffer, blen, out)))
        goto End;
    *outlen = CC_SM3_RESULT_SIZE_IN_BYTES;

End:
    if (NULL != working_buffer)
        CC_PalMemSet(working_buffer, 0, wblen);
    return err;
}

