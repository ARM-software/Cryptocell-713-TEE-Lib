/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

/************* Include Files ****************/

#include "cc_pal_mem.h"
#include "cc_common_math.h"
#include "cc_hmac.h"
#include "cc_hkdf.h"
#include "cc_hkdf_error.h"

/************************ Defines *******************************/

/************************ Enums *********************************/

/************************ macros ********************************/


/************************    Global Data    ******************************/

/************************ Private Functions ******************************/

/**
 *   The function returns a number of attributes related to a given hkdf
 *   hash mode
 */
static CCError_t GetParamsFromHKDFHashMode(
        CCHkdfHashOpMode_t          hkdf_hash_mode,
        CCHashOperationMode_t*      hash_mode_ptr,
        size_t*                   hash_output_size_bytes_ptr,
        size_t*                   block_size_bytes_ptr)
{
    /*for all modes, besides SHA384 and SHA512*/
    *block_size_bytes_ptr = CC_HASH_BLOCK_SIZE_IN_BYTES;

    switch (hkdf_hash_mode) {
    case CC_HKDF_HASH_SHA1_mode:
        *hash_mode_ptr = CC_HASH_SHA1_mode;
        *hash_output_size_bytes_ptr = CC_HASH_SHA1_DIGEST_SIZE_IN_BYTES;
        break;
    case CC_HKDF_HASH_SHA224_mode:
        *hash_mode_ptr  = CC_HASH_SHA224_mode;
        *hash_output_size_bytes_ptr = CC_HASH_SHA224_DIGEST_SIZE_IN_BYTES;
        break;
    case CC_HKDF_HASH_SHA256_mode:
        *hash_mode_ptr  = CC_HASH_SHA256_mode;
        *hash_output_size_bytes_ptr = CC_HASH_SHA256_DIGEST_SIZE_IN_BYTES;
        break;
    case CC_HKDF_HASH_SHA384_mode:
        *hash_mode_ptr = CC_HASH_SHA384_mode;
        *hash_output_size_bytes_ptr = CC_HASH_SHA384_DIGEST_SIZE_IN_BYTES;
        *block_size_bytes_ptr = CC_HASH_SHA512_BLOCK_SIZE_IN_BYTES;
        break;
    case CC_HKDF_HASH_SHA512_mode:
        *hash_mode_ptr = CC_HASH_SHA512_mode;
        *hash_output_size_bytes_ptr = CC_HASH_SHA512_DIGEST_SIZE_IN_BYTES;
        *block_size_bytes_ptr = CC_HASH_SHA512_BLOCK_SIZE_IN_BYTES;
        break;
    default:
        return CC_HKDF_INVALID_ARGUMENT_HASH_MODE_ERROR;
    }

    return CC_OK;
}

/****************************************************************/
/**
 * @brief HkdfExtract performs the extract stage of the
 *        HMAC-based key derivation, according to RFC5869.
    Computes a pseudo random key as PRK = HMAC_HASH (key=Salt , Data=Ikm)
 */
static CCError_t  HkdfExtract(
        CCHkdfHashOpMode_t      hkdf_hash_mode,/*!< [in]   hash mode */
        uint8_t*                salt_ptr,      /*!< [in]   A pointer to a non secret random value. can be NULL. */
        size_t                  salt_len,      /*!< [in]   The size of the salt_ptr. */
        uint8_t*                ikm_ptr,       /*!< [in]   A pointer to a input key message. */
        size_t                  ikm_len,       /*!< [in]   The size of the input key message */
        uint8_t*                prk_ptr,       /*!< [out]  A pointer to an output buffer */
        size_t*                 prk_len_ptr    /*!< [in/out]  The size of the output buffer */
                             )
{
    /* The return error identifier */
    CCError_t               rc = CC_OK;
    /* HASH function context structure buffer and parameters  */
    CCHashOperationMode_t   hash_mode;

    size_t                  hash_output_size_bytes;
    size_t                  block_size_bytes;
    /*The result buffer for the Hash*/
    CCHashResultBuf_t       hmac_result_buff;
    uint8_t                 salt_buff[CC_HKDF_MAX_HASH_KEY_SIZE_IN_BYTES]={0};

    if (prk_ptr == NULL || prk_len_ptr == NULL || ikm_ptr == NULL) {
        return CC_HKDF_INVALID_ARGUMENT_POINTER_ERROR;
    }

    rc = GetParamsFromHKDFHashMode(hkdf_hash_mode, &hash_mode,
                                      &hash_output_size_bytes, &block_size_bytes);
    if (rc != CC_OK)
        goto End;

    if (*prk_len_ptr < hash_output_size_bytes ) {
        return CC_HKDF_INVALID_ARGUMENT_SIZE_ERROR;
    }

    if (salt_ptr == NULL){
        if (salt_len!=0)
            return CC_HKDF_INVALID_ARGUMENT_SIZE_ERROR;
    }

    if (salt_len==0) {
        salt_len = hash_output_size_bytes;
        salt_ptr = salt_buff;
    }

    rc = CC_Hmac( hash_mode, salt_ptr, salt_len,
                  ikm_ptr, ikm_len, hmac_result_buff);
    if (rc != CC_OK) {
        goto End;
    }

    /* Copying HASH data into output buffer */
    CC_PalMemCopy(prk_ptr, hmac_result_buff, hash_output_size_bytes);
    *prk_len_ptr = hash_output_size_bytes;

    End:
    /* clean temp buffers */
    CC_PalMemSetZero(hmac_result_buff, sizeof(CCHashResultBuf_t));

    return rc;
}

/**
 * @brief HkdfExpand performs the expand stage of the HMAC-based key derivation,
 *        according to RFC5869.
    N = Ceil(L/HashLen)
    T = T(1) | T(2) | T(3) . . . . . | T(N)
    Computes the output key Material as follow OKM = first L octets of T
    where:
    T(0) = empty_string (zero length)
    T(1) = HMAC_HASH ( PRK, T(0) | info |0x01 )
    T(2) = HMAC_HASH ( PRK, T(1) | info |0x02 )
    T(N) = HMAC_HASH ( PRK, T(N-1) | info |N )   N<=255
 */
CCError_t  HkdfExpand(
        CCHkdfHashOpMode_t      hkdf_hash_mode, /*!< [in]   hash mode */
        uint8_t*                prk_ptr,        /*!< [in]   A pointer to a input message. */
        uint32_t                prk_len,        /*!< [in]   The size of the input message */
        uint8_t*                info,           /*!< [in]   A pointer to a info message. */
        uint32_t                info_len,       /*!< [in]   The size of the info message */
        uint8_t*                okm_ptr,        /*!< [out]  A pointer to an output buffer */
        uint32_t                okm_len)        /*!< [in]   The size of the output buffer */
{
    /* The return error identifier */
    CCError_t               rc = CC_OK;
    uint32_t                T[CC_HKDF_MAX_HASH_DIGEST_SIZE_IN_WORDS]={0};

    /* HASH function context structure buffer and parameters  */
    CCHashOperationMode_t   hash_mode;
    size_t                  hash_output_size_bytes;
    size_t                  block_size_bytes;
    CCHmacUserContext_t     user_context;

    uint32_t N;
    uint32_t i;
    uint8_t  counter;
    uint32_t disp=0;


    if (info == NULL) {
        info_len = 0;
    }

    if (prk_ptr == NULL || okm_ptr == NULL || prk_len == 0 || okm_len == 0) {
        return CC_HKDF_INVALID_ARGUMENT_POINTER_ERROR;
    }

    rc = GetParamsFromHKDFHashMode(hkdf_hash_mode, &hash_mode,
                                      &hash_output_size_bytes, &block_size_bytes);
    if (rc != CC_OK){
        return rc;
    }

    if (prk_len < hash_output_size_bytes) {
        return CC_HKDF_INVALID_ARGUMENT_SIZE_ERROR;
    }

    N = okm_len / hash_output_size_bytes;
    if ( N*hash_output_size_bytes != okm_len ){
        ++N;
    }

    if (N > 255){
        return CC_HKDF_INVALID_ARGUMENT_SIZE_ERROR;
    }

    for (i=1; i<=N; i++) {
        counter = (uint8_t)i;

        rc = CC_HmacInit(&user_context, hash_mode, prk_ptr, prk_len);
        if(rc != CC_OK) {
            goto Error;
        }

        if (i != 1) {
            rc = CC_HmacUpdate(&user_context, (uint8_t*)T,
                    hash_output_size_bytes);
            if(rc != CC_OK) {
                goto Error;
            }
        }

        rc = CC_HmacUpdate(&user_context, (uint8_t*)info, info_len);
        if(rc != CC_OK) {
            goto Error;
        }

        rc = CC_HmacUpdate(&user_context, &counter, 1);
        if(rc != CC_OK) {
            goto Error;
        }

        rc = CC_HmacFinish(&user_context, T);
        if(rc != CC_OK) {
            goto Error;
        }

        CC_PalMemCopy(okm_ptr+disp, T, (i!=N)?hash_output_size_bytes:okm_len-disp);
        disp += hash_output_size_bytes;
    }

Error:
    if(rc != CC_OK) {
        /* clean out buffer when error  */
        CC_PalMemSetZero(okm_ptr, okm_len);
    }
    CC_HmacFree(&user_context);

    return rc;
}

/************************ Public Functions ******************************/

/**
 * @brief CC_HkdfKeyDerivFunc performs the HMAC-based key derivation,
 *        according to RFC5869
 */
CEXPORT_C CCError_t  CC_HkdfKeyDerivFunc(
        CCHkdfHashOpMode_t      hkdf_hash_mode,
        uint8_t*                salt_ptr,
        size_t                  salt_len,
        uint8_t*                ikm_ptr,
        size_t                  ikm_len,
        uint8_t*                info_ptr,
        size_t                  info_len,
        uint8_t*                okm,
        size_t                  okm_len,
        CCBool                  is_strong_key
)
{
    /* The return error identifier */
    CCError_t rc = CC_OK;
    uint8_t   prk_buff[CC_HKDF_MAX_HASH_DIGEST_SIZE_IN_BYTES];
    size_t    prk_buff_len = sizeof(prk_buff);

    if (is_strong_key == CC_FALSE) {
        rc = HkdfExtract(hkdf_hash_mode, salt_ptr, salt_len, ikm_ptr, ikm_len,
                prk_buff, &prk_buff_len);

        if (rc != CC_OK) {
            return rc;
        }

        rc = HkdfExpand(hkdf_hash_mode, prk_buff, prk_buff_len,
                           info_ptr,info_len, okm, okm_len);
    } else { //skip extraction phase
        rc = HkdfExpand(hkdf_hash_mode, ikm_ptr, ikm_len,
                           info_ptr, info_len, okm, okm_len);
    }

    return rc;
}
