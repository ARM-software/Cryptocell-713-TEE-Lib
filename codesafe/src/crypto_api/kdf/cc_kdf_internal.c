/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

/************* Include Files ****************/

#include "cc_pal_mem.h"
#include "cc_common_math.h"
#ifdef USE_MBEDTLS_CRYPTOCELL
#include "mbedtls_cc_kdf.h"
#else
#include "cc_kdf.h"
#endif
#include "cc_kdf_error.h"
#include "cc_fips_defs.h"
#include "cc_general_defs.h"
#ifdef USE_MBEDTLS_CRYPTOCELL
#include "md.h"
#else
#include "cc_hash.h"
#endif
#include "cc_hash_defs.h"
#include "cc_kdf_internal.h"

/************************ Defines *******************************/
#ifdef USE_MBEDTLS_CRYPTOCELL
#define HASH_FINISH_FUNC(ctx, hashResultBuff)  mbedtls_md_finish(ctx, (unsigned char *)(hashResultBuff))
#define HASH_UPDATE_FUNC(ctx, in, inSize)  mbedtls_md_update((ctx), (in), (inSize))
#else
#define HASH_FINISH_FUNC(ctx, hashResultBuff)  CC_HashFinish(ctx, hashResultBuff)
#define HASH_UPDATE_FUNC(ctx, in, inSize)  CC_HashUpdate((ctx), (in), (inSize))
#endif


/************************ Enums *********************************/

/************************ macros ********************************/


/************************    Global Data    ******************************/

/************************ Private Functions ******************************/

/**
 * The function returns CC_HASH defined parameters according to given
 * KDF Hash mode
 *
 */
static CCError_t  KdfGetHashParameters(
                                CCKdfHashOpMode_t kdfhashMode,
                                CCHashOperationMode_t *pHashMode,
                                uint32_t *pHashBlockSize,
                                uint32_t *pHashDigestSize)
{
        switch (kdfhashMode) {
        case CC_KDF_HASH_SHA1_mode:
                *pHashMode = CC_HASH_SHA1_mode;
                *pHashDigestSize = CC_HASH_SHA1_DIGEST_SIZE_IN_BYTES;
                *pHashBlockSize = CC_HASH_BLOCK_SIZE_IN_BYTES;
                break;
        case CC_KDF_HASH_SHA224_mode:
                *pHashMode = CC_HASH_SHA224_mode;
                *pHashDigestSize = CC_HASH_SHA224_DIGEST_SIZE_IN_BYTES;
                *pHashBlockSize = CC_HASH_BLOCK_SIZE_IN_BYTES;
                break;
        case CC_KDF_HASH_SHA256_mode:
                *pHashMode = CC_HASH_SHA256_mode;
                *pHashDigestSize = CC_HASH_SHA256_DIGEST_SIZE_IN_BYTES;
                *pHashBlockSize = CC_HASH_BLOCK_SIZE_IN_BYTES;
                break;

        case CC_KDF_HASH_SHA384_mode:
                *pHashMode = CC_HASH_SHA384_mode;
                *pHashDigestSize = CC_HASH_SHA384_DIGEST_SIZE_IN_BYTES;
                *pHashBlockSize = CC_HASH_SHA512_BLOCK_SIZE_IN_BYTES;
                break;
        case CC_KDF_HASH_SHA512_mode:
                *pHashMode = CC_HASH_SHA512_mode;
                *pHashDigestSize = CC_HASH_SHA512_DIGEST_SIZE_IN_BYTES;
                *pHashBlockSize = CC_HASH_SHA512_BLOCK_SIZE_IN_BYTES;
                break;

        default:
                return CC_KDF_INVALID_ARGUMENT_HASH_MODE_ERROR;
        }

        return CC_OK;
}


/************************ Public Functions ******************************/

/****************************************************************/
/*!
 @brief kdfKeyDerivFunc performs key derivation according to one of the modes defined in standards:
       NIST 56A rev.3,  ANS X9.42-2001, ANS X9.63, ISO/IEC 18033-2.

The present implementation of the function allows the following operation modes:
<ul><li> CC_KDF_ASN1_DerivMode - mode based on ASN.1 DER encoding; </li>
<li> CC_KDF_NIST56A_ConcatDerivMode - according to NIST 56A rev.3; </li>
<li> CC_KDF_ConcatDerivMode - mode based on concatenation;</li>
<li> CC_KDF_X963_DerivMode = CC_KDF_ConcatDerivMode;</li>
<li> CC_KDF_ISO18033_KDF1_DerivMode, CC_KDF_ISO18033_KDF2_DerivMode - specific modes according to
ISO/IEC 18033-2 standard.</li></ul>

The purpose of this function is to derive a keying data from the shared secret value and some
other optional shared information, included in OtherInfo (SharedInfo).

\note All buffers arguments are represented in Big-Endian format.

@return CC_OK on success.
@return A non-zero value on failure as defined cc_kdf_error.h.
*/
CCError_t  kdfKeyDerivFunc(
                uint8_t              *pZzSecret,            /*!< [in]  A pointer to shared secret value octet string. */
                size_t                zzSecretSize,         /*!< [in]  The size of the shared secret value in bytes.
                                                                       The maximal size is defined as: ::CC_KDF_MAX_SIZE_OF_SHARED_SECRET_VALUE. */
                CCKdfOtherInfo_t     *pOtherInfo,           /*!< [in]  A pointer to the structure, containing pointers to the data, shared by
                                                                       two entities of agreement, depending on KDF mode:
                                                                           1. On NIST 56A rev.3 and KDF ASN1 concatenation modes OtherInfo includes
                                                                              AlgorithmID and some optional data entries as described in the standards;
                                                                           2. On both ISO18033-2 KDF1, KDF2 modes this parameter is ignored and may
                                                                              be set to NULL;
                                                                           3. On other modes it is optional and may be set to NULL. */
                CCKdfHashOpMode_t     kdfHashMode,          /*!< [in]  The KDF identifier (enum) of hash function to be used. */
                CCKdfDerivFuncMode_t  derivMode,            /*!< [in]  The enum value, specifies the key derivation mode. */
                uint8_t              *pKeyingData,          /*!< [out] A pointer to the buffer for derived keying data. */
                size_t                keyingDataSize        /*!< [in]  The size in bytes of the keying data to be derived.
                                                                       The maximal size is defined as :: CC_KDF_MAX_SIZE_OF_KEYING_DATA. */
)

{

    /* FUNCTION DECLARATIONS */

    /* The return error identifier */
    CCError_t error = CC_OK;
    /* HASH function context structure buffer and parameters  */
    CCHashOperationMode_t hashMode;
    uint32_t  hashOutputSize;

    /*The result buffer for the Hash*/
    CCHashResultBuf_t   hashResultBuff;
    /* Total count of full HASH blocs for deriving the keying data */
    uint32_t  countOfHashBlocks;

    /* Loop counters */
    uint32_t  i, j;
    /*counter of Hash blocks (to be hashed with ZZ and OtherInfo) */
    uint32_t counter;
    /* Current output buffer position */
    uint32_t currentOutputBuffPos = 0;

    uint32_t hashBlockSize;
    CCKdfOtherInfoEntries_t fromKdfMode;

#ifdef USE_MBEDTLS_CRYPTOCELL
    const mbedtls_md_info_t *md_info = NULL;
    mbedtls_md_context_t ctx;
#else
    CCHashUserContext_t  ctx;
#endif

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    if (pZzSecret == NULL || pKeyingData == NULL) {
        return CC_KDF_INVALID_ARGUMENT_POINTER_ERROR;
    }

    if (derivMode >= CC_KDF_DerivFunc_NumOfModes) {
        return CC_KDF_INVALID_KEY_DERIVATION_MODE_ERROR;
    }

    if (((derivMode == CC_KDF_ASN1_DerivMode) || (derivMode == CC_KDF_NIST56A_ConcatDerivMode))
                    && (pOtherInfo == NULL || pOtherInfo->dataPointers[CC_KDF_ALGORITHM_ID] == 0)) {
        return CC_KDF_INVALID_ARGUMENT_POINTER_ERROR;
    }

    /* Check sizes of the input data to be hashed according to KDF        *
    *  limitations                            */
    if ((zzSecretSize == 0) || (zzSecretSize > CC_KDF_MAX_SIZE_OF_SHARED_SECRET_VALUE)) {
        return CC_KDF_INVALID_SHARED_SECRET_VALUE_SIZE_ERROR;
    }

    /* Check the size of keying data output. Note: because max size is
       limited in our implementation by CC_KDF_MAX_SIZE_OF_KEYING_DATA
       bytes */
    if ((keyingDataSize == 0) || (keyingDataSize > CC_KDF_MAX_SIZE_OF_KEYING_DATA)) {
        return CC_KDF_INVALID_KEYING_DATA_SIZE_ERROR;
    }


    /*On KDF1 and KDF2 derivation modes set OtherInfo_ptr = NULL */
    if( derivMode == CC_KDF_ISO18033_KDF1_DerivMode || derivMode == CC_KDF_ISO18033_KDF2_DerivMode ) {
        pOtherInfo = NULL;
    }

    /* Get HASH parameters according to current operation modes */
    /*----------------------------------------------------------*/
    if (((error = KdfGetHashParameters(kdfHashMode, &hashMode, &hashBlockSize, &hashOutputSize)) != CC_OK)) {
        goto End;
    }

    /* Set count of HASH blocks and temp buffer pointer and size */
    countOfHashBlocks = ( keyingDataSize + hashOutputSize - 1 )/ hashOutputSize;

#ifdef USE_MBEDTLS_CRYPTOCELL
    md_info = mbedtls_md_info_from_string( HashAlgMode2mbedtlsString[hashMode] );
    if (NULL == md_info)
    {
        error = CC_KDF_INVALID_ARGUMENT_POINTER_ERROR;
        goto End;
    }
    mbedtls_md_init(&ctx);
    if (((error = mbedtls_md_setup(&ctx, md_info, 0)) != CC_OK)) {
        goto End;
    }
#endif

    /* **********  Keying data derivation loop ************ */

    for (i = 0; i < countOfHashBlocks; i++) {

        /* Set the blocks counter in big endianness mode */
        if (derivMode == CC_KDF_ISO18033_KDF1_DerivMode)
            counter = i;
        else
            counter = i+1;

#ifndef BIG__ENDIAN
        counter = CC_COMMON_REVERSE32(counter);
#endif

        /*.... HASH Init function .....*/
#ifdef USE_MBEDTLS_CRYPTOCELL
        if (((error = mbedtls_md_starts(&ctx)) != CC_OK)) {
            goto End;
        }
#else
        if (((error = CC_HashInit(&ctx, hashMode)) != CC_OK)) {
            goto End;
        }
#endif

        /*....... Hashing input data by calling HASH_Update function .......*/
        /*------------------------------------------------------------------*/

        /*  On CC_KDF_NIST56A_ConcatDerivMode: first Hash of the counter    */
        if(derivMode == CC_KDF_NIST56A_ConcatDerivMode) {
            if (((error = HASH_UPDATE_FUNC(&ctx, (uint8_t * )&counter, sizeof(uint32_t))) != CC_OK)) {
                goto End;
            }
        }

        /*.... Hashing of the shared secret value ....*/
        if (((error = HASH_UPDATE_FUNC(&ctx, pZzSecret, zzSecretSize)) != CC_OK)) {
            goto End;
        }

        /*.... Hashing of the AlgorithmID (on ASN1 Derivation Mode only) ....*/
        if (derivMode == CC_KDF_ASN1_DerivMode) {
            if (((error = HASH_UPDATE_FUNC(&ctx,
                                           pOtherInfo->dataPointers[CC_KDF_ALGORITHM_ID],
                                           pOtherInfo->dataSizes[CC_KDF_ALGORITHM_ID])) != CC_OK)) {
                goto End;
            }
            fromKdfMode = CC_KDF_PARTY_U_INFO;
        } else {
            fromKdfMode = CC_KDF_ALGORITHM_ID;
        }

        /*.... Hashing of the blocks counter ....*/
        if(derivMode != CC_KDF_NIST56A_ConcatDerivMode) {
            if (((error = HASH_UPDATE_FUNC(&ctx, (uint8_t * )&counter, sizeof(uint32_t))) != CC_OK)) {
                goto End;
            }
        }

        /* ..... Hashing of remaining data of the OtherInfo ..... */
        if (pOtherInfo != NULL) {

            /* OtherInfo data concatenating and hashing loop */
            for (j = fromKdfMode; j < CC_KDF_MAX_COUNT_OF_ENTRIES; j++) {

                /* if entry exists then hash it */
                if (pOtherInfo->dataPointers[j] != NULL && pOtherInfo->dataSizes[j] != 0) {
                    if (((error = HASH_UPDATE_FUNC(&ctx,
                                                   pOtherInfo->dataPointers[j]/*pointer to entry data*/,
                                                   pOtherInfo->dataSizes[j] /*size of entry data*/))
                                    != CC_OK)) {
                        goto End;
                    }
                }
            }
        }

        /* ..........  HASH Finish operation ............. */
        if (((error = HASH_FINISH_FUNC(&ctx, hashResultBuff)) != CC_OK)) {
            goto End;
        }

        /* Correction of output data size for last block ( if it is not full ) */
        if (i == (countOfHashBlocks - 1)){
                hashOutputSize = keyingDataSize - i * hashOutputSize;

        }
        /* Copying HASH data into output buffer */
        CC_PalMemCopy(&pKeyingData[currentOutputBuffPos],(uint8_t *)hashResultBuff, hashOutputSize);

        /* Increment the output buffer position */
        currentOutputBuffPos += hashOutputSize;
    }

End:
        /* clean temp buffers */
        CC_PalMemSetZero(&hashResultBuff, sizeof(CCHashResultBuf_t));
#ifdef USE_MBEDTLS_CRYPTOCELL
        if(md_info != NULL){
                mbedtls_md_free(&ctx);
        }
#endif
        CC_PalMemSetZero(&ctx, sizeof(ctx));

    return error;

}/* END OF kdfKeyDerivFunc */
