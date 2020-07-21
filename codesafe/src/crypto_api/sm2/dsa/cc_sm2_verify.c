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
#include "cc_util_int_defs.h"

/**************************************************************************
*                   CC_Sm2Verify
**************************************************************************/
/*!
@brief This function performs an SM2 verify operation in integrated form.
Algorithm according to the Public key cryptographic algorithm SM2 based on
elliptic curves. Part 2: Digital signature algorithm

The message data is a digest of a hash function.

@return CC_OK on success.
@return A non-zero value on failure as defined cc_ecpki_error.h or cc_hash_error.h.
@param[in] Pointer to a user public key structure.
@param[in] Pointer to the signature to be verified.
@param[in] Size of the signature (in bytes).
@param[in] Pointer to the hash of the input data that was signed
@param[in] Size of the hash of the input data (in words).
*/

CIMPORT_C CCError_t CC_Sm2Verify (
    const CCEcpkiUserPublKey_t  *pUserPublKey,
    uint8_t                     *pSignatureIn,
    const size_t                SignatureSizeBytes,
    const uint32_t              *pMessageHash,
    const size_t                HashInputSize
)
{
    CCError_t err = CC_OK;
    uint32_t pWorkingContext[CC_ECPKI_ORDER_MAX_LENGTH_IN_WORDS*3];
    const CCEcpkiDomain_t *pDomain = CC_EcpkiGetSm2Domain(); /* Currently the standard specifies only one possible domain for SM2. */
    CCEcpkiPublKey_t  *PublKey_ptr;
    uint32_t regVal;
    uint32_t    *pMessRepres, *pSignatureR, *pSignatureS;
    size_t      orderSizeInBits, orderSizeInBytes, orderSizeInWords;

    /*if the public key object is NULL return an error*/
    if (pUserPublKey == NULL){
        err = CC_ECDSA_VERIFY_INVALID_SIGNER_PUBL_KEY_PTR_ERROR;
        goto End;
    }

    if (pUserPublKey->valid_tag != CC_ECPKI_PUBL_KEY_VALIDATION_TAG){
        err = CC_ECDSA_VERIFY_SIGNER_PUBL_KEY_VALIDATION_TAG_ERROR;
        goto End;
    }

    /* if the users MessageHash pointer is illegal return an error */
    if (pMessageHash == NULL){
        err = CC_ECDSA_VERIFY_INVALID_MESSAGE_DATA_IN_PTR_ERROR;
        goto End;
    }

    if (HashInputSize != CC_SM3_RESULT_SIZE_IN_WORDS){
        err = CC_ECDSA_VERIFY_INVALID_MESSAGE_DATA_IN_SIZE_ERROR;
        goto End;
    }

    /* if the users Signature pointer is illegal then return an error */
    if (pSignatureIn == NULL){
        err = CC_ECDSA_VERIFY_INVALID_SIGNATURE_IN_PTR_ERROR;
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

    /* Currently there is only one possible domain. This assignment is constant.
     * In the future we may have more than one domain. */
    orderSizeInBits     = pDomain->ordSizeInBits;
    orderSizeInBytes    = CALC_FULL_BYTES(orderSizeInBits);
    orderSizeInWords    = CALC_FULL_32BIT_WORDS(orderSizeInBits);

    if (orderSizeInWords > (CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 1)) {
        err = ECWRST_SCALAR_MULT_INVALID_MOD_ORDER_SIZE_ERROR;
        goto End;
    }


    /* if the user signature size is not equal to 2*OrderSizeInBytes, then return an error */
    if (SignatureSizeBytes != 2*orderSizeInBytes){
        err = CC_ECDSA_VERIFY_INVALID_SIGNATURE_SIZE_ERROR;
        goto End;
    }

    /*  Initialisation of  EcWrstDsaVerify arguments */
    /* Temporary buffers */
    pSignatureR = pWorkingContext;
    pSignatureS = pSignatureR + orderSizeInWords; /* Max lengths of C in whole words */
    pMessRepres = pSignatureS + orderSizeInWords;

    PublKey_ptr = (CCEcpkiPublKey_t *)&pUserPublKey->PublKeyDbBuff;


    // Check shortened cleaning    /* Clean memory  */
    CC_PalMemSetZero(pSignatureR, 2*sizeof(uint32_t)*orderSizeInWords);
    CC_PalMemSetZero(pMessRepres, CC_SM3_RESULT_SIZE_IN_BYTES);

    CC_CommonReverseMemcpy((uint8_t*)pMessRepres,
                           (uint8_t*)(pMessageHash), CC_SM3_RESULT_SIZE_IN_BYTES);

    /* Convert signature data to words array with le order of  words. */
    pSignatureR[orderSizeInWords-1] = 0;
    CC_CommonReverseMemcpy((uint8_t*)pSignatureR, pSignatureIn, orderSizeInBytes);
    pSignatureS[orderSizeInWords-1] = 0;
    CC_CommonReverseMemcpy((uint8_t*)pSignatureS, pSignatureIn + orderSizeInBytes, orderSizeInBytes);

    /*------------------------------*/
    /* Verifying operation          */
    /*------------------------------*/
    err =  EcWrstSm2Verify(PublKey_ptr, pMessRepres, orderSizeInWords, pSignatureR, pSignatureS);

    if (err != CC_OK) {
        err = CC_ECDSA_VERIFY_INCONSISTENT_VERIFY_ERROR;
        goto End;
    }
End:
    /* clear the users context  */
    CC_PalMemSetZero(pWorkingContext, CC_PKA_ECDSA_VERIFY_BUFF_MAX_LENGTH_IN_WORDS);
    return err;
}/* END OF CC_Sm2Verify */




