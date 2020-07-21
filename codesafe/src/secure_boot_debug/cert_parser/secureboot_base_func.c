/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#define CC_PAL_LOG_CUR_COMPONENT CC_LOG_MASK_SECURE_BOOT

/************* Include Files ****************/

#include "secureboot_stage_defs.h"
#include "secureboot_error.h"
#include "secureboot_defs.h"
#include "cc_certificate_defs.h"
#include "bootimagesverifier_error.h"
#include "rsa_bsv.h"
#include "cc_pal_log.h"
#include "cc_pka_hw_plat_defs.h"


CCError_t CCSbCalcPublicKeyHASH(unsigned long hwBaseAddress,
                                uint32_t *NAndRevNp_ptr,
                                uint32_t *hashResult)
{

        /* error variable */
        CCError_t error = CC_OK;

        if ((NAndRevNp_ptr == NULL) ||
            (hashResult == NULL)) {
                return CC_BOOT_IMG_VERIFIER_INV_INPUT_PARAM;
        }
        error = _BSV_SHA256(hwBaseAddress, (uint8_t*)NAndRevNp_ptr,
                            (BSV_CERT_RSA_KEY_SIZE_IN_WORDS + RSA_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS) * CC_32BIT_WORD_SIZE,
                            hashResult);
        return error;
}

CCError_t CCSbCalcPublicKeyHASHAndCompare(unsigned long hwBaseAddress,
                                          uint32_t *NAndRevNp_ptr,
                                          uint32_t *NHASH_ptr,
                                          uint32_t    HashSize)
{
        /* error variable */
        CCError_t error = CC_OK;

        /* HASH result of the E||N */
        CCHashResult_t LocalHashResult = {0}; // __TRUSTINSOFT_ANALYZER__

/*------------------
    CODE
-------------------*/
        if ((NAndRevNp_ptr == NULL) ||
            (NHASH_ptr == NULL)) {
                return CC_BOOT_IMG_VERIFIER_INV_INPUT_PARAM;
        }

        if (HashSize != sizeof(CCHashResult_t) && HashSize != sizeof(CCHashResult_t) / 2) {
                return CC_BOOT_IMG_VERIFIER_INV_INPUT_PARAM;
        }

        /* calculate the HASH value of N (big endian)|| Np (reversed - little endian) */
        error = CCSbCalcPublicKeyHASH(hwBaseAddress, NAndRevNp_ptr, LocalHashResult);
        if (error != CC_OK) {
                return error;
        }

        /* compare the HASH results */
        error = UTIL_MemCmp((uint8_t *)LocalHashResult, (uint8_t *)NHASH_ptr, HashSize);
        if (error != CC_TRUE) {
                CC_PAL_LOG_ERR("PUB KEY HASH VALIDATION FAILURE\n");
                return CC_BOOT_IMG_VERIFIER_PUB_KEY_HASH_VALIDATION_FAILURE;
        }

        return CC_OK;
} /* End of CCSbCalcPublicKeyHASHAndCompare */



CCError_t CCSbVerifySignature(unsigned long hwBaseAddress,
                              uint32_t *pData,
                              CCSbNParams_t *pNParams,
                              CCSbSignature_t *pSignature,
                              uint32_t sizeOfData,
                              CCSbSignAlg_t sigAlg,
                              uint32_t *pWorkspace,
                              size_t workspaceSize)
{

        /* error variable */
        CCError_t error = CC_OK;

        /* a HASH result variable */
        CCHashResult_t HashResult;

/*------------------
    CODE
-------------------*/
        if ((pData == NULL) ||
            (pNParams == NULL) ||
            (pSignature == NULL) ||
            (sizeOfData == 0) ||
            ((sigAlg == RSA_PSS_3072) && (BSV_CERT_RSA_KEY_SIZE_IN_BITS != 3072)) ||
            ((sigAlg == RSA_PSS_2048) && (BSV_CERT_RSA_KEY_SIZE_IN_BITS != 2048))) {
                CC_PAL_LOG_ERR("CC_BOOT_IMG_VERIFIER_INV_INPUT_PARAM\n");
                return CC_BOOT_IMG_VERIFIER_INV_INPUT_PARAM;
        }

        /* Calculate HASH on the certificate */
        /*---------------------------------- */
        /* calc the  HASH according to the length minus the signature struct size (N,Np & signature)*/
        error = _BSV_SHA256(hwBaseAddress, (uint8_t*)pData,
                                 sizeOfData,
                                 HashResult);
        if (error != CC_OK) {
                CC_PAL_LOG_ERR("Failed SBROM_CryptoHash 0x%x\n", (unsigned int)error);
                return error;
        }

        /* Reverse the N and Np to be little endian arrays for the PKA usage */
        /* NOTICE: Must be after certificate hash is calculated and
           certificate public key Hash is verified */
        UTIL_ReverseMemCopy((uint8_t *)pNParams->N, (uint8_t *)pNParams->N, BSV_CERT_RSA_KEY_SIZE_IN_BYTES);
        UTIL_ReverseMemCopy((uint8_t *)pNParams->Np, (uint8_t *)pNParams->Np, RSA_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_BYTES);
        /* Verify the RSA signature */
        _RSA_PSS_Verify(error,
                        hwBaseAddress,
                        HashResult,
                        pNParams->N,
                        pNParams->Np,
                        pSignature->sig,
                        pWorkspace,
                        workspaceSize);

        /* on failure exit with an error code */
        if (error != CC_OK) {
                CC_PAL_LOG_ERR("RSA sig verification failed 0x%x\n", (unsigned int)error);
                return CC_BOOT_IMG_VERIFIER_RSA_SIG_VERIFICATION_FAILED;
        }

        return CC_OK;
} /* End of CCSbVerifySignature */

