/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


#ifndef RSA_BSV_H
#define RSA_BSV_H

/*
 * All the includes that are needed for code using this module to
 * compile correctly should be #included here.
 */
#ifdef __cplusplus
extern "C"
{
#endif

#include "cc_pka_hw_plat_defs.h"
#include "cc_pal_types.h"
#include "secureboot_error.h"



/************************ Defines ******************************/

#define CC_BOOT_RSA_VERIFIER_ALG_FAILURE    (CC_SB_RSA_BASE_ERROR + 0x00000001)
#define CC_BOOT_RSA_VERIFIER_CMP_FAILURE    (CC_SB_RSA_BASE_ERROR + 0x00000002)
#define CC_BOOT_RSA_VERIFIER_INVALID_PARAM_FAILURE    (CC_SB_RSA_BASE_ERROR + 0x00000003)

/* the modulus size ion bits */
#define RSA_EXP_SIZE_WORDS 			1


/* PKA max count of SRAM registers: */
#define RSA_HW_PKI_PKA_MAX_COUNT_OF_PHYS_MEM_REGS  PKA_MAX_COUNT_OF_PHYS_MEM_REGS /*32*/
/* PKA required count of SRAM registers: */
#define RSA_PKA_REQUIRED_COUNT_OF_PHYS_MEM_REGS     7

/* maximal size of extended register in "big PKA words" and in 32-bit words:  *
   the size defined according to RSA as more large, and used to define some   *
*  auxiliary buffers sizes      					      */
#define RSA_PKA_MAX_REGISTER_SIZE_IN_PKA_WORDS \
        ((BSV_CERT_RSA_KEY_SIZE_IN_BITS + RSA_PKA_EXTRA_BITS + RSA_PKA_BIG_WORD_SIZE_IN_BITS - 1)/RSA_PKA_BIG_WORD_SIZE_IN_BITS + 1)
#define RSA_PKA_MAX_REGISTER_SIZE_WORDS  (RSA_PKA_MAX_REGISTER_SIZE_IN_PKA_WORDS*(RSA_PKA_BIG_WORD_SIZE_IN_BITS/CC_BITS_IN_32BIT_WORD))
#define RSA_PKA_MAX_REGISTER_SIZE_BITS   (RSA_PKA_MAX_REGISTER_SIZE_WORDS * CC_BITS_IN_32BIT_WORD)

/* size of Barrett modulus tag NP, used in PKA algorithms */
#define RSA_HW_PKI_PKA_BARRETT_MOD_TAG_SIZE_IN_BITS    (RSA_PKA_BIG_WORD_SIZE_IN_BITS + RSA_PKA_EXTRA_BITS)
#define RSA_HW_PKI_PKA_BARRETT_MOD_TAG_SIZE_IN_BYTES   (CALC_FULL_BYTES(RSA_HW_PKI_PKA_BARRETT_MOD_TAG_SIZE_IN_BITS))
#define RSA_HW_PKI_PKA_BARRETT_MOD_TAG_SIZE_IN_WORDS   (CALC_FULL_32BIT_WORDS(RSA_HW_PKI_PKA_BARRETT_MOD_TAG_SIZE_IN_BITS))

/* the public exponent */
#define RSA_PUBL_EXP_SIZE_IN_BITS  17UL
#define RSA_PUBL_EXP_SIZE_IN_BYTES (CALC_FULL_BYTES(RSA_PUBL_EXP_SIZE_IN_BITS))
#ifndef BIG__ENDIAN
#define RSA_EXP_VAL          0x00010001UL
#else
#define RSA_EXP_VAL          0x01000100UL
#endif

/* RSA PSS verify definitions */
#define RSA_HASH_LENGTH  32 /*SHA256*/
#define RSA_PSS_SALT_LENGTH  32
#define RSA_PSS_PAD1_LEN     8

/* RSA Encrypt definitions */
#define RSA_ENCR_RND_PS_SIZE_BYTES   8
#define RSA_ENCR_DATA_IN_SIZE_BYTES  16

#define RSA_PKCS1_VER21   1

/*! Public key data structure. */
typedef struct {
    uint32_t N[BSV_CERT_RSA_KEY_SIZE_IN_WORDS];                 /*!< N public key, big endian representation. */
    uint32_t Np[RSA_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS];    /*!< Np (Barrett n' value). */
}CCSbNParams_t;


/*! Defines the workspace structure used by RsaCalcExponentBE. */
typedef struct {
    CCSbNParams_t pNparams;
    uint32_t pDataIn[BSV_CERT_RSA_KEY_SIZE_IN_WORDS];
}BsvRsaExponentWorkspace_t;

/*! Defines the workspace structure used by BsvRsaPssDecode. */
typedef struct {
    uint32_t dbMask[BSV_CERT_RSA_KEY_SIZE_IN_WORDS];  /*!< The buffer holding the digest of SHA256. */
}BsvPssDecodeWorkspace_t;

typedef struct {
    uint32_t ED[BSV_CERT_RSA_KEY_SIZE_IN_WORDS+1];
    BsvPssDecodeWorkspace_t pssDecode;
}BsvPssVerifyIntWorkspace_t;

/*! Defines the workspace structure used by CC_BsvRsaPssVerify.
 * NOTE: that fields order must be the same as in BsvPssVerifyIntWorkspace_t
 * since for certificate verification using  BsvRsaPssVerify() */
typedef struct {
    BsvPssVerifyIntWorkspace_t pssVerWs;
    BsvRsaExponentWorkspace_t rsaExponentWs;
}BsvPssVerifyWorkspace_t;




#ifdef __cplusplus
}
#endif

#endif



