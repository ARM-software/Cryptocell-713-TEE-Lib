/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

/*!
 @file
 @brief This file contains all the type definitions that are used for the CryptoCell ECPKI APIs.
 */


 /*!
  @addtogroup cc_ecpki_types
  @{
	*/

#ifndef _CC_ECPKI_TYPES_COMMON_H
#define _CC_ECPKI_TYPES_COMMON_H


#include "cc_pal_types_plat.h"
#include "cc_hash_defs.h"
#include "cc_pka_defs_hw.h"



#ifdef __cplusplus
extern "C"
{
#endif

/************************ Defines ******************************/
/*! The size of the internal buffer in words. */
#define CC_PKA_DOMAIN_LLF_BUFF_SIZE_IN_WORDS (10 + 3*CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS)

/**************************************************************************************
 *                Enumerators
 ***************************************************************************************/

/*------------------------------------------------------------------*/
/*! @brief EC domain identifiers.

   For more information, see <em>Standards for Efficient Cryptography Group (SECG):
   SEC2 Recommended Elliptic Curve Domain Parameters, Version 1.0</em>.
*/

typedef enum
{
    /* For prime field */
    CC_ECPKI_DomainID_secp192k1,   /*!< EC secp192k1. */
    CC_ECPKI_DomainID_secp192r1,   /*!< EC secp192r1. */
    CC_ECPKI_DomainID_secp224k1,   /*!< EC secp224k1. */
    CC_ECPKI_DomainID_secp224r1,   /*!< EC secp224r1. */
    CC_ECPKI_DomainID_secp256k1,   /*!< EC secp256k1. */
    CC_ECPKI_DomainID_secp256r1,   /*!< EC secp256r1. */
    CC_ECPKI_DomainID_secp384r1,   /*!< EC secp384r1. */
    CC_ECPKI_DomainID_secp521r1,   /*!< EC secp521r1. */
    CC_ECPKI_DomainID_bp256r1,     /*!< EC bp256r1. */

    CC_ECPKI_DomainID_Builded,     /*!< User given, not identified. */
#ifndef CC_IOT
    CC_ECPKI_DomainID_sm2,         /*!< SM2 domain.*/
#endif
    CC_ECPKI_DomainID_OffMode,     /*!< Reserved.*/

    CC_ECPKI_DomainIDLast      = 0x7FFFFFFF, /*!< Reserved.*/

}CCEcpkiDomainID_t;

/*------------------------------------------------------------------*/
/*!
  @brief Hash operation mode.

  Defines hash modes according to <em>IEEE 1363-2000: IEEE Standard for
  Standard Specifications for Public-Key Cryptography</em>.
 */
typedef enum
{
    CC_ECPKI_HASH_SHA1_mode    = 0,     /*!< The message data will be hashed with SHA-1. */
    CC_ECPKI_HASH_SHA224_mode  = 1,     /*!< The message data will be hashed with SHA-224. */
    CC_ECPKI_HASH_SHA256_mode  = 2,     /*!< The message data will be hashed with SHA-256. */
    CC_ECPKI_HASH_SHA384_mode  = 3,     /*!< The message data will be hashed with SHA-384. */
    CC_ECPKI_HASH_SHA512_mode  = 4,     /*!< The message data will be hashed with SHA-512. */

    CC_ECPKI_AFTER_HASH_SHA1_mode    = 5,   /*!< The message data is a digest of SHA-1 and will not be hashed. */
    CC_ECPKI_AFTER_HASH_SHA224_mode  = 6,   /*!< The message data is a digest of SHA-224 and will not be hashed. */
    CC_ECPKI_AFTER_HASH_SHA256_mode  = 7,   /*!< The message data is a digest of SHA-256 and will not be hashed. */
    CC_ECPKI_AFTER_HASH_SHA384_mode  = 8,   /*!< The message data is a digest of SHA-384 and will not be hashed. */
    CC_ECPKI_AFTER_HASH_SHA512_mode  = 9,   /*!< The message data is a digest of SHA-512 and will not be hashed. */


    CC_ECPKI_HASH_NumOfModes,   /*!< The maximal number of hash modes. */
    CC_ECPKI_HASH_OpModeLast        = 0x7FFFFFFF, /*!< Reserved. */

}CCEcpkiHashOpMode_t;

/*---------------------------------------------------*/
/*! EC point-compression identifiers.
*/
typedef enum
{
    CC_EC_PointCompressed     = 2,  /*!< A compressed point. */
    CC_EC_PointUncompressed   = 4,  /*!< An uncompressed point. */
    CC_EC_PointContWrong      = 5,  /*!< An incorrect point-control value. */
    CC_EC_PointHybrid         = 6,  /*!< A hybrid point. */

    CC_EC_PointCompresOffMode = 8,  /*!< Reserved. */

    CC_ECPKI_PointCompressionLast= 0x7FFFFFFF,  /*!< Reserved. */

}CCEcpkiPointCompression_t;

/*----------------------------------------------------*/
/*! EC key checks. */
typedef enum {
    CheckPointersAndSizesOnly = 0,   /*!< Check only preliminary input parameters. */
    ECpublKeyPartlyCheck      = 1,   /*!< Check preliminary input parameters and verify that the EC public-key point is on the curve. */
    ECpublKeyFullCheck        = 2,   /*!< Check preliminary input parameters, verify that the EC public-key point is on the curve,
                                          and verify that \c EC_GeneratorOrder*PubKey = 0 */

    PublKeyChecingOffMode,          /*! Reserved. */
    EC_PublKeyCheckModeLast  = 0x7FFFFFFF,  /*! Reserved. */
}ECPublKeyCheckMode_t;
/*----------------------------------------------------*/
/*! SW SCA protection type. */
typedef enum {
    SCAP_Inactive,  /*! SCA protection inactive.*/
    SCAP_Active,    /*! SCA protection active.*/
    SCAP_OFF_MODE,  /*! Reserved. */
    SCAP_LAST = 0x7FFFFFFF  /*! Reserved. */
}CCEcpkiScaProtection_t;


/**************************************************************************************
 *               EC Domain structure definition
 ***************************************************************************************/

/*!
 @brief The structure containing the EC domain parameters in little-endian form.

 EC equation: \c Y^2 = \c X^3 + \c A*X + \c B over prime field \p GFp.
 */
typedef  struct {

    uint32_t    ecP [CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS] /*!< EC modulus: P. */;
    uint32_t    ecA [CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS] /*!< EC equation parameter A. */;
    uint32_t    ecB [CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS] /*!< EC equation parameter B. */;
    uint32_t    ecR [CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 1] /*!< Order of generator. */;
    uint32_t    ecGx [CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS] /*!< EC cofactor EC_Cofactor_K.
        The coordinates of the EC base point generator in projective form. */;
    uint32_t    ecGy [CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS] /*!< EC cofactor EC_Cofactor_K.
        The coordinates of the EC base point generator in projective form. */;
    uint32_t    ecH /*!< EC cofactor EC_Cofactor_K.
        The coordinates of the EC base point generator in projective form. */;
    uint32_t    llfBuff[CC_PKA_DOMAIN_LLF_BUFF_SIZE_IN_WORDS] /*!< Specific fields that are used by the low-level functions.*/;
    uint32_t    modSizeInBits /*!< The size of fields in bits. */;
    uint32_t    ordSizeInBits /*!< The size of the order in bits. */;
    uint32_t    barrTagSizeInWords /*!< The size of each inserted Barret tag in words. 0 if not inserted.*/;
    CCEcpkiDomainID_t   DomainID /*!< The EC Domain identifier.*/;
    int8_t      name[20] /*!< Internal buffer. */;
}CCEcpkiDomain_t;

/*! The structure containing the public key in affine coordinates.*/
typedef  struct
{
    uint32_t x[CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS] /*!< The X coordinate of the public key.*/;
    uint32_t y[CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS] /*!< The Y coordinate of the public key.*/;
    CCEcpkiDomain_t  domain /*!< The EC Domain.*/;
    uint32_t pointType /*!< The point type.*/;
} CCEcpkiPublKey_t;

/*!
@brief The user structure prototype of the EC public key.

This structure must be saved by the user. It is used as input to ECC functions,
for example, CC_EcdsaVerify().
*/
typedef struct   CCEcpkiUserPublKey_t
{
    uint32_t    valid_tag /*!< The validation tag.*/;
    uint32_t    PublKeyDbBuff[(sizeof(CCEcpkiPublKey_t)+3)/4] /*!< The data of the public key. */;

} CCEcpkiUserPublKey_t;


/* --------------------------------------------------------------------- */
/* .................. The private key structures definitions ........... */
/* --------------------------------------------------------------------- */

/*! The structure containing the data of the private key. */
typedef  struct
{
    uint32_t  PrivKey[CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 1] /*!< The data of the private key. */;
    CCEcpkiDomain_t  domain /*!< The EC domain. */;
    CCEcpkiScaProtection_t  scaProtection /*!< The SCA protection mode. */;

}CCEcpkiPrivKey_t;

/*!
 @brief The user structure prototype of the EC private key.

 This structure must be saved by the user. It is used as input to ECC functions,
 for example, CC_EcdsaSign().
 */
typedef struct   CCEcpkiUserPrivKey_t
{

    uint32_t    valid_tag /*!< The validation tag. */;
    uint32_t    PrivKeyDbBuff[(sizeof(CCEcpkiPrivKey_t)+3)/4] /*!< The data of the private key. */;
}  CCEcpkiUserPrivKey_t;

/*! The type of the ECDH temporary data. */
typedef struct CCEcdhTempData_t
{
    uint32_t ccEcdhIntBuff[CC_PKA_ECDH_BUFF_MAX_LENGTH_IN_WORDS] /*!< Temporary buffers. */;
}CCEcdhTempData_t;

/*! EC build temporary data. */
typedef struct CCEcpkiBuildTempData_t
{
    uint32_t  ccBuildTmpIntBuff[CC_PKA_ECPKI_BUILD_TMP_BUFF_MAX_LENGTH_IN_WORDS] /*!< Temporary buffers. */;
}CCEcpkiBuildTempData_t;


/****************************************************************************/

/* --------------------------------------------------------------------- */
/*                ECDSA Verifying context structure                 */
/* --------------------------------------------------------------------- */

/*! The internal buffer used in the verification process. */
typedef uint32_t CCEcdsaVerifyIntBuff_t[CC_PKA_ECDSA_VERIFY_BUFF_MAX_LENGTH_IN_WORDS];

/*! The context definition for verification operation. */
typedef  struct
{
    CCEcpkiUserPublKey_t        ECDSA_SignerPublKey /*!< The data of the public key. */;
	/*! The hash context. */
    CCHashUserContext_t         hashUserCtxBuff ;
	/*! The hash result. */
    CCHashResultBuf_t           hashResult ;
	/*! The size of the hash result in words. */
    uint32_t                    hashResultSizeWords ;
	 /*! The hash mode. */
    CCEcpkiHashOpMode_t         hashMode;
	/*! Internal buffer. */
    CCEcdsaVerifyIntBuff_t      ccEcdsaVerIntBuff ;
}EcdsaVerifyContext_t;

/* --------------------------------------------------------------------- */
/*                ECDSA Verifying User context database             */
/* --------------------------------------------------------------------- */
/*!
 @brief The context definition of the user for the verification operation.

 The context saves the state of the operation, and must be saved by the user
 until the end of the API flow.
 */
typedef struct  CCEcdsaVerifyUserContext_t
{
    /*! The data of the verification process. */
    uint32_t    context_buff[(sizeof(EcdsaVerifyContext_t)+3)/4];
    /*! The validation tag. */
    uint32_t    valid_tag;
}CCEcdsaVerifyUserContext_t;


/* --------------------------------------------------------------------- */
/* .................. key generation temp buffer   ........... */
/* --------------------------------------------------------------------- */
/*! The temporary data type of the ECPKI KG. */
typedef struct CCEcpkiKgTempData_t
{
    uint32_t ccKGIntBuff[CC_PKA_KG_BUFF_MAX_LENGTH_IN_WORDS] /*!< Internal buffer. */;
}CCEcpkiKgTempData_t;

/*! The temporary data definition of the ECIES. */
typedef struct CCEciesTempData_t {
	/*! The data of the private key. */
    CCEcpkiUserPrivKey_t   PrivKey ;
	/*! The data of the public key. */
    CCEcpkiUserPublKey_t   PublKey ;
        /*! Internal buffer. */
    uint32_t  zz[3*CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 1];
    union {
        CCEcpkiBuildTempData_t buildTempbuff;
        CCEcpkiKgTempData_t    KgTempBuff;
        CCEcdhTempData_t       DhTempBuff;
    } tmp /*!< Internal buffers. */;

}CCEciesTempData_t;


#ifdef __cplusplus
}
#endif

 /*!
 @}
 */
 #endif
