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

#ifndef _CC_ECPKI_TYPES_H
#define _CC_ECPKI_TYPES_H


#include "cc_bitops.h"
#include "cc_pal_types_plat.h"
#include "cc_hash_defs.h"
#include "cc_pka_defs_hw.h"
#include "cc_pal_compiler.h"
#include "cc_ecpki_types_common.h"

#ifdef __cplusplus
extern "C"
{
#endif

/**************************************************************************************
 *               EC  point structures definitions
 ***************************************************************************************/

/*! The structure containing the EC point in affine coordinates
   and little endian form. */
typedef  struct
{	/*! The X coordinate of the point. */
    uint32_t x[CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS] ;
	/*! The Y coordinate of the point. */
    uint32_t y[CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS] ;

}CCEcpkiPointAffine_t;


/**************************************************************************
 *                CryptoCell ECDSA context structures
 **************************************************************************/

/* --------------------------------------------------------------------- */
/*                CryptoCell ECDSA Signing context structure                   */
/* --------------------------------------------------------------------- */

/*! The internal buffer used in the signing process. */
typedef uint32_t CCEcdsaSignIntBuff_t[CC_PKA_ECDSA_SIGN_BUFF_MAX_LENGTH_IN_WORDS];

/*! The context definition for the signing operation. */
typedef  struct
{
    CCEcpkiUserPrivKey_t     ECDSA_SignerPrivKey /*!< The data of the private key. */;
	/*! The hash context. */
    CCHashUserContext_t      hashUserCtxBuff ;
	/*! The hash result buffer. */
    CCHashResultBuf_t        hashResult ;
	/*! The size of the hash result in words. */
    uint32_t                 hashResultSizeWords ;
	/*! The hash mode. */
    CCEcpkiHashOpMode_t  hashMode ;
	/*! Internal buffer. */
    CCEcdsaSignIntBuff_t     ecdsaSignIntBuff ;
}EcdsaSignContext_t;


/* --------------------------------------------------------------------- */
/*                ECDSA  Signing User context database              */
/* --------------------------------------------------------------------- */
/*!
 @brief The context definition of the user for the signing operation.

 This context saves the state of the operation, and must be saved by the user
 until the end of the API flow.
 */
typedef struct  CCEcdsaSignUserContext_t
{
	/*! The data of the signing process. */
    uint32_t  context_buff [(sizeof(EcdsaSignContext_t)+3)/4] ;
	/*! The validation tag. */
    uint32_t  valid_tag ;
} CCEcdsaSignUserContext_t;



/* --------------------------------------------------------------------- */
/* .................. defines for FIPS      ........... */
/* --------------------------------------------------------------------- */

/*! The order length for FIPS ECC tests. */
#define CC_ECPKI_FIPS_ORDER_LENGTH (256/CC_BITS_IN_BYTE)  // the order of secp256r1 in bytes

/*! ECDSA KAT data structures for FIPS certification.
    The ECDSA KAT tests are defined for domain 256r1.     */
typedef struct CCEcdsaFipsKatContext_t{
    union {
        struct {
            CCEcpkiUserPrivKey_t    PrivKey;
            CCEcdsaSignUserContext_t    signCtx;
        }userSignData /*! The data of the private key. */;
        /*! The data of the public key. */
        struct {
            CCEcpkiUserPublKey_t    PublKey;
            union {
                CCEcdsaVerifyUserContext_t  verifyCtx;
                CCEcpkiBuildTempData_t  tempData;
            }buildOrVerify;
        }userVerifyData;
    }keyContextData /*! The data of the key. */;
    /*! Internal buffer. */
    uint8_t         signBuff[2*CC_ECPKI_FIPS_ORDER_LENGTH];
}CCEcdsaFipsKatContext_t;

/*! ECDH KAT data structures for FIPS certification. */
typedef struct CCEcdhFipsKatContext_t{
	/*! The data of the public key. */
    CCEcpkiUserPublKey_t  pubKey ;
	/*! The data of the private key. */
    CCEcpkiUserPrivKey_t  privKey ;
    union {
        CCEcpkiBuildTempData_t  ecpkiTempData;
        CCEcdhTempData_t      ecdhTempBuff;
    }tmpData /*! Internal buffers. */;

    uint8_t           secretBuff[CC_ECPKI_FIPS_ORDER_LENGTH] /*! The buffer for the secret key. */;
}CCEcdhFipsKatContext_t;

/*! ECPKI data structures for FIPS certification. */
typedef struct CCEcpkiKgFipsContext_t
{
    union {
        CCEcdsaSignUserContext_t    signCtx;
        CCEcdsaVerifyUserContext_t  verifyCtx;
    }operationCtx /*!< Signing and verification data. */;

    uint32_t    signBuff[2*CC_ECPKI_ORDER_MAX_LENGTH_IN_WORDS] /*!< Internal buffer. */;
}CCEcpkiKgFipsContext_t;
#ifdef __cplusplus
}
#endif
/*!
 @}
 */
#endif

