/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _CC_KDF_DEFS_H
#define _CC_KDF_DEFS_H

#ifdef __cplusplus
extern "C"
{
#endif

/*!
@file
@brief This file contains the CryptoCell Key Derivation definitions.
 */
/*!
 @addtogroup cc_kdf_defs
  @{
*/


/************************ Defines ******************************/

/*! Maximal size of keying data in bytes. */
#define  CC_KDF_MAX_SIZE_OF_KEYING_DATA  2048

/************************ Enums ********************************/
/*! HASH operation modes */
typedef enum
{
    /*! SHA1 mode.*/
    CC_KDF_HASH_SHA1_mode    = 0,
    /*! SHA224 mode.*/
    CC_KDF_HASH_SHA224_mode  = 1,
    /*! SHA256 mode.*/
    CC_KDF_HASH_SHA256_mode  = 2,
    /*! SHA384 mode.*/
    CC_KDF_HASH_SHA384_mode  = 3,
    /*! SHA512 mode.*/
    CC_KDF_HASH_SHA512_mode  = 4,
    /*! Maximal number of HASH modes. */
    CC_KDF_HASH_NumOfModes,
    /*! Reserved.*/
    CC_KDF_HASH_OpModeLast = 0x7FFFFFFF,

}CCKdfHashOpMode_t;

/*! Key derivation modes. */
typedef enum
{
    /*! ASN1 key derivation mode.*/
    CC_KDF_ASN1_DerivMode    = 0,
    /*! Concatenation key derivation mode.*/
    CC_KDF_ConcatDerivMode   = 1,
    /*! X963 key derivation mode.*/
    CC_KDF_X963_DerivMode    = CC_KDF_ConcatDerivMode,
    /*! ISO 18033 KDF1 key derivation mode.*/
    CC_KDF_ISO18033_KDF1_DerivMode = 3,
    /*! ISO 18033 KDF2 key derivation mode.*/
    CC_KDF_ISO18033_KDF2_DerivMode = 4,
    /*! NIST 56Arev3 (Hash KDF) concatenation key derivation mode.*/
    CC_KDF_NIST56A_ConcatDerivMode = 5,
    /*! Maximal number of key derivation modes. */
    CC_KDF_DerivFunc_NumOfModes = 6,
    /*! Reserved.*/
    CC_KDF_DerivFuncModeLast= 0x7FFFFFFF,

}CCKdfDerivFuncMode_t;

/*! Enumerator for the additional information given to the KDF. */
typedef enum
{
    CC_KDF_ALGORITHM_ID     = 0, /*! An identifier (OID), indicating algorithm for which the keying data is used. */
    CC_KDF_PARTY_U_INFO     = 1, /*! Optional data of party U .*/
    CC_KDF_PARTY_V_INFO     = 2, /*! Optional data of party V. */
    CC_KDF_SUPP_PRIV_INFO   = 3, /*! Optional supplied private shared data. */
    CC_KDF_SUPP_PUB_INFO    = 4, /*! Optional supplied public shared data. */

    CC_KDF_MAX_COUNT_OF_ENTRIES,  /*! Maximal allowed number of entries in Other Info structure. */
    /*! Reserved.*/
    CC_KDF_ENTRYS_MAX_VAL  = 0x7FFFFFFF,

}CCKdfOtherInfoEntries_t;

/************************ Typedefs  ****************************/

/*! KDF structure, containing pointers to OtherInfo data entries and sizes.

    The structure contains two arrays: one for data pointers and one for sizes. They are placed according
    to the order given in the ANSI X9.42-2003: Public Key Cryptography for the Financial Services
    Industry: Agreement of Symmetric Keys Using Discrete Logarithm Cryptography standard
    and defined in CCKdfOtherInfoEntries_t enumerator.
    In KDF ASN1 mode this order is mandatory. In other KDF modes, you can insert
    optional OtherInfo simply in one (preferably the first) or in some entries.
    If any data entry is not used, then the pointer value and the size must be set to NULL. */
typedef struct
{
        /*! Pointers to data entries. */
        uint8_t  *dataPointers[CC_KDF_MAX_COUNT_OF_ENTRIES];
        /*! Sizes of data entries. */
        uint32_t  dataSizes[CC_KDF_MAX_COUNT_OF_ENTRIES];
}CCKdfOtherInfo_t;


#ifdef __cplusplus
}
#endif
 /*!
 @}
 */
#endif /* _CC_KDF_DEFS_H */
