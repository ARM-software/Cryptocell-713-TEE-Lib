/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

/*!
@file
@brief This file contains all the enums and definitions
that are used for the CryptoCell DES APIs, as well as the APIs themselves.

DES is a block cipher, i.e. it processes data in multiples of block size (8 bytes). DES data can be processed in one of two modes of operation:

<ul><li> Integrated operation - Processes all data in a single function call. This flow is applicable when all data is available prior to the
	 cryptographic operation.</li>
<li> Block operation - Processes a subset of the data buffers, and is called multiple times in a sequence. This flow is applicable when the next data
     buffer becomes available only during/after processing of the current data buffer.</li></ul>

The following is a typical DES Block operation flow:
<ol><li> ::CC_DesInit - Initializes the CryptoCell DES machine by setting the context pointer that is used for the entire DES operation.</li>
<li> ::CC_DesBlock - Performs a DES operation on a block of data allocated by the user. This function stores the relevant block information so that the user can operate on the next block by calling CC_DesBlock again. It may be called as many times as required, until block n.</li>
<li> ::CC_DesFree - This function releases the context data.</li></ol>

\note The input and output data buffers may point to the same memory, or they may be completely disjoint. However, partially overlapping input and output data returns an error.\par
\note In case FIPS certification mode is set to ON, illegal keys for TDEA (as defined in NIST Special Publication 800-67: Recommendation for the Triple Data Encryption
      Algorithm (TDEA) Block Cipher) are not allowed. \par
\note In case FIPS certification mode is set to ON, if the input data size is bigger than 2^20 bytes than TDEA with 2 keys is not allowed (only 3 keys).
*/

 /*!
 @addtogroup cc_des_apis
 @{
*/

#ifndef _CC_DES_H
#define _CC_DES_H

#include "cc_pal_types.h"
#include "cc_error.h"



#ifdef __cplusplus
extern "C"
{
#endif


/************************ Defines ******************************/
/*! The size of the context prototype of the user (see CCDesUserContext_t) in words. */
/* In order to allow contiguous context the user context is doubled + 3 words for management */
#define CC_DES_USER_CTX_SIZE_IN_WORDS 131


/*! The size of the IV or counter buffer (see ::CCDesIv_t) in words. */
#define CC_DES_IV_SIZE_IN_WORDS 2
/*! The size of the IV or counter buffer (see ::CCDesIv_t) in bytes. */
#define CC_DES_IV_SIZE_IN_BYTES ( CC_DES_IV_SIZE_IN_WORDS * sizeof(uint32_t) )

/*! The maximum number of Keys supported by DES. */
#define CC_DES_MAX_NUMBER_OF_KEYS 3

/*! The key size in words on the DES machine in words (see ::CCDesKey32bit_t). */
#define CC_DES_KEY_SIZE_IN_WORDS 2
/*! The key size in words on the DES machine in bytes (see ::CCDesKey_t). */
#define CC_DES_KEY_SIZE_IN_BYTES ( CC_DES_KEY_SIZE_IN_WORDS * sizeof(uint32_t) )

/*! The DES block size in bytes. */
#define CC_DES_BLOCK_SIZE_IN_BYTES 8

/*! The DES block size in words. */
#define CC_DES_BLOCK_SIZE_IN_WORDS 2

/************************ Enums ********************************/

/*!
The number of keys supported on the DES machine.
*/
typedef enum
{
   CC_DES_1_KeyInUse  = 1,    /*!< Single key (56bit). */
   CC_DES_2_KeysInUse = 2,    /*!< Two keys (112bit). */
   CC_DES_3_KeysInUse = 3,    /*!< Three keys (168bit). */

   CC_DES_NumOfKeysOptions,   /*!< Reserved. */

   CC_DES_NumOfKeysLast= 0x7FFFFFFF, /*!< Reserved. */

}CCDesNumOfKeys_t;

/*!
Encrypt or Decrypt operation mode.
*/
typedef enum
{
    CC_DES_Encrypt = 0,    /*!< Encrypt mode. */
    CC_DES_Decrypt = 1,    /*!< Decrypt mode. */

    CC_DES_EncryptNumOfOptions, /*!< Reserved. */

    CC_DES_EncryptModeLast = 0x7FFFFFFF, /*!< Reserved. */

}CCDesEncryptMode_t;

/*!
DES operation mode.
*/
typedef enum
{
    CC_DES_ECB_mode = 0,    /*!< ECB mode. */
    CC_DES_CBC_mode = 1,    /*!< CBC mode. */

    CC_DES_NumOfModes, /*!< Reserved. */

    CC_DES_OperationModeLast = 0x7FFFFFFF, /*!< Reserved. */

}CCDesOperationMode_t;

/************************ Typedefs  ****************************/

/*! The IV buffer definition. */
typedef uint8_t CCDesIv_t[CC_DES_IV_SIZE_IN_BYTES];

/*! Defining the KEY argument - contains maximum of three keys, size expressed in bytes.  */
typedef struct CCDesKey_t
{
   /* The key variables */
   uint8_t key1[CC_DES_KEY_SIZE_IN_BYTES]; /*!< buffer for the first key.*/
   uint8_t key2[CC_DES_KEY_SIZE_IN_BYTES]; /*!< buffer for the second key.*/
   uint8_t key3[CC_DES_KEY_SIZE_IN_BYTES]; /*!< buffer for the third key.*/

}CCDesKey_t;

/************************ Structs  ******************************/

/*! Defines the KEY argument - contains maximum of three keys, size expressed in words. */
typedef struct
{
   /* The key variables */
   uint32_t key1[CC_DES_KEY_SIZE_IN_WORDS]; /*!< buffer for the first key.*/
   uint32_t key2[CC_DES_KEY_SIZE_IN_WORDS]; /*!< buffer for the second key.*/
   uint32_t key3[CC_DES_KEY_SIZE_IN_WORDS]; /*!< buffer for the third key.*/

}CCDesKey32bit_t;

/************************ Structs  ******************************/


/*! Context prototype of the user - the argument type that is passed by the user
   to the APIs that are called. */
typedef struct
{
   uint32_t buff[CC_DES_USER_CTX_SIZE_IN_WORDS
   ]; /*!< User context.*/
}CCDesUserContext_t;

/************************ Public Variables **********************/


/************************ Public Functions **********************/

/*!
@brief This function is used to initialize the DES machine.
       To operate the DES machine, this should be the first function called.

@return \c CC_OK on success.
@return A non-zero value from cc_des_error.h on failure.
*/
CIMPORT_C CCError_t  CC_DesInit(
                            CCDesUserContext_t    *ContextID_ptr,         /*!< [in]  Pointer to the DES context buffer allocated by the user, which is used for the DES machine operation. */
                            CCDesIv_t            IV_ptr,                 /*!< [in]  The IV buffer. In ECB mode this parameter is not used. In CBC this parameter should contain the IV values. */
                            CCDesKey_t           *Key_ptr,               /*!< [in]  Pointer to the key buffer of the user. */
                            CCDesNumOfKeys_t     NumOfKeys,              /*!< [in]  The number of keys used: 1, 2 or 3 (defined by the enum).
                                                                                        One key implies DES encryption/decryption, two or three keys imply triple-DES. */
                            CCDesEncryptMode_t   EncryptDecryptFlag,     /*!< [in]  A flag that determines whether the DES should perform an Encrypt operation (0) or a Decrypt operation (1). */
                            CCDesOperationMode_t OperationMode           /*!< [in]  The operation mode: ECB or CBC. */
);


/*!
@brief This function is used to process a block on the DES machine.
        This function should be called after the CC_DesInit function was called.

@return \c CC_OK on success.
@return A non-zero value from cc_des_error.h on failure.
*/
 CIMPORT_C CCError_t  CC_DesBlock(
                            CCDesUserContext_t   *ContextID_ptr,         /*!< [in] Pointer to the DES context buffer allocated by the user, which is used for the DES machine operation.
                                                                                        This should be the same context used on the previous call of this session. */
                            uint8_t                 *DataIn_ptr,            /*!< [in]  The pointer to input data.
                                                                                        The size of the scatter/gather list representing the data buffer is limited to 128 entries,
                                                                                        and the size of each entry is limited to 64KB (fragments larger than 64KB are broken into fragments <= 64KB). */
                            size_t                  DataInSize,             /*!< [in]  The size of the input data. Must be a multiple of the DES block size, 8 bytes. */
                            uint8_t                 *DataOut_ptr            /*!< [out] The pointer to the output data.
                                                                                        The size of the scatter/gather list representing the data buffer is limited to 128 entries,
                                                                                        and the size of each entry is limited to 64KB (fragments larger than 64KB are broken into fragments <= 64KB).*/
);


/*!
@brief This function is used to end the DES processing session.
       It is the last function called for the DES process.

@return \c CC_OK on success.
@return A non-zero value from cc_des_error.h on failure.
*/
CIMPORT_C CCError_t  CC_DesFree(
                            CCDesUserContext_t   *ContextID_ptr         /*!< [in]  Pointer to the DES context buffer allocated by the user that is used for the DES machine operation.
                                                                                        This should be the same context that was used on the previous call of this session. */
);


/*!
@brief This function is used to operate the DES machine in one integrated operation.

@return CC_OK on success.
@return A non-zero value from cc_des_error.h on failure.
*/
 CIMPORT_C CCError_t  CC_Des(
                CCDesIv_t             IV_ptr,                 /*!< [in]  The IV buffer in CBC mode. In ECB mode this parameter is not used. */
                CCDesKey_t           *Key_ptr,                /*!< [in]  Pointer to the user's key buffer. */
                CCDesNumOfKeys_t      NumOfKeys,              /*!< [in]  The number of keys used: single (56bit), double (112bit) or triple (168bit). */
                CCDesEncryptMode_t    EncryptDecryptFlag,     /*!< [in]  A flag that determines if the DES should perform an Encrypt operation (0) or a Decrypt operation (1). */
                CCDesOperationMode_t  OperationMode,          /*!< [in]  The operation mode: ECB or CBC. */
                uint8_t                  *DataIn_ptr,             /*!< [in]  The pointer to the input data.
                                                                                The size of the scatter/gather list representing the data buffer is limited to 128 entries,
                                                                                and the size of each entry is limited to 64KB (fragments larger than 64KB are broken into fragments <= 64KB). */
                size_t                  DataInSize,             /*!< [in]  The size of the input data. Must be a multiple of the DES block size, 8 bytes. */
                uint8_t                  *DataOut_ptr             /*!< [out] The pointer to the output data.
                                                                                The size of the scatter/gather list representing the data buffer is limited to 128 entries,
                                                                                and the size of each entry is limited to 64KB (fragments larger than 64KB are broken into fragments <= 64KB). */
);

#ifdef __cplusplus
}
#endif
/*!
 @}
 */
#endif
