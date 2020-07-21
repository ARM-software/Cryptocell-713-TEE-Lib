/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


#ifndef _CC_AESGCM_H
#define _CC_AESGCM_H

#include "cc_aes.h"
#include "cc_pal_types.h"
#include "cc_error.h"

#include "cc_aes_defs.h"
#include "cc_aes_defs_proj.h"
#include "cc_aes_error.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*!
@file
@brief This file contains all the enums and definitions that are used for the CryptoCell AES-GCM APIs, as well as the APIs themselves.
*/

/*!
 @addtogroup cc_aes_gcm
 @{
     */

/************************ Defines ******************************/

/* In order to allow contiguous context the user context is doubled + 3 words for management */
#define CC_AESGCM_USER_CTX_SIZE_IN_WORDS 133 /*!< AES-GCM context size expressed in words.*/

/* key and key buffer sizes definitions */

/*! AES-GCM key size in words. */
#define CC_AESGCM_KEY_SIZE_WORDS           8
/*! AES-GCM Tag size: 4 bytes. */
#define CC_AESGCM_TAG_SIZE_4_BYTES          4
/*! AES-GCM Tag size: 8 bytes. */
#define CC_AESGCM_TAG_SIZE_8_BYTES          8
/*! AES-GCM Tag size: 12 bytes. */
#define CC_AESGCM_TAG_SIZE_12_BYTES         12
/*! AES-GCM Tag size: 13 bytes. */
#define CC_AESGCM_TAG_SIZE_13_BYTES         13
/*! AES-GCM Tag size: 14 bytes. */
#define CC_AESGCM_TAG_SIZE_14_BYTES         14
/*! AES-GCM Tag size: 15 bytes. */
#define CC_AESGCM_TAG_SIZE_15_BYTES         15
/*! AES-GCM Tag size: 16 bytes. */
#define CC_AESGCM_TAG_SIZE_16_BYTES         16
/*! AES-GCM Tag minimal size in bytes. */
#define CC_AESGCM_TAG_MIN_SIZE_BYTES        CC_AESGCM_TAG_SIZE_4_BYTES
/*! AES-GCM Tag maximal size in bytes. */
#define CC_AESGCM_TAG_MAX_SIZE_BYTES        CC_AESGCM_TAG_SIZE_16_BYTES

/*! AES-GCM Tag Comparison failure. */
#define CC_AESGCM_TAG_COMPARISON_FAILURE    0xFFFFFFFF

/*! AES-GCM decrypt mode */
#define CC_AESGCM_Decrypt   CC_AES_DECRYPT
/*! AES-GCM encrypt mode */
#define CC_AESGCM_Encrypt   CC_AES_ENCRYPT

/************************ Typedefs  ****************************/
/*! AES-GCM key size definitions. */
typedef enum {
	CC_AESGCM_Key128BitSize   = 0, /*!< AES-GCM 128 bit key*/
	CC_AESGCM_Key192BitSize   = 1, /*!< AES-GCM 192 bit key*/
	CC_AESGCM_Key256BitSize   = 2, /*!< AES-GCM 256 bit key*/

	CC_AESGCM_KeySizeNumOfOptions,  /*!< Reserved. */

	CC_AESGCM_KeySizeLast    = 0x7FFFFFFF, /*!< Reserved. */

}CCAesGcmKeySize_t;

/* Defines the AES_GCM key buffer */
 /*! AES-GCM key structure definition. */
typedef uint8_t CCAesGcmKey_t[CC_AESGCM_KEY_SIZE_WORDS * sizeof(uint32_t)];
/*! AES-GCM tag structure definition. */
typedef uint8_t CCAesGcmTagRes_t[CC_AES_BLOCK_SIZE_IN_BYTES];


/******************* Context Structure  ***********************/
/* The user's context structure - the argument type that is passed by the user
   to the APIs called */


   /*! AES-GCM context structure */
  /* Allocated buffer must be double the size of actual context
* + 3 words for offset management */
typedef struct
{
   uint32_t  buff[CC_AESGCM_USER_CTX_SIZE_IN_WORDS];  /*!< Context structure definition. */
}CCAesGcmUserContext_t;

/************************ Public Variables **********************/


/************************ Public Functions **********************/

/*!
@brief This function initializes the AES GCM context.

It formats the input data, calculates the hash subkey for GHASH and J0 value,
and initializes the AES context structure.
 \note To be FIPS-compliant, the user must use the AES GCM integrated function only.
 @return \c CC_OK on success.
 @return A non-zero value on failure as defined cc_aesgcm_error.h.
*/
CCError_t CC_AesGcmInit(
			CCAesGcmUserContext_t *ContextID_ptr,   /*!< [in]  Pointer to the AES context buffer that is allocated by the user and is used for the AES operation. */
			CCAesEncryptMode_t EncrDecrMode,        /*!< [in]  Flag specifying whether Encrypt (::CC_AES_ENCRYPT) or Decrypt (::CC_AES_DECRYPT) operation should be performed. */
			CCAesGcmKey_t GCM_Key,                  /*!< [in]  Pointer to the AES-GCM key. */
			CCAesGcmKeySize_t KeySizeId,            /*!< [in]  Enumerator defining the key size (128, 192 or 256 bits). */
			size_t AdataSize,                       /*!< [in]  Full byte length of additional (associated) data.
                                                               If set to zero, calling ::CC_AesGcmBlockAdata on the same context would return an error.
                                                               Max size of Adata is limited to 2^32. */
			size_t TextSize,                        /*!< [in]  Full length of plain text data .Max size of text data is limited to 2^32.*/
			uint8_t *pIv,                           /*!< [in]  Pointer to the IV. */
			size_t  ivSize,                         /*!< [in]  Byte size of the IV. Max size of IV is limited to 2^32. */
			uint8_t tagSize                         /*!< [in]  AES-GCM authentication tag byte size. Valid range = [4, 8, 12, 13, 14, 15, 16]. */
            );

/*!
@brief This function receives a GCM context and a block of additional data, and adds it to the authentication tag calculation.
This API can be called only once per operation context. It should not be called in case AdataSize was set to zero in CC_AesGcmBlockAdata.
\note To be FIPS-compliant, you must only use the AES GCM integrated function .
@return \c CC_OK on success.
@return A non-zero value on failure as defined cc_aesgcm_error.h.
*/
CCError_t CC_AesGcmBlockAdata(
		CCAesGcmUserContext_t *ContextID_ptr,   /*!< [in]  Pointer to the context buffer. */
                uint8_t *DataIn_ptr,                      /*!< [in]  Pointer to the additional input data. */
                size_t DataInSize                         /*!< [in]  Byte size of the additional data. Must match AdataSize parameter provided to ::CC_AesGcmInit. */
);

/*!
@brief This function can be invoked for any block of Text data whose size is a multiple of 16 bytes,
excluding the last block that has to be processed by ::CC_AesGcmFinish.

 <ul><li> If encrypting:
 Continues encryption of the text data, while calculating the authentication tag value of encrypted data.</li>
 <li> If decrypting:
 Continues calculation of the authentication tag value of the text data, while simultaneously decrypting the text data. </li></ul>
 \note To be FIPS-compliant, you must only use the AES-GCM integrated function.
@return \c CC_OK on success.
@return A non-zero value on failure as defined cc_aesgcm_error.h.
*/
CCError_t CC_AesGcmBlockTextData(
				CCAesGcmUserContext_t *ContextID_ptr,   /*!< [in]  Pointer to the context buffer. */
				uint8_t *DataIn_ptr,                    /*!< [in]  Pointer to the input data. */
				size_t DataInSize,                      /*!< [in]  Byte size of the text data block. Must be a multiple of 16 bytes. */
				uint8_t *DataOut_ptr                    /*!< [out] Pointer to the output data. The size of the output buffer must be at least DataInSize. */
);

/*!
@brief This function must be the last to be called on the text data.

It can either be called on the entire text data (if transferred as one block), or on the last block of the text data, even if total size of text data is equal to 0.
It performs the same operations as CC_AesGcmBlockTextData, but additionally:
<ul><li> If encrypting:
  <ul><li> If the size of text data is not in multiples of 16 bytes, it pads the remaining bytes with zeroes to a full 16-bytes block and processes the data using GHASH and GCTR algorithms.</li>
  <li> Encrypts the authentication result with GCTR using the J0 value saved in the context and places the authentication tag at the end.</li></ul>
<li> If decrypting:
  <ul><li> Processes the text data using GHASH and GCTR algorithms.</li>
  <li> Encrypts the calculated authentication tag using GCTR based on the saved J0 value, and compares it with tagSize last bytes of input data (such as the tag value).</li>
  <li> The function saves the validation result (Valid/Invalid) in the context.</li>
  <li> Returns (as the error code) the final authentication tag verification result.</li></ul></ul>
\note To be FIPS-compliant, the user must use the AES GCM integrated function only.
@return \c CC_OK on success.
@return A non-zero value on failure as defined cc_aesgcm_error.h.
*/
CEXPORT_C CCError_t CC_AesGcmFinish(
				CCAesGcmUserContext_t *ContextID_ptr,   /*!< [in]  Pointer to the context buffer. */
				uint8_t *DataIn_ptr,                    /*!< [in]  Pointer to the last input data. */
				size_t DataInSize,                      /*!< [in]  Byte size of the last text data block. Can be zero. */
				uint8_t *DataOut_ptr,                   /*!< [out] Pointer to the output (cipher or plain text data) data. If DataInSize = 0, output buffer is not required. */
                uint8_t *tagSize,                       /*!< [in]  AES-GCM authentication tag byte size as defined in CC_AesGcmInit. */
				CCAesGcmTagRes_t pTag                   /*!< [in/out]  AES-GCM authentication tag buffer pointer. */
);

/****************************************************************************************************/
/********                       AESGCM  FUNCTION                                              ******/
/****************************************************************************************************/
/*!
@brief This API performs AES-GCM operation on a given data.
\note To be FIPS-compliant, the user must use the AES GCM integrated function only. \par
\note For security reasons, Arm recommendeds that you use the integrated function only, if the non integrated        												 functions are used the data is decrypted before the full authentication is done.
@return \c CC_OK on success.
@return A non-zero value on failure as defined cc_aesgcm_error.h.
*/
CIMPORT_C CCError_t  CC_AesGcm(
				   CCAesEncryptMode_t     EncrDecrMode,       /*!< [in]  A flag specifying whether an AES Encrypt (CC_AES_ENCRYPT) or Decrypt (CC_AES_DECRYPT) operation should be performed. */
				   CCAesGcmKey_t          GCM_Key,            /*!< [in]  Pointer to AES-GCM key. */
				   CCAesGcmKeySize_t      KeySizeId,          /*!< [in]  Enumerator defining the key size (128, 192 or 256 bits). */
				   uint8_t                *pIv,               /*!< [in]  Pointer to the IV. The buffer must be contiguous. */
				   size_t                 ivSize,             /*!< [in]  Byte size of the IV. Max size of IV is limited to 2^32. */
				   uint8_t                *ADataIn_ptr,       /*!< [in]  Pointer to the additional input data. */
				   size_t                 ADataInSize,        /*!< [in]  Byte size of the additional data. Max size of Adata is limited to 2^32. */
				   uint8_t                *TextDataIn_ptr,    /*!< [in]  Pointer to the plain-text data for encryption or cipher-text data for decryption. */
				   size_t                 TextDataInSize,     /*!< [in]  Byte size of the full text data. Max size of text data is limited to 2^32. */
				   uint8_t                *TextDataOut_ptr,   /*!< [out] Pointer to the output (cipher or plain text data according to encrypt-decrypt mode) data. */
				   uint8_t                tagSize,            /*!< [in]  AES-GCM authentication tag byte size. Valid range = [4, 8, 12, 13, 14, 15, 16]. */
				   CCAesGcmTagRes_t       pTag               /*!< [in/out] Pointer to the authentication tag result buffer. */
);

#ifdef __cplusplus
}
#endif

#endif /*#ifndef _CC_AESGCM_H*/
/*!
 @}
 */

