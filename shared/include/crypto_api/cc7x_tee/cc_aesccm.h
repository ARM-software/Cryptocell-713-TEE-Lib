/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


#ifndef _CC_AESCCM_H
#define _CC_AESCCM_H

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
@brief This file contains all the enums and definitions that are used for the CryptoCell AES-CCM APIs, as well as the APIs themselves.
*/

/*!
 @addtogroup cc_aes_ccm
 @{
     */

/************************ Defines ******************************/

/* In order to allow contiguous context the user context is doubled + 3 words for management */
/*! AES-CCM Context size expressed in words. */
#define CC_AESCCM_USER_CTX_SIZE_IN_WORDS 133

/*! AES-CCM key size in words. */
#define CC_AESCCM_KEY_SIZE_WORDS           8

/* nonce and AESCCM-MAC sizes definitions */
/*! AES-CCM minimal Nonce size expressed in bytes.*/
#define CC_AESCCM_NONCE_MIN_SIZE_BYTES     7
/*! AES-CCM maximal Nonce size expressed in bytes.*/
#define CC_AESCCM_NONCE_MAX_SIZE_BYTES    13
/*! AES-CCM minimal message authentication code size expressed in bytes.*/
#define CC_AESCCM_MAC_MIN_SIZE_BYTES       4
/*! AES-CCM maximal message authentication code size expressed in bytes.*/
#define CC_AESCCM_MAC_MAX_SIZE_BYTES      16
/*! Size of the AES CCM star Nonce expressed in bytes.*/
#define CC_AESCCM_STAR_NONCE_SIZE_BYTES   13


 /*! Decrypt mode*/
#define CC_AESCCM_Decrypt   CC_AES_DECRYPT
 /*! Encrypt mode*/
#define CC_AESCCM_Encrypt   CC_AES_ENCRYPT



/************************ Typedefs  ****************************/
/*! CCM Keysize*/
typedef enum {
	CC_AES_Key128BitSize   = 0, /*!< 128 bit key.*/
	CC_AES_Key192BitSize   = 1, /*!< 192 bit key.*/
	CC_AES_Key256BitSize   = 2, /*!< 256 bit key.*/
	CC_AES_Key512BitSize   = 3, /*!< 512 bit key.*/

	CC_AES_KeySizeNumOfOptions, /*!< Reserved.*/

	CC_AES_KeySizeLast    = 0x7FFFFFFF, /*!< Reserved. */

}CCAesCcmKeySize_t;

/*! CCM mode*/
typedef enum {
    CC_AES_MODE_CCM       = 0, /*!< AES-CCM mode. */
    CC_AES_MODE_CCM_STAR  = 1, /*!< AES-CCM star mode. */

    CC_AES_CCM_ModeNumOfOptions, /*!< Number of CCM mode option.*/

    CC_AES_CCM_ModeLast    = 0x7FFFFFFF, /*!< Reserved.*/
}CCAesCcmMode_t;

/* Defines the AES_CCM key buffer */
 /*! AES-CCM key structure definition.*/
typedef uint8_t CCAesCcmKey_t[CC_AESCCM_KEY_SIZE_WORDS * sizeof(uint32_t)];
 /*! AES-CCM key message authentication code structure definition.*/
typedef uint8_t CCAesCcmMacRes_t[CC_AES_BLOCK_SIZE_IN_BYTES];


/******************* Context Structure  ***********************/
/* The user's context structure - the argument type that is passed by the user
   to the APIs called */

 /*! User context*/
typedef struct CCAesCcmUserContext_t
{
/* Allocated buffer must be double the size of actual context
* + 1 word for offset management */
   uint32_t  buff[CC_AESCCM_USER_CTX_SIZE_IN_WORDS]; /*!< User context buffer definition.*/
}CCAesCcmUserContext_t;

/************************ Public Variables **********************/


/************************ Public Functions **********************/

/*!
@brief This function initializes the AES CCM context.

It formats the input data, calculates AES-MAC value for the formatted B0 block containing control information and CCM unique value (Nonce),
and initializes the AES context structure including the initial CTR0 value.
 \note To be FIPS-compliant, the user must use the AES-CCM integrated function only.
 @return \c CC_OK on success.
 @return A non-zero value on failure as defined cc_aesccm_error.h.
*/
CCError_t CC_AesCcmInit(
			CCAesCcmUserContext_t *ContextID_ptr,   /*!< [in]  Pointer to the AES context buffer that is allocated by the user and is used for the AES operation. */
			CCAesEncryptMode_t EncrDecrMode,          /*!< [in]  Flag specifying whether Encrypt (::CC_AES_ENCRYPT) or Decrypt (::CC_AES_DECRYPT) operation should be performed. */
			CCAesCcmKey_t CCM_Key,                  /*!< [in]  Pointer to the AES-CCM key. */
			CCAesCcmKeySize_t KeySizeId,            /*!< [in]  Enumerator defining the key size (128, 192 or 256 bits). */
			size_t AdataSize,                         /*!< [in]  Full byte length of additional (associated) data. Max size of Adata is limited to 2^32.
                                                                    If set to zero, calling ::CC_AesCcmBlockAdata on the same context would return an error. */
			size_t TextSize,                          /*!< [in]  Full length of plain text data. Max size of TextSize is limited to 2^32.*/
			uint8_t *N_ptr,                             /*!< [in]  Pointer to the Nonce. */
			uint8_t SizeOfN,                            /*!< [in]  Nonce byte size. Valid range = [7 .. 13]. */
			uint8_t SizeOfT,                             /*!< [in]  AES-CCM MAC (tag) byte size. Valid range = [4, 6, 8, 10, 12, 14, 16]. */
			CCAesCcmMode_t ccmMode        /*!< [in] CCM or CCM star */
            );

/*!
  @brief This function receives the MAC source address, the frame counter,
         and the MAC size, and returns the required nonce for AES-CCM*,
         as defined in <em>IEEE 802.15.4: IEEE Standard for Local and metropolitan
         area networks— Part 15.4: Low-Rate Wireless Personal Area Networks (LR-WPANs)</em>.

  @note  This API should be called before CC_AesCcmInit(),
         and the generated nonce should be provided to this function.

  @return \c CC_OK on success.
  @return A non-zero value on failure, as defined cc_aesccm_error.h.
 */
CCError_t  CC_AesCcmStarNonceGenerate(
                                     unsigned char * src_addr, /*!< [in] The MAC address in EUI-64 format. */
                                     uint32_t frame_counter,   /*!< [in] The MAC frame counter. */
                                     uint8_t size_of_t,        /*!< [in]  The size of the AES-CCM* MAC tag in bytes:
                                                                             4, 6, 8, 10, 12, 14 or 16. */
                                     unsigned char * nonce_buf /*!< [out] The required nonce for AES-CCM*. */
                                    );


/*!
@brief This function receives a CCM context and a block of additional data, and adds it to the AES MAC calculation.
This API can be called only once per operation context. It should not be called in case AdataSize was set to zero in CC_AesCcmBlockAdata.
\note To be FIPS-compliant, the user must use the AES CCM integrated function only.
@return \c CC_OK on success.
@return A non-zero value on failure as defined cc_aesccm_error.h.
*/
CCError_t CC_AesCcmBlockAdata(
		CCAesCcmUserContext_t *ContextID_ptr,   /*!< [in]  Pointer to the context buffer. */
                uint8_t *DataIn_ptr,                        /*!< [in]  Pointer to the additional input data.
                                                                        The size of the scatter/gather list representing the data buffer is limited to 128 entries,
                                                                        and the size of each entry is limited to 64KB (fragments larger than 64KB are broken into
									fragments <= 64KB). */
                size_t DataInSize                         /*!< [in]  Byte size of the additional data. Must match AdataSize parameter provided to ::CC_AesCcmInit. */
);

/*!
@brief This function can be invoked for any block of Text data whose size is a multiple of 16 bytes,
excluding the last block that has to be processed by ::CC_AesCcmFinish.

<ul><li> If encrypting:
Continues calculation of the intermediate AES_MAC value of the text data, while simultaneously encrypting the text data using AES_CTR,
starting from CTR value = CTR0+1.</li>
<li> If decrypting:
Continues decryption of the text data, while calculating the intermediate AES_MAC value of decrypted data.</li></ul>
\note To be FIPS-compliant, you must only use the AES-CCM integrated function.
@return \c CC_OK on success.
@return A non-zero value on failure as defined cc_aesccm_error.h.
*/
CCError_t CC_AesCcmBlockTextData(
				CCAesCcmUserContext_t *ContextID_ptr,   /*!< [in]  Pointer to the context buffer. */
				uint8_t *DataIn_ptr,                        /*!< [in]  Pointer to the input data. */
				size_t DataInSize,                        /*!< [in]  Byte size of the text data block. Must be <= 512KB. Must be a multiple of 16 bytes. */
				uint8_t *DataOut_ptr                        /*!< [out] Pointer to the output data. The size of the output buffer must be at least DataInSize. */
);

/*!
@brief This function must be the last to be called on the text data.

It can either be called on the entire text data (if transferred as one block), or on the last block of the text data, even if total size of text data is equal to 0.
It performs the same operations as CC_AesCcmBlockTextData, but additionally:
<ul><li> If encrypting:
  <ul><li> If the size of text data is not in multiples of 16 bytes, it pads the remaining bytes with zeroes to a full 16-bytes block and processes the data using AES_MAC and AES_CTR algorithms.</li>
  <li> Encrypts the AES_MAC result with AES_CTR using the CTR0 value saved in the context and places the SizeOfT bytes of MAC (tag) at the end.</li></ul>
<li> If decrypting:
  <ul><li> Processes the text data, except for the last SizeOfT bytes (tag), using AES_CTR and then AES_MAC algorithms.</li>
  <li> Encrypts the calculated MAC using AES_CTR based on the saved CTR0 value, and compares it with SizeOfT last bytes of input data (such as the tag value).</li>
  <li> The function saves the validation result (Valid/Invalid) in the context.</li>
  <li> Returns (as the error code) the final CCM-MAC verification result.</li></ul></ul>
\note To be FIPS-compliant, the user must use the AES-CCM integrated function only.
@return \c CC_OK on success.
@return A non-zero value on failure as defined cc_aesccm_error.h.
*/
CEXPORT_C CCError_t CC_AesCcmFinish(
				CCAesCcmUserContext_t *ContextID_ptr,   /*!< [in]  Pointer to the context buffer. */
				uint8_t *DataIn_ptr,                        /*!< [in]  Pointer to the last input data. */
				size_t DataInSize,                        /*!< [in]  Byte size of the last text data block. Can be zero. */
				uint8_t *DataOut_ptr,                       /*!< [out]  Pointer to the output (cipher or plain text data) data. If DataInSize = 0, output buffer is not required. */
				CCAesCcmMacRes_t MacRes,               /*!< [in/out]  MAC result buffer pointer. */
				uint8_t *SizeOfT                            /*!< [in]  AES-CCM MAC byte size as defined in CC_AesCcmInit. */
);

/****************************************************************************************************/
/********                       AESCCM  FUNCTION                                              ******/
/****************************************************************************************************/
/*!
@brief This API performs AES-CCM operation on a given data.
 \note To be FIPS-compliant, the user must use the AES CCM integrated function only. \par
 \note For security reasons, Arm recommends that you use the integrated function only, if the non integrated        												 functions are used the data is decrypted before the full authentication is done.
 @return \c CC_OK on success.
 @return A non-zero value on failure as defined cc_aesccm_error.h.
*/
CIMPORT_C CCError_t  CC_AesCcm(
				   CCAesEncryptMode_t     EncrDecrMode,       /*!< [in]  A flag specifying whether an AES Encrypt (CC_AES_ENCRYPT) or Decrypt (CC_AES_DECRYPT) operation should be performed. */
				   CCAesCcmKey_t          CCM_Key,            /*!< [in]  Pointer to AES-CCM key. */
				   CCAesCcmKeySize_t      KeySizeId,          /*!< [in]  Enumerator defining the key size (128, 192 or 256 bits). */
				   uint8_t                *N_ptr,             /*!< [in]  Pointer to the Nonce. */
				   uint8_t                SizeOfN,            /*!< [in]  Nonce byte size. Valid range = [7 .. 13]. */
				   uint8_t                *ADataIn_ptr,       /*!< [in]  Pointer to the additional input data. The size of the scatter/gather list representing the data buffer is limited to 128 entries, and the size of each entry is limited to 64KB (fragments larger than 64KB are broken into fragments <= 64KB). */
				   size_t                 ADataInSize,        /*!< [in]  Byte size of the additional data. Max size of Adata is limited to 2^32. */
				   uint8_t                *TextDataIn_ptr,    /*!< [in]  Pointer to the plain-text data for encryption or cipher-text data for decryption. The size of the scatter/gather list representing the data buffer is limited to 128 entries, and the size of each entry is limited to 64KB (fragments larger than 64KB are broken into fragments <= 64KB).  */
				   size_t                 TextDataInSize,     /*!< [in]  Byte size of the full text data. Max size of TextSize is limited to 2^32. */
				   uint8_t                *TextDataOut_ptr,   /*!< [out] Pointer to the output (cipher or plain text data according to encrypt-decrypt mode) data. The size of the scatter/gather list representing the data buffer is limited to 128 entries, and the size of each entry is limited to 64KB (fragments larger than 64KB are broken into fragments <= 64KB).  */
				   uint8_t                SizeOfT,            /*!< [in]  AES-CCM MAC (tag) byte size. Valid range = [4, 6, 8, 10, 12, 14, 16]. */
				   CCAesCcmMacRes_t       Mac_Res,            /*!< [in/out] Pointer to the MAC result buffer. */
				   CCAesCcmMode_t         ccm_mode            /*!< [in] ccm mode.*/
);

#ifdef __cplusplus
}
#endif
/*!
 @}
 */
#endif /*#ifndef _CC_AESCCM_H*/

