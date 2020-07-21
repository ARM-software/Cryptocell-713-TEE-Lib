/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


#ifndef _BSV_CRYPTO_DRIVER_H
#define _BSV_CRYPTO_DRIVER_H


#ifdef __cplusplus
extern "C"
{
#endif

#include "cc_sec_defs.h"
#include "cc_address_defs.h"
#include "bsv_crypto_defs.h"
#include "cc_hw_queue_defs.h"

/*! @file
@brief This file contains crypto driver definitions: SH256, CMAC KDF, and CCM.
*/

/************************ Defines ******************************/

/*! CC maximal DMA DLLI data flow size (limited by dscrptr_word1[25:2] - 16MB - 1 */
#define BSV_DMA_DLLI_MAX_SIZE_IN_BYTES          0x00FFFFFF
/*! maximal data size to process */
#define BSV_MAX_DATA_SIZE_IN_BYTES              BSV_DMA_DLLI_MAX_SIZE_IN_BYTES

/*! SHA256 digest result in words. */
#define BSV_SHA256_DIGEST_SIZE_IN_WORDS         8
/*! SHA256 digest result in bytes. */
#define BSV_SHA256_DIGEST_SIZE_IN_BYTES         (BSV_SHA256_DIGEST_SIZE_IN_WORDS * CC_32BIT_WORD_SIZE)

/*! HASH length in words. */
#define BSV_HASH_LENGTH_SIZE_IN_WORDS           4
/*! HASH length in bytes. */
#define BSV_HASH_LENGTH_SIZE_IN_BYTES           (BSV_HASH_LENGTH_SIZE_IN_WORDS * CC_32BIT_WORD_SIZE)
/*! HASH block size in bytes. */
#define BSV_HASH_BLOCK_SIZE_IN_BYTES            64

/*! The derived key size for 128 bits. */
#define BSV_128BITS_KEY_SIZE_IN_BYTES           16
/*! The derived key size for 256 bits. */
#define BSV_256BITS_KEY_SIZE_IN_BYTES           32
/*! The derived key size for 128 bits in words. */
#define BSV_128_BIT_KEY_SIZE_WORDS              (BSV_128BITS_KEY_SIZE_IN_BYTES / CC_32BIT_WORD_SIZE)

/*! Maximal label length in bytes. */
#define BSV_KDF_MAX_LABEL_LENGTH_IN_BYTES       64
/*! Maximal context length in bytes. */
#define BSV_KDF_MAX_CONTEXT_LENGTH_IN_BYTES     64
/*! KDF 128 bits key fixed data size in bytes. */
#define BSV_KDF_DATA_128BITS_SIZE_IN_BYTES      3 /*!< \internal 0x01, 0x00, lengt(-0x80) */
/*! KDF 256 bits key fixed data size in bytes. */
#define BSV_KDF_DATA_256BITS_SIZE_IN_BYTES      4 /*!< \internal 0x02, 0x00, lengt(-0x0100) */
/*! KDF data maximal size in bytes. */
#define BSV_KDF_MAX_SIZE_IN_BYTES               (BSV_KDF_DATA_256BITS_SIZE_IN_BYTES + BSV_KDF_MAX_LABEL_LENGTH_IN_BYTES + BSV_KDF_MAX_CONTEXT_LENGTH_IN_BYTES)

/*! Maximal AES CCM associated data size in bytes. */
#define BSV_CCM_MAX_ASSOC_DATA_SIZE_IN_BYTES         0xff00     /* 2^16-2^8 */
/*! Maximal AES CCM text data size in bytes. */
#define BSV_CCM_MAX_TEXT_DATA_SIZE_IN_BYTES          BSV_DMA_DLLI_MAX_SIZE_IN_BYTES

/*! AES block size in bytes. */
#define BSV_AES_BLOCK_SIZE_IN_BYTES     16
/*! AES IV size in bytes. */
#define BSV_AES_IV_SIZE_IN_BYTES        16
/*! AES IV size in words. */
#define BSV_AES_IV_SIZE_IN_WORDS        4

/*! HASH initial vector. */
#ifdef BIG__ENDIAN
#define BSV_SHA256_VAL 0x19CDE05B, 0xABD9831F, 0x8C68059B, 0x7F520E51, 0x3AF54FA5, 0x72F36E3C, 0x85AE67BB, 0x67E6096A
#else
#define BSV_SHA256_VAL 0x5BE0CD19, 0x1F83D9AB, 0x9B05688C, 0x510E527F, 0xA54FF53A, 0x3C6EF372, 0xBB67AE85, 0x6A09E667
#endif
/*! HASH SHA256 control value. */
#define BSV_HASH_CTL_SHA256_VAL         0x2UL
/*! HASH padding enabled. */
#define BSV_HASH_PADDING_ENABLED        0x1UL
/*! HASH big-endianness. */
#define BSV_HASH_BIG_ENDIANNESS         0x2UL
/*! HASH zero value for not using XOR. */
#define BSV_HASH_DO_NOT_XOR_VAL         0x0UL
/*! HASH input value for using XOR. */
#define BSV_HMAC_IPAD_CONST_BLOCK       0x36363636
/*! HASH output value for using XOR. */
#define BSV_HMAC_OPAD_CONST_BLOCK       0x5C5C5C5C

/*! Use HASH engine for AES_MAC purposes */
#define BSV_DIGEST_AES_MAC              1
/*! Use Hash engine for HASH purposes */
#define BSV_DIGEST_HASH                 0

/************************ Typedefs  *****************************/
/* Defines the IV counter buffer  - 16 bytes array */
typedef uint32_t AES_Iv_t[BSV_AES_BLOCK_SIZE_IN_BYTES/CC_32BIT_WORD_SIZE];


/* AES supported HW key code table - defined in bsv_crypto_defs.h  */
/* HwCryptoKey[1:0] is mapped to cipher_do[1:0] */
/* HwCryptoKey[2:3] is mapped to cipher_config2[1:0] */
/* typedef enum {
                                   conf2   do
    CC_BSV_USER_KEY = 0,            0     0
    CC_BSV_HUK_KEY = 1,             0     1
    CC_BSV_RTL_KEY = 2,             0     2
    CC_BSV_SESSION_KEY = 3,         0     3
    CC_BSV_CE_KEY = 4,              1     0
    CC_BSV_PLT_KEY = 5,             1     1
    CC_BSV_KCST_KEY = 6,            1     2
    CC_BSV_ICV_PROV_KEY = 0xd,      3     1
    CC_BSV_ICV_CE_KEY = 0xe,        3     2
    CC_BSV_PROV_KEY = 0xf,          3     3
    CC_BSV_END_OF_KEY_TYPE = INT32_MAX,
}CCBsvKeyType_t; */

/*! Definitions of cryptographic mode. */
typedef enum bsvCryptoMode {
    /*! AES.*/
    BSV_CRYPTO_AES = 1,
    /*! AES and HASH.*/
    BSV_CRYPTO_AES_AND_HASH = 3,
    /*! HASH.*/
    BSV_CRYPTO_HASH = 7,
    /*! AES to HASH and to DOUT.*/
    BSV_CRYPTO_AES_TO_HASH_AND_DOUT = 10,
    /*! Reserved.*/
    BSV_CRYPTO_RESERVE32B = INT32_MAX
}bsvCryptoMode_t;


/*! Definitions for AES modes. */
typedef enum aesMode {
    BSV_AES_CIPHER_NULL_MODE = -1,
    BSV_AES_CIPHER_ECB = 0,
    BSV_AES_CIPHER_CBC = 1,
    BSV_AES_CIPHER_CTR = 2,
    BSV_AES_CIPHER_CBC_MAC = 3,
    BSV_AES_CIPHER_OFB = 6,
    BSV_AES_CIPHER_CMAC = 7,
    BSV_AES_CIPHER_CCMA = 8,
    BSV_AES_CIPHER_CCMPE = 9,
    BSV_AES_CIPHER_CCMPD = 10,
    BSV_AES_CIPHER_RESERVE32B = INT32_MAX
}bsvAesMode_t;

/*! Definitions for AES key sizes. */
typedef enum bsvAesKeySize {
    /*! 128 bits AES key. */
    BSV_AES_KEY_SIZE_128BITS = 0,
    /*! 256 bits AES key. */
    BSV_AES_KEY_SIZE_256BITS = 2,
    /*! Reserved.*/
    BSV_AES_KEY_SIZE_RESERVE32B = INT32_MAX
}bsvAesKeySize_t;

/***************************** function declaration **************************/

/*!
@brief This function initializes the HASH machine for SHA256 operation.
*/
void BsvDigestDrvInit(unsigned long hwBaseAddress,          /*!< [in] The base address of the CryptoCell HW registers. */
                      uint32_t      mode,                   /*!< [in] cipher mode to work with.
                                                                      use BSV_AES_CIPHER_CBC_MAC for AES_MAC, with digestAlg = BSV_DIGEST_AES_MAC.
                                                                      use BSV_HASH_CTL_SHA256_VAL for HASH  */
                      CCSramAddr_t  keySramAddr,            /*!< [in] Sram address of the key to use.
                                                                      Ignored when using BSV_DIGEST_HASH alg */
                      size_t        keySize,                /*!< [in] key size to use.
                                                                      Ignored when using BSV_DIGEST_HASH alg */
                      CCDmaAddr_t   ivAddr,                 /*!< [in] The address of the hash initial buffer. */
                      size_t        ivSize,                 /*!< [in] initial vector size */
                      uint32_t      xorData,                /*!< [in] when using alg BSV_DIGEST_HASH. The sequence that will be xored with the data.
                                                                      In order to XOR this sequence with the data before the sha256 operation
                                                                      isXored should be 1 in BsvDigestDrvProcess. should be 6 bytes */
                      uint8_t       digestAlg               /*!< [in] BSV_DIGEST_AES_MAC or BSV_DIGEST_HASH */
                      );

/*!
@brief This function is used to process a block(s) of data on HASH machine.
*/
void BsvDigestDrvProcess(unsigned long     hwBaseAddress,   /*!< [in] The base address of the CryptoCell HW registers. */
                         CCDmaAddr_t       dataInAddr,      /*!< [in] The address of the input buffer to be hashed. The buffer must be contiguous. */
                         DmaMode_t         dmaInMode,       /*!< [in] DMA type of input buffer: DMA_SRAM, DMA_DLLI. */
                         size_t            dataInSize,      /*!< [in] The size of the data to be hashed, in bytes.
                                                                      If a multiple of 64 bytes, then HASH computation can continue with subsequent caals
                                                                      to HASH update; Else, only HASH finish with no data is allowed afterwards. */
                         uint8_t           isXored          /*!< [in] The sequence that will be xored with the data. In order
                                                                      to XOR this sequence with the data before the sha256 operation
                                                                      isXored should be 1 in BsvSha256Process. */
                          );

/*!
@brief This function finalizes the HASH operation, and returns the digest result.
*/
void BsvDigestDrvFinish(unsigned long   hwBaseAddress,      /*!< [in] The base address of the CryptoCell HW registers. */
                        uint32_t        mode,               /*!< [in] cipher mode to work with.
                                                                      use BSV_AES_CIPHER_CBC_MAC for AES, with digestAlg = BSV_DIGEST_AES_MAC.
                                                                      use BSV_HASH_CTL_SHA256_VAL for HASH  */
                        CCDmaAddr_t     hashLengthAddr,     /*!< [out] The address where to read the digest length value */
                        CCDmaAddr_t     hashBuffAddr,       /*!< [out] The address where to where to read the digest result */
                        size_t          digestSize,         /*!< [in] The length of the digest to read */
                        uint8_t         digestAlg);         /*!< [in] BSV_DIGEST_AES_MAC or BSV_DIGEST_HASH */


/*!
@brief This function is used to initialize an AES operation with a given key for CMAC or CTR modes.

@return \c CC_OK on success.
@return A non-zero value from bsv_error.h on failure.
*/
CCError_t BsvAesDrvInit(unsigned long   hwBaseAddress,      /*!< [in] The base address of the CryptoCell HW registers. */
                        bsvAesMode_t    mode,               /*!< [in] The operation cipher/mode: CMAC or CTR. */
                        CCBsvKeyType_t  keyType,            /*!< [in] The key type to use for th AES operation:
                                                              <ul><li>For CTR: Kce, Kceicv.</li>
                                                              <li>For CMAC: HUK, Krtl, Kpicv, and user key.</li></ul> */
                        CCDmaAddr_t     userKeyAddr,        /*!< [in] Address of the user key buffer. */
                        size_t          userKeySize,        /*!< [in] The user key size in bytes. */
                        DmaMode_t       userKeyDmaMode,     /*!< [in] DMA type of user key: DMA_SRAM, DMA_DLLI. */
                        CCDmaAddr_t     ivBufAddr,          /*!< [in] Address of the IV / counter buffer. */
                        DescDirection_t direction);         /*!< [in] The operation direction: encrypt / decrypt. */

/*!
@brief This function can be called in a sequence, to process consecutive blocks of AES operation.

@return \c CC_OK on success.
@return A non-zero value from bsv_error.h on failure.
*/
void BsvAesDrvProcess(unsigned long     hwBaseAddress,      /*!< [in] The base address of the CryptoCell HW registers. */
                        bsvAesMode_t    mode,               /*!< [in] The operation cipher/mode: CMAC or CTR. */
                        FlowMode_t      flow,               /*!< [in] The data flow mode: AES/ AES-to-HASH/ AES-and-HASH. */
                        CCDmaAddr_t     inputDataAddr,      /*!< [in] Address of the input data to the AES. */
                        CCDmaAddr_t     outputDataAddr,     /*!< [out] Address of the output buffer. NA for CMAC mode */
                        DmaMode_t       outputDmaMode,      /*!< [out] DMA type of the output buffer: DMA_SRAM, DMA_DLLI . NA for CMAC mode */
                        uint32_t        blockSize);         /*!< [in] Size of the input data in bytes. */

/*!
@brief This function is used to finish AES operation (for CMAC mode).

@return \c CC_OK on success.
@return A non-zero value from bsv_error.h on failure.
*/
void BsvAesDrvFinish(unsigned long      hwBaseAddress,      /*!< [in] The base address of the CryptoCell HW registers. */
                     bsvAesMode_t       mode,               /*!< [in] The operation cipher/mode: CMAC or CTR. */
                     CCDmaAddr_t        dataMacBuf,         /*!< [out] MAC result buffer address of CMAC mode. */
                     DmaMode_t          dataMacDmaMode);    /*!< [in] DMA type of MAC buffer: DMA_SRAM, DMA_DLLI. */

#ifdef __cplusplus
}
#endif

#endif


