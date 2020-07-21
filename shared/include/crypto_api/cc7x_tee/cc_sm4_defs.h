/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

/*!
 @file
 @brief This file contains the type definitions that are used by the CryptoCell
 SM4 APIs.
 */


 /*!
  @addtogroup cc_sm4_defs
  @{
      */

#ifndef CC_SM4_DEFS_H
#define CC_SM4_DEFS_H

#include "cc_sm4_defs_proj.h"


#ifdef __cplusplus
extern "C"
{
#endif


/************************ Defines  ******************************/
/*! The size of the SM4 block in words. */
#define CC_SM4_CRYPTO_BLOCK_SIZE_IN_WORDS 4
/*! The size of the SM4 block in Bytes. */
#define CC_SM4_BLOCK_SIZE_IN_BYTES  (CC_SM4_CRYPTO_BLOCK_SIZE_IN_WORDS * sizeof(uint32_t))

/*! The size of the Key buffer in words. */
#define CC_SM4_KEY_SIZE_IN_WORDS   CC_SM4_CRYPTO_BLOCK_SIZE_IN_WORDS
/*! The size of the Key buffer in Bytes. */
#define CC_SM4_KEY_SIZE_IN_BYTES  (CC_SM4_KEY_SIZE_IN_WORDS * sizeof(uint32_t))

/*! The size of the IV buffer in words. */
#define CC_SM4_IV_SIZE_IN_WORDS   CC_SM4_CRYPTO_BLOCK_SIZE_IN_WORDS
/*! The size of the IV buffer in Bytes. */
#define CC_SM4_IV_SIZE_IN_BYTES  (CC_SM4_IV_SIZE_IN_WORDS * sizeof(uint32_t))


/************************ Enums ********************************/
/*! The SM4 operation:<ul><li>Encrypt</li><li>Decrypt</li></ul>. */
typedef enum {
    /*! An SM4 encrypt operation. */
    CC_SM4_ENCRYPT = 0,
 /*! An SM4 decrypt operation. */
    CC_SM4_DECRYPT = 1,
    /*! The maximal number of operations. */
    CC_SM4_NUM_OF_ENCRYPT_MODES,
    /*! Reserved. */
    CC_SM4_ENCRYPT_MODE_LAST = 0x7FFFFFFF
}CCSm4EncryptMode_t;

/*! The SM4 operation mode. */
typedef enum {
    /*! ECB mode. */
    CC_SM4_MODE_ECB          = 0,
    /*! CBC mode. */
    CC_SM4_MODE_CBC          = 1,
    /*! CTR mode. */
    CC_SM4_MODE_CTR          = 2,
    /*! OFB mode. */
    CC_SM4_MODE_OFB          = 3,
    /*! The maximal number of SM4 modes. */
    CC_SM4_NUM_OF_OPERATION_MODES,
    /*! Reserved. */
    CC_SM4_OPERATION_MODE_LAST = 0x7FFFFFFF
}CCSm4OperationMode_t;

/************************ Typedefs  ****************************/

/*! Defines the IV buffer. A 16-Byte array. */
typedef uint8_t CCSm4Iv_t[CC_SM4_IV_SIZE_IN_BYTES];

/*! Defines the SM4 key data buffer. */
typedef uint8_t CCSm4Key_t[CC_SM4_KEY_SIZE_IN_BYTES];

/************************ Structs  ******************************/

/*!
 The context prototype of the user.

 The argument type that is passed by the user to the SM4 APIs. The context
 saves the state of the operation, and must be saved by the user
 till the end of the API flow.
 */
typedef struct CCSm4UserContext_t {
    /*! The context buffer for internal usage. */
    uint32_t buff[CC_SM4_USER_CTX_SIZE_IN_WORDS] ;
}CCSm4UserContext_t;

/*!
 @}
 */

#endif /* CC_SM4_DEFS_H */

