/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _CC_CRYPTO_BOOT_DEFS_H
#define _CC_CRYPTO_BOOT_DEFS_H

#include "cc_pal_types.h"
#include "cc_boot_defs.h"

/*! @file
@brief This file contains Secure Boot definitions.
 */

 /*!
 @addtogroup cc_sbrom_defs
 @{
     */


/*! Maximal size of Secure Boot nonce. */
#define CC_SB_MAX_SIZE_NONCE_BYTES		(2*sizeof(uint32_t))

/*! SW image code encryption type definition. */
typedef enum {
    CC_SB_NO_IMAGE_ENCRYPTION   = 0,              /*!< A plain SW image. */
    CC_SB_ICV_CODE_ENCRYPTION   = 1,              /*!< Use Kceicv to encrypt the SW image. */
    CC_SB_OEM_CODE_ENCRYPTION   = 2,              /*!< Use Kce to encrypt the SW image. */
    CC_SB_CODE_ENCRYPTION_MAX_NUM   = 0x7FFFFFFF, /*!< Reserved. */
}CCswCodeEncType_t;

/*! SW image load and verify scheme. */
typedef enum {
    CC_SB_LOAD_AND_VERIFY       = 0,          /*!< Load and verify from flash to memory. */
    CC_SB_VERIFY_ONLY_IN_FLASH  = 1,          /*!< Verify only in flash. */
    CC_SB_VERIFY_ONLY_IN_MEM    = 2,          /*!< Verify only in memory. */
    CC_SB_LOAD_ONLY             = 3,          /*!< Load only from flash to memory. */
    CC_SB_LOAD_VERIFY_MAX_NUM   = 0x7FFFFFFF, /*!< Reserved. */
    /*!\internal For internal use only */
}CCswLoadVerifyScheme_t;

/*! The Cryptographic verification and decryption mode. */
typedef enum {
    CC_SB_HASH_ON_DECRYPTED_IMAGE   = 0,      /*!< AES and hash are calculated on the plain image. */
    CC_SB_HASH_ON_ENCRYPTED_IMAGE   = 1,      /*!< AES is calculated on the plain image, and the hash is calculated on the encrypted image. */
    CC_SB_CRYPTO_TYPE_MAX_NUM   = 0x7FFFFFFF, /*!< Reserved. */
    /*!\internal For internal use only */
}CCswCryptoType_t;

/*! Table nonce used in composing IV for SW-component decryption. */
typedef uint8_t CCSbNonce_t[CC_SB_MAX_SIZE_NONCE_BYTES];

/*! SW components data. */
typedef struct {
    /*! Number of SW components. */
    uint32_t  numOfSwComps;

    /*! Indicates if SW image is encrypted. */
    CCswCodeEncType_t swCodeEncType;

    /*! The load and verify scheme of the SW image. */
    CCswLoadVerifyScheme_t swLoadVerifyScheme;

    /*! The cryptographic type of the SW image. */
    CCswCryptoType_t swCryptoType;

    /*! Nonce. */
    CCSbNonce_t nonce;

    /*! Pointer to start of SW comps data. */
    uint8_t *pSwCompsData;

}CCSbCertParserSwCompsInfo_t;

/*! SW version */
typedef struct {
    /*! SW version ID. */
    CCSbSwVersionId_t  id;

    /*! SW version value. */
    uint32_t swVersion;

}CCSbSwVersion_t;


#endif

/**
 @}
 */
