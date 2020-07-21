/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

/*!
 @file
 @brief This file contains type definitions for the Secure Boot.
 */

/*!
 @addtogroup cc_sb_defs
 @{
 */

#ifndef _SECURE_BOOT_DEFS_H
#define _SECURE_BOOT_DEFS_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "cc_crypto_boot_defs.h"
#include "cc_sec_defs.h"
#include "bootimagesverifier_def.h"
#include "cc_address_defs.h"

/* General definitions */
/***********************/

/*! The structure used for input or output to the Secure Boot verification API. */
typedef struct{
    /*! The NV counter saved in OTP. */
    uint32_t                otpVersion;
    /*! The key hash to retrieve:<ul><li>The 128-bit Hbk0.</li><li>The 128-bit Hbk1.</li><li>The 256-bit Hbk.</li></ul> */
    CCSbPubKeyIndexType_t   keyIndex;
    /*! The revocation version word as defined in the certificate-chain. */
    uint32_t                nvCounter;
    /*! <ul><li>[in] The hash of the public key (N||Np), to compare to the public key stored in the certificate.</li>
            <li>[out] The hash of the public key (N||Np) stored in the certificate, to be used for verification
                of the public key of the next certificate in the chain.</li></ul> */
    CCHashResult_t          pubKeyHash;
    /*! The initialization indication. Internal flag. */
    uint32_t initDataFlag;
}CCSbCertInfo_t;

/*! Certificate chain types. */
typedef enum {
        /*! Secure Boot chain combined.*/
        CC_SECURE_BOOT_CHAIN = 0,
        /*! Image storage memory is RAM.*/
        CC_SECURE_DEBUG_CHAIN = 1,
        /*! Reserved.*/
        CC_SB_RESERVED_CHAIN_TYPE = 0x7FFFFFFF
}CCSbCertChainType_t;

/*! Memory types where the image is stored. */
typedef enum {
        /*! Software image is not valid.*/
        CC_SB_NO_IMAGE_VALID = 0,
        /*! Image storage memory is RAM.*/
        CC_SB_IMAGE_IN_RAM = 1,
        /*! Image storage memory is flash.*/
        CC_SB_IMAGE_IN_FLASH = 2,
        /*! Reserved.*/
        CC_SB_RESERVED_IMAGE_MEMORY_TYPE = 0x7FFFFFFF
}CCSbImageMemoryType_t;

/*! The structure to store the memory types of the verified software image. */
typedef struct {
        CCSbImageMemoryType_t   imageMemoryType; /*!< The memory type of the software image. */
        CCAddr_t                imageAddr;       /*!< The address of the software image. */
        uint32_t                imageSize;       /*!< The size of the software image. */
}VerifiedImageInfo_t;

/*! Definition of software images list. */
typedef VerifiedImageInfo_t VerifiedImagesList_t[CC_SB_MAX_NUM_OF_IMAGES];

/*! A structure defining the list of stored images. */
typedef struct {
        /*! Number of software images. */
        uint32_t                numOfImages;
        /*! List of addresses of the software images. */
        VerifiedImagesList_t    imagesList;
}CCSbImagesInfo_t;

/*! A structure to store the X509 TBS header info. */
typedef struct {
        /*! Pointer to an allocated buffer. */
        uint32_t   *pBuffer;
        /*! The size of the allocated buffer.*/
        uint32_t   bufferSize;
} CCSbX509TBSHeader_t;

/*! The public key hash array of the Secure Boot certificate. */
typedef uint32_t CCSbCertPubKeyHash_t[HASH_RESULT_SIZE_IN_WORDS];

/*! The \c SoC_ID array of the Secure Boot certificate. */
typedef uint32_t CCSbCertSocId_t[HASH_RESULT_SIZE_IN_WORDS];


/********* Function pointer definitions ***********/

/*!
  @brief Typedef of the flash read function pointer, which you implement.

  Used for reading the certificates and software modules from flash memory.

  @note It is your responsibility to verify that this function does not copy data from restricted memory regions.
 */

typedef uint32_t (*CCSbFlashReadFunc) (
                     CCAddr_t flashAddress, /*!< [in] The address for reading from flash memory. */
                     uint8_t *memDst, /*!< [out] A pointer to the RAM destination address to write the data to.
                                                 When running in boot context, memDst is expected to be physical address.
                                                 When running in runtime context, memDst is expected to be virtual address. */
                     uint32_t sizeToRead, /*!< [in] The size to read in bytes. */
                     void* context /*!< [in] For your use. */
                     );



/* ******** End of Function pointer definitions ***********/


#ifdef __cplusplus
}
#endif
/*!
 @}
 */
#endif
