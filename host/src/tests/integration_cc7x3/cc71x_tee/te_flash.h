/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


#ifndef _CC71X_TEE_INTEGRATION_TE_FLASH_H
#define _CC71X_TEE_INTEGRATION_TE_FLASH_H

/*!
  @file
  @brief This file contains Flash definitions for test usage.

  This file defines:
      <ol><li>Flash mapping used for Secure Boot certificates and images.</li>
      <li>Declarations of Flash functions.</li></ol>
 */
#include "cc_address_defs.h"
 /*!
 @addtogroup flash_apis
 @{
 */
/******************************************************************
 * Defines
 ******************************************************************/
/* Flash maximum size usage */
/*! 11K bytes for certificates and images. */
#define TE_FLASH_MAX_SIZE (11*1024U)

/*! Secure Boot certificate maximum size. */
#define TE_FLASH_MAP_CERT_MAX_SIZE      (0xC00)
/*!Base address in the flash for the certificates. */
#define TE_FLASH_MAP_CERT_BASE_ADDR     (0x0U)
/*! Offset in the Flash of the first certificate. */
#define TE_FLASH_MAP_CERT_START_OFFSET  (0x100U)
/*! First certificate in chain Flash address. */
#define TE_FLASH_MAP_KEY1_CERT_ADDR     (TE_FLASH_MAP_CERT_BASE_ADDR + TE_FLASH_MAP_CERT_START_OFFSET)
/*! Second certificate in chain Flash address. */
#define TE_FLASH_MAP_KEY2_CERT_ADDR     (TE_FLASH_MAP_KEY1_CERT_ADDR + TE_FLASH_MAP_CERT_MAX_SIZE)
/*! Third certificate in chain Flash address. */
#define TE_FLASH_MAP_CONTENT_CERT_ADDR  (TE_FLASH_MAP_KEY2_CERT_ADDR + TE_FLASH_MAP_CERT_MAX_SIZE)

/*! Secure Boot image maximal size. */
#define TE_FLASH_MAP_IMAGE_MAX_SIZE       (128U)
/*! Secure Boot number of images in a content certificate. */
#define TE_FLASH_MAP_MAX_IMAGES           2

/*! Flash address of the SW images (these addresses must be aligned with the
data in the certificate). */
#define TE_FLASH_MAP_IMAGES_BASE_ADDR     (TE_FLASH_MAP_CONTENT_CERT_ADDR + TE_FLASH_MAP_CERT_MAX_SIZE)

/*! Base address in the flash for the software images. */
#define TE_FLASH_MAP_IMAGES_START_OFFSET  (0x100U)
/*! Address in the flash for the software images. */
#define TE_FLASH_MAP_IMAGE_ADDR_START    (TE_FLASH_MAP_IMAGES_BASE_ADDR + TE_FLASH_MAP_IMAGES_START_OFFSET)  // 0x2600


/******************************************************************
 * Types
 ******************************************************************/
/******************************************************************
 * Externs
 ******************************************************************/
/******************************************************************
 * functions
 ******************************************************************/
/*!
@brief This function allocates and initializes the Flash resources.

\note This function must be the first Flash function called in a flow.

@return \c zero on success.
@return A non-zero value on failure.
*/
int TE_flash_init(void);


/*!
@brief This function terminates and clears the Flash resources.

\note This function is called at the end of the Flash usage flow.

@return Void.
*/
void TE_flash_finish(void);

/*!
@brief This function reads sizeToRead bytes from flashAddress into memDst
provided buffer.

@return \c zero on success.
@return A non-zero value on failure.
*/
int TE_flash_read(
                  /*! [in] The flash address to read from. */
                  CCAddr_t flashAddress,
                  /*! [out] The buffer to write to. Its size must be at least
                  sizeToRead bytes. */
                  uint8_t *memDst,
                  /*! [in] The number of bytes to read. */
                  uint32_t sizeToRead,
                  /*! [in/out] The user context. */
                  void* context
                  );

/*!
@brief This function writes sizeToWrite bytes from memSrc buffer into flashDest.

@return \c zero on success.
@return A non-zero value on failure.
*/
int TE_flash_write(
                   /*! [in] The flash address to write to. */
                   CCAddr_t flashDest,
                   /*! [in] The buffer to read from. Its size must be at least
                   sizeToWrite bytes. */
                   uint8_t *memSrc,
                   /*! [in] The number of bytes to write. */
                   uint32_t sizeToWrite
                   );

/*!
@brief This function compares sizeToRead bytes between flashAddress and the
buffer provided by expBuff.

@return \c zero on success.
@return A non-zero value on failure.
*/
int TE_flash_memCmp(
                    /*! [in] The flash address to compare to. */
                    CCAddr_t flashAddress,
                    /*! [in] The expected buffer. Its size must be at least
                    sizeToRead bytes. */
                    uint8_t *expBuff,
                    /*! [in] The number of bytes to compare. */
                    uint32_t sizeToRead,
                    /*! [in/out] User context. */
                    void* context
                    );
/*!
 @}
 */
#endif /* _CC71X_TEE_INTEGRATION_TE_FLASH_H */
