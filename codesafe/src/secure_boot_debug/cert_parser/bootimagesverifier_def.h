/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

/*!
 @file
 @brief This file contains definitions used for the Secure Boot and Secure Debug APIs.
 */



 /*!
 @addtogroup cc_sb_image_verifier
 @{
 */

#ifndef _BOOT_IMAGES_VERIFIER_DEF_H
#define _BOOT_IMAGES_VERIFIER_DEF_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "cc_pal_types.h"
#include "cc_pka_hw_plat_defs.h"
/*! The size of the user additional data added to each certificate defined in bytes. */
#define BSV_CERT_USER_ADD_DATA_SIZE_IN_BYTES   64
 /*! The size of additional data defined in words.*/
#define BSV_CERT_USER_ADD_DATA_SIZE_IN_WORDS   (BSV_CERT_USER_ADD_DATA_SIZE_IN_BYTES/CC_32BIT_WORD_SIZE)

/*! Definition of a buffer used for user additional data. */
typedef uint32_t CCSbUserAddData_t[BSV_CERT_USER_ADD_DATA_SIZE_IN_WORDS];

/*! Definition of a structure holding the user additional data in a certificate chain. */
typedef struct {
    CCSbUserAddData_t userData1;  /*!< Additional data in the first certificate in the chain. */
    CCSbUserAddData_t userData2;  /*!< Additional data in the second certificate in the chain. */
    CCSbUserAddData_t userData3;  /*!< Additional data in the third certificate in the chain. */
}BsvCertUserAddData_t;

/*! The maximal number of software images per content certificate. */
#define CC_SB_MAX_NUM_OF_IMAGES 16

/*! The maximal size of the certificate, in bytes.*/
#ifdef CC_SB_X509_CERT_SUPPORTED
#define CC_SB_MAX_CERT_SIZE_IN_BYTES    (0xB10)
#else
#define CC_SB_MAX_CERT_SIZE_IN_BYTES    (0x700)
#endif

/*! The maximal size of the Secure Boot certificate, in words.*/
#define CC_SB_MAX_CERT_SIZE_IN_WORDS    (CC_SB_MAX_CERT_SIZE_IN_BYTES/CC_32BIT_WORD_SIZE)

/*! The Secure Debug maximal workspace size, in bytes.
    This workspace is used to store the RSA parameters, such as the modulus and signature.
*/
#define CC_BSV_PSS_WORKSPACE_SIZE_IN_BYTES   (4*BSV_CERT_RSA_KEY_SIZE_IN_BYTES +\
                                              2*RSA_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_BYTES)

/*!
 @brief The minimal size of the Secure Boot workspace in bytes.

 When not loading images to memory, the Secure Boot APIs use a temporary workspace for
 processing the data that is read from the flash. This workspace must be large enough
 to accommodate the size of the certificates, and twice the size of the data that is
 read from flash in each processing round. However, when loading images to memory, the
 destination memory itself serves as the workspace.\n

 The size that is read each round is defined by \c CC_CONFIG_SB_IMAGES_OPTIMIZED_MEMORY_CHUNK_SIZE_IN_BYTES.
 The \c CC_CONFIG_SB_IMAGES_OPTIMIZED_MEMORY_CHUNK_SIZE_IN_BYTES value needs to be modeled
 for the specific system and allows the user to find a balance between the cycles needed to complete
 a flash read operation of that size and the cycles needed to process decryption operation on the
 same size. The value must not be larger than \c CC_SBRT_MAX_MLLI_SIZE.\n

 The definition of \c CC_SB_MIN_WORKSPACE_SIZE_IN_BYTES is comprised of \c CC_SB_IMAGES_WORKSPACE_SIZE_IN_BYTES
 and additional space for the certificate itself, which resides in the workspace at the same time the
 software images data is processed.\n

 It is assumed that the optimal size of the data to read in each processing round is 4KB, based on the
 standard flash-memory page size. Therefore, the size of the image workspace,
 \c CC_CONFIG_SB_IMAGES_WORKSPACE_SIZE_IN_BYTES, is defined by default as 8KB in the project configuration file.
 This can be changed to accommodate the optimal value in different environments.
 \c CC_SB_IMAGES_WORKSPACE_SIZE_IN_BYTES is defined by the Boot Services makefile as
 equal to \c CC_CONFIG_SB_IMAGES_WORKSPACE_SIZE_IN_BYTES.

 @note When you write code that uses the Secure Boot APIs, and includes the bootimagesverifier_def.h file,
 the value of \c CC_SB_IMAGES_WORKSPACE_SIZE_IN_BYTES must be defined by your makefile to be exactly
 the same value as was used when compiling the Secure Boot code, and \c CC_SB_X509_CERT_SUPPORTED
 must be defined in the Makefile, according to the definition of \c CC_CONFIG_SB_X509_CERT_SUPPORTED.\n \par

 @note The size of \c CC_SB_IMAGES_WORKSPACE_SIZE_IN_BYTES must be a multiple of the hash SHA-256 block size of 64 bytes.
*/
#define CC_SB_MIN_WORKSPACE_SIZE_IN_BYTES   (CC_SB_MAX_CERT_SIZE_IN_BYTES + \
                                             CC_MAX(CC_BSV_PSS_WORKSPACE_SIZE_IN_BYTES, CC_SB_IMAGES_WORKSPACE_SIZE_IN_BYTES))

#ifdef __cplusplus
}
#endif

#endif

/**
 @}
 */


