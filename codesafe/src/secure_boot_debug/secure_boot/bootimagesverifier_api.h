/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _BOOT_IMAGES_VERIFIER_API_H
#define _BOOT_IMAGES_VERIFIER_API_H


#ifdef __cplusplus
extern "C"
{
#endif


/*!
@file
@brief This file contains the set of Secure Boot APIs.

@defgroup cc_biv_api CryptoCell Secure Boot APIs
@{
@ingroup cc_sb_sd
*/

#include "secureboot_defs.h"
#include "cc_pal_types_plat.h"


/*----------------------------
      PUBLIC FUNCTIONS
-----------------------------------*/

/*!
@brief This function initializes the Secure Boot certificate chain process.

It initializes the structure that holds the state of the certificate chain.

@note This must be the first API called when processing the Secure Boot certificate chain.

@return \c CC_OK on success.
@return A non-zero value from bootimagesverifier_error.h on failure.
*/
CCError_t CC_SbCertChainVerificationInit(
    CCSbCertInfo_t *certPkgInfo     /*!< [in/out] A pointer to the structure
	that holds the state of the certificate chain. */
    );

/*!
@brief This function verifies a single key or content certificate.

It verifies the following:
    <ul><li>The public key that is saved in the certificate, against its
	hash that is either found in the OTP memory (Hbk) or in \p certPkgInfo.</li>
    <li>The RSA signature of the certificate.</li>
    <li>That the NV counter in the certificate is higher than, or equal to,
	the minimum NV counter, as recorded on the device and passed in \p certPkgInfo.</li>
    <li>Each SW module against its hash in the certificate, for content certificates.</li></ul>

@return \c CC_OK on success.
@return A non-zero value from bootimagesverifier_error.h on failure.
*/
CCError_t CC_SbCertVerifySingle(
    CCSbFlashReadFunc flashReadFunc, /*!< [in] A pointer to the flash read function. */
    void *userContext,               /*!< [in] An additional pointer for flash read usage. May be NULL. */
    unsigned long hwBaseAddress,     /*!< [in] The base address of the CryptoCell HW registers. */
    CCAddr_t certSrcAddress,         /*!< [in] The flash address where the certificate is located. This address is provided to \p flashReadFunc. */
    CCSbCertInfo_t *certPkgInfo,     /*!< [in/out] A pointer to the structure that holds the state of the certificate chain. */
    CCSbX509TBSHeader_t *pX509Header,/*!< [in/out] A pointer to X509 TBS header info.
                                          - For proprietary format, this parameter is NA.
                                          - For x509 format: this parameter is optional. If pX509Header->pBuffer points to legal buffer (not NULL),
                                            the x509 TBS header info will be copied to it. */
    uint32_t *pWorkspace,            /*!< [in] A buffer for internal use by the function. */
    uint32_t workspaceSize,          /*!< [in] The size of the workspace, in bytes. Must be at least \c CC_SB_MIN_WORKSPACE_SIZE_IN_BYTES. */
    CCSbImagesInfo_t *pImagesInfo,   /*!< [out] A pointer to the information about the verified images, which includes addresses and sizes. */
    CCSbUserAddData_t  *pUserData    /*!< [out] Buffer holding the user additional data. The buffer is being used only
                                            CC_CONFIG_BSV_CERT_WITH_USER_ADDITIONAL_DATA compilation flag is set*/
    );

/*!
@brief This function changes the storage address of a specific SW image in the content certificate.
\note The certificate must be loaded to the RAM, and verified prior calling this function.
\note This API is not relevant for X509 SB solution.

@return \c CC_OK on success.
@return A non-zero value from bootimagesverifier_error.h on failure.
*/
CCError_t CC_SbSwImageStoreAddrChange(
    uint32_t *pCert,                 /*!< [in] The certificate address (after it has been loaded to memory). */
    uint32_t maxCertSizeWords,       /*!< [in] The certificate boundaries - the maximal memory size allocated for the certificate in words . */
    CCAddr_t address,                /*!< [in] The new storage address to change to. */
    uint32_t indexOfAddress          /*!< [in] The index of the SW image in the content certificate, starting from 0. */
    );

/*!
@brief This function returns the size in words of a certificate.
\note The certificate (or part of it which includes the header) should be loaded to the RAM prior calling this function.
\note This API is not relevant for X509 SB solution.

@return CC_OK   On success.
@return A non-zero value from bootimagesverifier_error.h on failure.
*/
CCError_t CC_SbGetCertSize(
    CCSbCertChainType_t chainType,   /*!< [in] The certificate chain type: CC_SECURE_BOOT_CHAIN / CC_SECURE_DEBUG_CHAIN */
    uint32_t *pCert,                 /*!< [in] The certificate address (after it has been loaded to memory). */
    uint32_t *pCertSizeWords         /*!< [in/out] A pointer to certificate size in words:
                                             - in: the size of the data which has been loaded to memory.
                                             - out: the actual certificate size. */
    );

#ifdef __cplusplus
}
#endif

#endif

/**
 @}
 */

