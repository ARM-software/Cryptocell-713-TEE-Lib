/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


#ifndef _SECDEBUG_API_H
#define _SECDEBUG_API_H

#ifdef __cplusplus
extern "C"
{
#endif

/*!
@file
@brief This file contains the Secure Debug APIs.
@defgroup cc_sd_api CryptoCell Secure Debug APIs
@{
@ingroup cc_sb_sd
*/

#include "cc_pal_types_plat.h"
#include "bootimagesverifier_def.h"

/*! SOC-id size. */
#define CC_BSV_SEC_DEBUG_SOC_ID_SIZE            0x20

/*----------------------------------
         PUBLIC FUNCTIONS
-----------------------------------*/

/*!
@brief This API enables and disables debugging through the DCU registers.

This is done according to the permissions given in the debug certificate, or by
predefined values.
For more information, see the relevant CryptoCell's Software Integrator's Manual.


@return \c CC_OK on success.
@return A non-zero value from bsv_error.h on failure. It is recommended that if CC_BSV_AO_WRITE_FAILED_ERR
      is returned the system will be set to FATAL error.
*/
CCError_t CC_BsvSecureDebugSet(
    unsigned long   hwBaseAddress,  /*!< [in] The base address of the CryptoCell HW registers. */
    uint32_t   *pDebugCertPkg,      /*!< [in] A pointer to the Secure Debug certificate package. May be NULL. */
    uint32_t   certPkgSize,         /*!< [in] The size of the certificate package, in bytes. */
    uint32_t   *pEnableRmaMode,     /*!< [out] The RMA entry flag. Non-zero indicates that RMA LCS entry is required. */
    uint32_t   *pWorkspace,         /*!< [in] A pointer to an internal buffer. */
    uint32_t   workspaceSize,        /*!< [in] The size of the internal buffer. The minimum size is \c CC_BSV_PSS_WORKSPACE_SIZE_IN_BYTES. */
    BsvCertUserAddData_t  *pUserData           /*!< [out] Buffer holding the user additional data. The buffer is being used only when
                                            CC_CONFIG_BSV_CERT_WITH_USER_ADDITIONAL_DATA compilation flag is set*/
);


#ifdef __cplusplus
}
#endif

#endif

/**
 @}
 */

