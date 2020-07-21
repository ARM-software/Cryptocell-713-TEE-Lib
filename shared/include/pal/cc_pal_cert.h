/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef  _CC_PAL_CERT_H
#define  _CC_PAL_CERT_H

/*!
@file
@brief This file contains definitions that are used by the CERT related APIs. The implementation of these functions
needs to be replaced according to the Platform and TEE_OS.
*/

/*!
 @addtogroup cc_pal_cert
 @{
*/

#include "cc_pal_types_plat.h"

/**
 * @brief Gets the CERT state.
 *
 *
 * @return Zero on success.
 * @return A non-zero value on failure.
 */
CCError_t CC_PalCertGetState(uint32_t *pCertState /*!< [in] The address of the buffer to map. */);


/**
 * @brief Gets the CERT error.
 *
 *
 * @return Zero on success.
 * @return A non-zero value on failure.
 */
CCError_t CC_PalCertGetError(uint32_t *pCertError);


/**
 * @brief Gets the CERT trace.
 *
 *
 * @return Zero on success.
 * @return A non-zero value on failure.
 */
CCError_t CC_PalCertGetTrace(uint32_t *pCertTrace);


/**
 * @brief Sets the CERT state.
 *
 *
 * @return Zero on success.
 * @return A non-zero value on failure.
 */
CCError_t CC_PalCertSetState(uint32_t certState);


/**
 * @brief Sets the CERT error.
 *
 *
 * @return Zero on success.
 * @return A non-zero value on failure.
 */
CCError_t CC_PalCertSetError(uint32_t certError);


/**
 * @brief Sets the CERT trace.
 *
 *
 * @return Zero on success.
 * @return A non-zero value on failure.
 */
CCError_t CC_PalCertSetTrace(uint32_t certTrace);

/*!
 @}
 */

#endif  // _CC_PAL_CERT_H

