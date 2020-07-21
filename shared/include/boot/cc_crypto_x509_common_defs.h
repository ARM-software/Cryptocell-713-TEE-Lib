/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _CC_CRYPTO_X509_COMMON_DEFS_H
#define _CC_CRYPTO_X509_COMMON_DEFS_H

/*!
@file
@brief This file contains definitions used in the X509 certificates.
*/

/*!
 @addtogroup cc_x509_defs
 @{
     */


/*!  Maximum size of issuer name string. */
#define X509_ISSUER_NAME_MAX_STRING_SIZE     64
/*!  Maximum size of subject name string. */
#define X509_SUBJECT_NAME_MAX_STRING_SIZE    64
/*!  Maximum size of  validity period string. */
#define X509_VALIDITY_PERIOD_MAX_STRING_SIZE  16
/*! Maximum size of the data buffer of a single user. */
#define X509_USER_DATA_MAX_SIZE_BYTES	      64

/*!
 @}
 */
#endif
