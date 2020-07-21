/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

/*!
@file
@brief This file contains X509 user-defined functions and related data structures.
*/

/*!
 @addtogroup sb_pal_functions
 @{
     */

#ifndef _CC_PAL_X509_DEFS_H
#define _CC_PAL_X509_DEFS_H



#ifdef __cplusplus
extern "C"
{
#endif

#include "cc_pal_types.h"
#include "cc_crypto_x509_common_defs.h"


/*!
@brief This function checks validity period. You should implement it.
       It receives start and end validity period as input. It also receives an indication flag for each period. If the flag is not 1,
       the value of current period was not defined by the user.

@return \c CC_OK on success.
@return A non-zero value on failure.
*/
uint32_t CC_PalVerifyCertValidity(char *pNotBeforeStr, /*!< [in] Pointer to the start period string. */
	uint32_t notBeforeStrSize, /*!< [in] Size of the start period string. */
	uint8_t notBeforeStrFlag, /*!< [in] Start period definition flag indication. */
	char *pNotAfterStr,/*!< [in] Pointer to the end period string. */
	uint32_t notAfterStrSize,/*!< [in] Size of the end period string. */
	uint8_t notAfterStrFlag /*!< [in] Start period definition flag indication. */);


/*! X509 Data of the certificate user. This data is outputted after the certificate passed validation.
*/
typedef struct {
	uint8_t   setSerialNum;                                   /*!< Definition flag of certificate serial number. */
	uint32_t  serialNum;                                      /*!< Value of certificate serial number. */
	uint8_t   setIssuerName;                                  /*!< Definition flag of certificate issuer name. */
	char      IssuerName[X509_ISSUER_NAME_MAX_STRING_SIZE+1];   /*!< String of certificate issuer name. */
	uint8_t   setSubjectName;                                 /*!< Definition flag of certificate subject name. */
	char      SubjectName[X509_SUBJECT_NAME_MAX_STRING_SIZE+1]; /*!< String of certificate subject name. */
	uint8_t   setNotBeforeStr;                                /*!< Definition flag of start validity period.  */
	char      NotBeforeStr[X509_VALIDITY_PERIOD_MAX_STRING_SIZE+1]; /*!< String of start validity period. */
	uint8_t   setNotAfterStr;                                     /*!< Definition flag of end validity period.  */
	char      NotAfterStr[X509_VALIDITY_PERIOD_MAX_STRING_SIZE+1]; /*!< String of end validity period. */
#ifdef CC_SB_CERT_USER_DATA_EXT
	uint8_t   userData[X509_USER_DATA_MAX_SIZE_BYTES*3];	       /*!< Byte array containing the user data from the certificate, which is only valid if the code was
									   compiled with CC_CONFIG_SB_CERT_USER_DATA_EXT = 1.
									   This structure is used by both Secure Debug and Secure Boot. For Secure Debug
									   there are 3 buffers of user's data: key, enabler certificate, and developer certificate. */
#endif
}CCX509CertHeaderInfo_t;

#ifdef __cplusplus
}
#endif
/*!
@}
 */
#endif





