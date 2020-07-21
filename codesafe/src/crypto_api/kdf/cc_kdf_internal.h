/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _CC_KDF_INTERNAL_H
#define _CC_KDF_INTERNAL_H

#ifdef __cplusplus
extern "C"
{
#endif


#include "cc_kdf_defs.h"


/*!
 @file
 @brief This file contains KDF definitions.
 */

 /*!
 @addtogroup cc_kdf_defs
 @{
     */


/************************ Defines ******************************/
/*! Shared secret value max size in bytes */
#define  CC_KDF_MAX_SIZE_OF_SHARED_SECRET_VALUE  1024

/* Count and max. sizeof OtherInfo entries (pointers to data buffers) */
/*! Number of other info entries. */
#define  CC_KDF_COUNT_OF_OTHER_INFO_ENTRIES   5

/*! Size of KDF counter in bytes */
#define CC_KDF_COUNTER_SIZE_IN_BYTES  4

/************************ Internal Functions **********************/

/*!
 @brief kdfKeyDerivFunc performs key derivation according to one of the modes defined in standards:
        NIST 800-56Ar3, NIST 800-56Cr1, ANS X9.42-2001, ANS X9.63, ISO/IEC 18033-2.

The present implementation of the function allows the following operation modes:
<ul>
<li> CC_KDF_NIST56A_ConcatDerivMode - mode based on concatenation;</li>
<li> CC_KDF_ConcatDerivMode (ANS X9.42) - mode based on concatenation;</li>
<li> CC_KDF_ASN1_DerivMode - mode based on  ASN.1 DER encoding; </li>
<li> CC_KDF_X963_DerivMode = CC_KDF_ConcatDerivMode;</li>
<li> CC_KDF_ISO18033_KDF1_DerivMode, CC_KDF_ISO18033_KDF2_DerivMode -
specific modes according to ISO/IEC 18033-2 standard.</li></ul>

The purpose of this function is to derive a keying data from the shared secret value and some
other optional shared information, included in shared OtherInfo (FixedInfo).

\note All buffer- data is represented in big-endianness format.

@return CC_OK on success.
@return A non-zero value on failure as defined cc_kdf_error.h.
*/
CCError_t  kdfKeyDerivFunc(
        uint8_t              *pZzSecret,            /*!< [in]  A pointer to shared secret value octet string. */
        size_t                zzSecretSize,         /*!< [in]  The size of the shared secret value in bytes.
                                                               The maximal size is defined as: ::CC_KDF_MAX_SIZE_OF_SHARED_SECRET_VALUE. */
        CCKdfOtherInfo_t     *pOtherInfo,           /*!< [in]  A pointer to the structure, containing pointers to the data, shared by
                                                               two entities of agreement, depending on KDF mode:
                                                               1. On KDF ASN1 and NIST 56A concatenation modes OtherInfo includes AlgorithmID
                                                                  and some optional data entries as described in the standards;
                                                               2. On other modes AlgorithmID is optional and may be set to NULL. */
        CCKdfHashOpMode_t     kdfHashMode,          /*!< [in]  The KDF identifier (enum) of hash function to be used. */
        CCKdfDerivFuncMode_t  derivMode,            /*!< [in]  The enum value, specifies the key derivation mode. */
        uint8_t              *pKeyingData,          /*!< [out] A pointer to the buffer for derived keying data. */
        size_t                keyingDataSize        /*!< [in]  The size in bytes of the keying data to be derived.
                                                               The maximal size is defined as :: CC_KDF_MAX_SIZE_OF_KEYING_DATA. */
);

#ifdef __cplusplus
}
#endif
/*!
 @}
 */
#endif /* _CC_KDF_INTERNAL_H */
