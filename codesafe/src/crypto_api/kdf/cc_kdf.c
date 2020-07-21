/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


#include "cc_kdf.h"
#include "cc_kdf_internal.h"

/************************ Public Functions ******************************/
/****************************************************************/
/*!
 @brief CC_KdfKeyDerivFunc performs key derivation according to one of the modes defined in standards:
       NIST 56A rev.3,  ANS X9.42-2001, ANS X9.63, ISO/IEC 18033-2.

The present implementation of the function allows the following operation modes:
<ul><li> CC_KDF_ASN1_DerivMode - mode based on ASN.1 DER encoding; </li>
<li> CC_KDF_NIST56A_ConcatDerivMode - according to NIST 56A rev.3; </li>
<li> CC_KDF_ConcatDerivMode - mode based on concatenation;</li>
<li> CC_KDF_X963_DerivMode = CC_KDF_ConcatDerivMode;</li>
<li> CC_KDF_ISO18033_KDF1_DerivMode, CC_KDF_ISO18033_KDF2_DerivMode - specific modes according to
ISO/IEC 18033-2 standard.</li></ul>

The purpose of this function is to derive a keying data from the shared secret value and some
other optional shared information, included in OtherInfo (SharedInfo).

\note All buffers arguments are represented in Big-Endian format.

@return CC_OK on success.
@return A non-zero value on failure as defined cc_kdf_error.h.
*/
CCError_t  CC_KdfKeyDerivFunc(
                    uint8_t              *pZzSecret,            /*!< [in]  A pointer to shared secret value octet string. */
                    size_t                zzSecretSize,         /*!< [in]  The size of the shared secret value in bytes.
                                                                           The maximal size is defined as: ::CC_KDF_MAX_SIZE_OF_SHARED_SECRET_VALUE. */
                    CCKdfOtherInfo_t     *pOtherInfo,           /*!< [in]  A pointer to the structure, containing pointers to the data, shared by
									                                       two entities of agreement, depending on KDF mode:
                                                                               1. On NIST 56A rev.3 and KDF ASN1 concatenation modes OtherInfo includes
                                                                                  AlgorithmID and some optional data entries as described in the standards;
                                                                               2. On both ISO18033-2 KDF1, KDF2 modes this parameter is ignored and may
                                                                                  be set to NULL;
                                                                               3. On other modes it is optional and may be set to NULL. */
                    CCKdfHashOpMode_t     kdfHashMode,          /*!< [in]  The KDF identifier of hash function to be used. The hash function output
									   must be at least 160 bits. */
                    CCKdfDerivFuncMode_t  derivMode,            /*!< [in]  The enum value, specifies one of above described derivation modes. */
                    uint8_t              *pKeyingData,          /*!< [out] A pointer to the buffer for derived keying data. */
                    size_t                keyingDataSize        /*!< [in]  The size in bytes of the keying data to be derived.
                                                                           The maximal size is defined as :: CC_KDF_MAX_SIZE_OF_KEYING_DATA. */
)

{
    return kdfKeyDerivFunc(pZzSecret,
                           zzSecretSize,
                           pOtherInfo,
                           kdfHashMode,
                           derivMode,
                           pKeyingData,
                           keyingDataSize);

}
