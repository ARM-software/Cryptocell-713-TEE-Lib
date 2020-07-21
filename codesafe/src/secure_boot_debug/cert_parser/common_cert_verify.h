/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


#ifndef _COMMON_CERT_VERIFY_H
#define _COMMON_CERT_VERIFY_H

#include "cc_pal_types.h"
#include "cc_certificate_defs.h"
#include "secureboot_defs.h"

/* The function validates the certificate header - Magic number , type and version. */
CCError_t CCCertValidateHeader(CCSbCertHeader_t *pCertHeader,
                                      CCSbCertTypes_t *pCertType);

/**
   @brief This function is used for basic verification of all Secure Boot/Debug certificates.
   it verifies type, size, public key and signature.
   The function returns pointers to certificate proprietary header, and body.
   The function:
   1. calls CCCertFieldsParse() - according to certificate type(x509 or not),
                copy public key, Np and signature to workspace,
                and returns pointers to certificate proprietary header, and body.
   2. Calls CCCertValidateHeader(), and verify cert type (as expected) and size (according to type).
   3. If expected public key hash is NULL, call CC_BsvPubKeyHashGet() with HBK type defined in certificate to get OTP HBK
   4. Calls verifyCertPubKeyAndSign() To verify public key and certificate RSA signature.
 */
CCError_t CCCommonCertVerify(unsigned long   hwBaseAddress,
                             BufferInfo32_t  *pCertInfo,
                             CertFieldsInfo_t  *pCertFields,  // in/out
                             CCSbCertInfo_t  *pSbCertInfo,   //in/out
                             BufferInfo32_t  *pWorkspaceInfo,
                             CCSbX509TBSHeader_t  *pX509HeaderInfo,
                             CCSbUserAddData_t  *pUserAddData);


/**
   @brief This function verifies key certificate specific fields.
 */
uint32_t CCCommonKeyCertVerify(unsigned long   hwBaseAddress,
                               uint8_t  *pCertMain,
                               CCSbCertInfo_t *pCertPkgInfo);

/**
   @brief This function copy N, Np (CCSbNParams_t) and signature
   (certificate start address + sizeof certificate in certificate header) from the certificate to workspace.
   Return pointer to certificate header CCSbCertHeader_t, and pointer to cert body sizeof()
 */
CCError_t CCCertFieldsParse(BufferInfo32_t  *pCertInfo,
                            BufferInfo32_t  *pWorkspaceInfo,
                            CertFieldsInfo_t  *pCertFields,
                            uint32_t    **ppCertStartSign,
                            uint32_t    *pCertSignedSize,
                            CCSbX509TBSHeader_t  *pX509HeaderInfo);

#endif /* _COMMON_CERT_VERIFY_H */


