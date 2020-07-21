/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


#ifndef _SECBOOT_CERT_DEFS_H
#define _SECBOOT_CERT_DEFS_H

#include "cc_certificate_defs.h"
#include "cc_address_defs.h"
#include "bootimagesverifier_def.h"


/********* Certificate structure definitions ***********/



/* All certificate header flags, first 4 bits are for certificate type,
    next 4 bits are RSA algorithm used.
    for  key certificate and enabler certificate next 4 bits are HBK-id used */

/* Content certificate definitions */
/*! Content Certificate flag bit field structure. */
typedef union {
    /*! Flags definitions in bits.*/
    struct {
        uint32_t      hbkId:4;
        uint32_t      swCodeEncType:4;
        uint32_t      swLoadVerifyScheme:4;
        uint32_t      swCryptoType:4;
        uint32_t      numOfSwCmp:16;
    }flagsBits;
    /*! Flags definition as a word.*/
    uint32_t            flagsWord;
} CCSbCertFlags_t;

typedef struct {
    CCHashResult_t      imageHash;
    CCImageAddrWidth_t  dstAddr;
    uint32_t 	        imageSize;
    uint32_t 	        isAesCodeEncUsed;
} ContentCertImageRecord_t;

typedef struct {
    uint32_t            nvCounter;
    CCSbNonce_t         nonce;
    ContentCertImageRecord_t    imageRec[CC_SB_MAX_NUM_OF_IMAGES];
} ContentCertMain_t;

#define CONTENT_CERT_MAIN_SIZE_IN_BYTES   (sizeof(uint32_t) + sizeof(CCSbNonce_t) + SW_REC_SIGNED_DATA_SIZE_IN_BYTES*CC_SB_MAX_NUM_OF_IMAGES)

/*! SW component additional parameters. */
typedef struct {
    CCImageAddrWidth_t  srcAddr;
}CCSbSwImgAddData_t;

typedef struct {
    CCSbCertHeader_t    certHeader;
    CCSbNParams_t       certPubKey;
    ContentCertMain_t   certBody;
    CCSbSignature_t     certSign;
} ContentCert_t;

#define CONTENT_CERT_SIZE_IN_BYTES   (sizeof(CCSbCertHeader_t) + sizeof(CCSbNParams_t) + CONTENT_CERT_MAIN_SIZE_IN_BYTES + sizeof(CCSbSignature_t))

/*!  MAX size of certificate pkg - may contain up to 16 signed sw images. */
#ifdef CC_SB_X509_CERT_SUPPORTED
#define CC_SB_MAX_CONTENT_CERT_SIZE_IN_BYTES        (0x800UL)
#else
#define CC_SB_MAX_CONTENT_CERT_SIZE_IN_BYTES        CONTENT_CERT_SIZE_IN_BYTES
#endif

#define CC_SB_MAX_CONTENT_CERT_BODY_SIZE_IN_BYTES   CONTENT_CERT_MAIN_SIZE_IN_BYTES

#define CC_SB_MAX_CONTENT_PKG_SIZE_IN_BYTES         (CC_SB_MAX_CONTENT_CERT_SIZE_IN_BYTES + SW_REC_NONE_SIGNED_DATA_SIZE_IN_BYTES*CC_SB_MAX_NUM_OF_IMAGES)

#endif


