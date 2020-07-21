/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _CC_CERTIFICATE_DEFS_H
#define _CC_CERTIFICATE_DEFS_H

#include "cc_address_defs.h"
#include "rsa_bsv.h"
#include "cc_sec_defs.h"
#ifdef CC_CONFIG_BSV_CERT_WITH_USER_ADDITIONAL_DATA
#include "bootimagesverifier_def.h"
#endif

/*! Secure Boot key certificate magic number. "S,B,K,C" */
#define CC_SB_KEY_CERT_MAGIC_NUMBER	 	0x53426b63
/*! Secure Boot content certificate magic number.  "S,B,C,C" */
#define CC_SB_CONTENT_CERT_MAGIC_NUMBER     0x53426363

/********* Certificate structure definitions ***********/

/*! Definition of certificate address width, according to platform. */
typedef CCAddr_t        CCImageAddrWidth_t;

/*! Certificate types structure. */
typedef enum {
    /*! Reserved.*/
    CC_SB_MIN_CERT,
    /*! Key certificate. */
    CC_SB_KEY_CERT = 1,
    /*! Content certificate. */
    CC_SB_CONTENT_CERT = 2,
    /*! Key or content certificate. */
    CC_SB_KEY_OR_CONTENT_CERT = 3,
    /*! Debug enabler certificate. */
    CC_SB_ENABLER_CERT = 4,
    /*! Debug developer certificate. */
    CC_SB_DEVELOPER_CERT = 5,
    /*! Max number of certificates types.*/
    CC_SB_MAX_CERT,
    /*! Reserved.*/
    CC_SB_CERT_TYPE_LAST = 0x7FFFFFFF

} CCSbCertTypes_t;

/*! Certificate types structure. */
typedef enum {
    /*! First certificate in chain.*/
    CC_SB_FIRST_CERT_IN_CHAIN = 0,
    /*! Second certificate in chain.*/
    CC_SB_SECOND_CERT_IN_CHAIN = 1,
    /*! Third and last certificate in chain.*/
    CC_SB_THIRD_CERT_IN_CHAIN = 2,
    /*! Last certificate in chain.*/
    CC_SB_LAST_CERT_IN_CHAIN = 3,
    /*! Reserved.*/
    CC_SB_RESERVED_CERT_IN_CHAIN = 0x7FFFFFFF

} CCSbCertOrderInChain_t;

typedef struct {
        uint32_t   *pBuffer;
        uint32_t   bufferSize;
} BufferInfo32_t;

/*! Signature structure. */
typedef struct {
    uint32_t sig[BSV_CERT_RSA_KEY_SIZE_IN_WORDS];               /*!< RSA PSS signature. */
}CCSbSignature_t;

/*! Certificate header structure. */
typedef struct {
#ifdef CC_CONFIG_BSV_CERT_WITH_USER_ADDITIONAL_DATA
    CCSbUserAddData_t userAddData; /*!< User additional data. */
#endif
    uint32_t magicNumber; /*!< Magic number to validate the certificate. */
    uint32_t certVersion; /*!< Certificate version to validate the certificate. */
    uint32_t certSize; /*!< Offset in words to the Certificate signature.
                             And number of SW components , if any exist.*/
    uint32_t certFlags; /*!< Bit field according to certificate type */
} CCSbCertHeader_t;

/* IMPORATNT NOTE:  The certificate body may not be word aligned.
   For proprietary it is aligned but for x.509 we can not guarantee that */
typedef struct {
        CCSbCertTypes_t certType;
        CCSbCertHeader_t certHeader;
        uint8_t     *pCertBody;
        uint32_t certBodySize;
} CertFieldsInfo_t;

/* All certificate header flags, first 4 bits are for certificate type,
 next 4 bits are rsa algorithm used.
 for  key certficate and enabler ecrtificate next 4 bits are HBK-id used */

/* Key certificate definitions */
typedef union {
    struct {
        uint32_t hbkId :4;  // must be first
        uint32_t reserved :28;
    } flagsBits;
    uint32_t flagsWord;
} keyCertFlags_t;

typedef struct {
    uint32_t nvCounter;
    CCHashResult_t nextPubKeyHash;
} KeyCertMain_t;

typedef struct {
    CCSbCertHeader_t certHeader;
    CCSbNParams_t certPubKey;
    KeyCertMain_t certBody;
    CCSbSignature_t certSign;
} KeyCert_t;


/*!  MAX size of certificate pkg. */
#ifdef CC_SB_X509_CERT_SUPPORTED
#define CC_SB_MAX_KEY_CERT_SIZE_IN_BYTES	(0x500UL)
#define CC_SB_MAX_CERT_SIGN_SIZE_IN_BYTES               (0x1D0)
#else
#define CC_SB_MAX_KEY_CERT_SIZE_IN_BYTES	(sizeof(KeyCert_t))
#define CC_SB_MAX_CERT_SIGN_SIZE_IN_BYTES               (sizeof(CCSbSignature_t))
#endif

#define CC_SB_MAX_KEY_CERT_BODY_SIZE_IN_BYTES	(sizeof(KeyCertMain_t))

/*! Definition of NV counter as defined in the certificate NV counter word. */
#ifndef CC_IOT

/* NV counter revocation as defined for each certificate */
typedef union {
    struct {
        uint32_t nvCounterValue :16;
        uint32_t nvCounterId    :16;
    } nvCounterBits;
    uint32_t nvCounterWord;
} nvCounter_t;

#endif

#endif

