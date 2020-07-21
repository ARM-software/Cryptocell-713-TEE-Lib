/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


#ifndef _SECDEBUG_DEFS_H
#define _SECDEBUG_DEFS_H

#include "secdebug_api.h"
#include  "cc_certificate_defs.h"

#define CC_BSV_SEC_DEBUG_DCU_SIZE_IN_BITS   128
#define CC_BSV_SEC_DEBUG_DCU_SIZE_IN_BYTES   (CC_BSV_SEC_DEBUG_DCU_SIZE_IN_BITS/CC_BITS_IN_BYTE)
#define CC_BSV_SEC_DEBUG_DCU_SIZE_IN_WORDS   (CC_BSV_SEC_DEBUG_DCU_SIZE_IN_BITS/CC_BITS_IN_32BIT_WORD)

/*! Defines SOC ID */
typedef uint8_t        SocId_t[CC_BSV_SEC_DEBUG_SOC_ID_SIZE];
/*! Defines DCU */
typedef uint32_t       Dcu_t[CC_BSV_SEC_DEBUG_DCU_SIZE_IN_WORDS];


/*! Certificate debug enabler magic number. */
#define CC_CERT_SEC_DEBUG_ENABLER_MAGIC 	0x5364656E
/*! Certificate debug developer magic number. */
#define CC_CERT_SEC_DEBUG_DEVELOPER_MAGIC 	0x53646465

/********* Certificate structure definitions ***********/

// All certificate header flags, first 4 bits are for certificate type,
// next 4 bits are rsa algorithm used.
// for  key certificate and enabler certificate next 4 bits are HBK-id used

/* Enabler certificate definitions */
typedef union {
    struct {
        uint32_t      hbkId:4; // must be first
        uint32_t      lcs:4;
        uint32_t      isRma:4;
        uint32_t      reserved:20;
    }flagsBits;
    uint32_t      flagsWord;
} EnablerCertFlags_t;

/* definition for enabler certificate */
typedef struct {
    Dcu_t      	debugMask;
    Dcu_t      	debugLock;
    CCHashResult_t		nextPubKeyHash;
} EnablerCertMain_t;

typedef struct {
    CCSbCertHeader_t	certHeader;
    CCSbNParams_t 		certPubKey;
    EnablerCertMain_t	certBody;
    CCSbSignature_t      	certSign;
} EnablerCert_t;

/* Developer certificate definitions */
typedef struct {
    struct {
        uint32_t      reserved:32;
    }flagsBits;
    uint32_t      flagsWord;
} DeveloperCertFlags_t;

typedef struct {
    Dcu_t      	debugMask;
    SocId_t         socId;
} DeveloperCertMain_t;

typedef struct {
    CCSbCertHeader_t	certHeader;
    CCSbNParams_t        certPubKey;
    DeveloperCertMain_t	certBody;
    CCSbSignature_t      	certSign;
} DeveloperCert_t;



/*!  MAX size of certificate pkg. */
#ifdef CC_SB_X509_CERT_SUPPORTED
#define CC_SB_MAX_ENABLER_CERT_SIZE_IN_BYTES	(0x500UL)
#define CC_SB_MAX_DEVELOPER_CERT_SIZE_IN_BYTES	(0x500UL)
#else
#define CC_SB_MAX_ENABLER_CERT_SIZE_IN_BYTES	(sizeof(EnablerCert_t))
#define CC_SB_MAX_DEVELOPER_CERT_SIZE_IN_BYTES	(sizeof(DeveloperCert_t))
#endif

#define CC_SB_MAX_ENABLER_CERT_BODY_SIZE_IN_BYTES	(sizeof(EnablerCertMain_t))
#define CC_SB_MAX_DEVELOPER_CERT_BODY_SIZE_IN_BYTES	(sizeof(DeveloperCertMain_t))

#define CC_SB_MAX_CERT_PKG_SIZE_IN_BYTES	(CC_SB_MAX_KEY_CERT_SIZE_IN_BYTES+CC_SB_MAX_ENABLER_CERT_SIZE_IN_BYTES+CC_SB_MAX_DEVELOPER_CERT_SIZE_IN_BYTES)

/* check reset over-ride */
#ifdef CC_IOT
    #define DCU_RESET_OVERRIDE_BIT_SHIFT	(0)
    #define BSV_SDER_HANDLE(dcuVal) do {} while(0)
#else
    #define DCU_RESET_OVERRIDE_BIT_SHIFT    (31)
    /* check SDER */
    #define DCU_SDER_BIT_SHIFT    (29)
    #define DCU_SDER_BIT_SIZE     0x2
    #define DCU_SDER_MASK     (((1<<DCU_SDER_BIT_SIZE)-1)<<DCU_SDER_BIT_SHIFT)
    #define IS_DCU_SDER_ON(dcuVal)   (dcuVal & DCU_SDER_MASK)
    #define BSV_SDER_HANDLE(dcuVal) do { \
        if (IS_DCU_SDER_ON(dcuVal)) { \
           CC_PalSetSder((dcuVal & DCU_SDER_MASK)>>DCU_SDER_BIT_SHIFT); \
        } \
    } while(0)
#endif

#define DCU_RESET_OVERRIDE_BIT_SIZE	0x1
#define DCU_RESET_OVERRIDE_MASK     (((1U<<DCU_RESET_OVERRIDE_BIT_SIZE)-1)<<DCU_RESET_OVERRIDE_BIT_SHIFT)
#define IS_DCU_RESET_OVERRIDE(dcuVal)   (dcuVal&DCU_RESET_OVERRIDE_MASK)


#define CLEAR_ALL_DCU(dcuVal) {\
        dcuVal[0] = DCU_DISABLE_ALL_DBG; \
        dcuVal[1] = DCU_DISABLE_ALL_DBG; \
        dcuVal[2] = DCU_DISABLE_ALL_DBG; \
        dcuVal[3] = DCU_DISABLE_ALL_DBG; \
}

#define LOCK_ALL_DCU(dcuLock) {\
        dcuLock[0] = DCU_ENABLE_ALL_DBG; \
        dcuLock[1] = DCU_ENABLE_ALL_DBG; \
        dcuLock[2] = DCU_ENABLE_ALL_DBG; \
        dcuLock[3] = DCU_ENABLE_ALL_DBG; \
}


#define WRITE_DCU_LOCK(hwBaseAddress, dcuLock, rc) {\
        uint32_t ii = 0;\
        uint32_t rr = 0;\
        for (ii = 0; ii < CC_BSV_SEC_DEBUG_DCU_SIZE_IN_WORDS; ii++) {\
            SB_HAL_WRITE_REGISTER(SB_REG_ADDR(hwBaseAddress, HOST_DCU_LOCK0) + ii * sizeof(uint32_t), dcuLock[ii]); \
            SB_HAL_READ_REGISTER(SB_REG_ADDR(hwBaseAddress,HOST_DCU_LOCK0) + ii * sizeof(uint32_t), rr);       \
            if(rr!=dcuLock[ii]) { \
                rc = CC_BSV_AO_WRITE_FAILED_ERR; \
            } \
        }\
}

#define WRITE_VERIFY_DCU_VAL(hwBaseAddress, dcuVal, dcuLock, rc) {\
        uint32_t ii = 0;\
        uint32_t jj = 0;\
        uint32_t dcuReadVal = 0; \
        uint32_t regVal = 0; \
        for (ii = 0; ii < CC_BSV_SEC_DEBUG_DCU_SIZE_IN_WORDS; ii++) {\
            SB_HAL_READ_REGISTER(SB_REG_ADDR(hwBaseAddress, AO_PERMANENT_DISABLE_MASK0) + ii * sizeof(uint32_t), regVal);       \
            dcuVal[ii] &= regVal;\
            SB_HAL_WRITE_REGISTER(SB_REG_ADDR(hwBaseAddress, HOST_DCU_EN0) + ii * sizeof(uint32_t), dcuVal[ii]); \
            CC_BSV_WAIT_ON_NVM_IDLE_BIT(hwBaseAddress); \
            SB_HAL_READ_REGISTER(SB_REG_ADDR(hwBaseAddress, HOST_DCU_EN0) + ii * sizeof(uint32_t), dcuReadVal);       \
            if (dcuReadVal != dcuVal[ii]) {\
                for (jj = 0; jj < CC_BSV_SEC_DEBUG_DCU_SIZE_IN_WORDS; jj++) {\
                    SB_HAL_WRITE_REGISTER(SB_REG_ADDR(hwBaseAddress, HOST_DCU_EN0) + jj * sizeof(uint32_t), DCU_DISABLE_ALL_DBG); \
                    dcuLock[jj] = DCU_ENABLE_ALL_DBG; \
                    CC_BSV_WAIT_ON_NVM_IDLE_BIT(hwBaseAddress); \
                }\
                rc = CC_BSV_AO_WRITE_FAILED_ERR; \
                break;\
            }\
        }\
}

#ifdef CC_IOT
#define READ_DCU_LOCK_DEFAULT(hwBaseAddress, dcuLock, rc) \
do {\
    uint32_t ii; \
    for (ii = 0; ii<CC_OTP_DCU_SIZE_IN_WORDS; ii++) { \
        rc = CC_BsvOTPWordRead(hwBaseAddress, (CC_OTP_DCU_OFFSET+ii), &dcuLock[ii]); \
        if (rc != CC_OK) { \
            break;\
        } \
    }  \
} while(0)
#else
#ifdef CC_CONFIG_BSV_CC712_SUPPORTED
#define READ_DCU_LOCK_DEFAULT(hwBaseAddress, dcuLock, rc) \
do {\
    uint32_t ii; \
    for (ii = 0; ii<CC_OTP_DCU_SIZE_IN_WORDS; ii++) { \
        dcuLock[ii] = DCU_ENABLE_ALL_DBG; \
    }  \
    CC_BSV_IRR_OTP_ERR_GET(hwBaseAddress, rc); \
    rc = (rc == 1) ? CC_BSV_OTP_ACCESS_ERR : CC_OK; \
} while(0)
#else
#define READ_DCU_LOCK_DEFAULT(hwBaseAddress, dcuLock, rc) \
do {\
    uint32_t ii; \
    for (ii = 0; ii<CC_OTP_DCU_SIZE_IN_WORDS; ii++) { \
        CC_BSV_READ_OTP_WORD(hwBaseAddress, (CC_OTP_DCU_OFFSET+ii), dcuLock[ii], rc); \
        if (rc != CC_OK) { \
            break;\
        } \
    }  \
} while(0)
#endif
#endif
#endif


CCError_t CCCertSecDbgParse(uint32_t   *pDebugCertPkg,
                            uint32_t   certPkgSize,
                            BufferInfo32_t  *pKeyCert,       // out
                            BufferInfo32_t  *pEnablerCert,   // out
                            BufferInfo32_t  *pDeveloperCert); // out





