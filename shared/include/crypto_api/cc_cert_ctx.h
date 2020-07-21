/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _CC_CERT_CTX_H_
#define _CC_CERT_CTX_H_


/*!
@file
@brief This file contains definitions that are required for CryptoCell certification (FIPS or Chinese).
*/

  /*!
  @addtogroup cc_cert_defs
  @{
  */


/*!
@note You must add the required flag to the full compilation (CC_SUPPORT_FIPS if FIPS certification is required,
 * or CC_SUPPORT_CH_CERT if chinese certification is required). */
/*!
@note For Slim version FIPS certification mode is not supported. */

#ifdef CC_SUPPORT_FIPS
#include "cc_rsa_types.h"
#include "cc_ecpki_types.h"
#include "cc_dh.h"
#include "cc_rnd.h"
#endif
#ifdef CC_SUPPORT_CH_CERT
#include "cc_sm2.h"
#endif

#if defined(CC_SUPPORT_FIPS) || defined(CC_SUPPORT_CH_CERT)

/*! Definitions for the certification context. */

typedef union {
#ifdef CC_SUPPORT_FIPS
 /*! Definition for RSA certification context. */
    CCRsaFipsKatContext_t   fipsRsaCtx;
	/*! Definition for ECC certification context. */
    CCEcdsaFipsKatContext_t fipsEcdsaCtx;
	/*! Definition for DH certification context. */
    CCDhFipsKat_t           fipsDhCtx;
	/*! Definition for ECDH certification context. */
    CCEcdhFipsKatContext_t  fipsEcdhCtx;
	 /*! Definition for DRBG certification context. */
    CCPrngFipsKatCtx_t      fipsPrngCtx;
#endif
#ifdef CC_SUPPORT_CH_CERT
    /*! Definition for SM2 certification context. */
    CCSm2FipsKatContext_t   fipsSm2Ctx;
#endif
}CCCertKatContext_t;

#else
typedef uint32_t   CCCertKatContext_t; /*!< If no certification is needed - this type is used only as NULL.*/


#endif

#ifdef CC_SUPPORT_CH_CERT
/*! Definition for SM2 key generation certification context. */
#define CCEcpkiKgCertContext_t CCSm2KeyGenCHCertContext_t
#else
/*! Definition for ECPKI certification context. */
#define CCEcpkiKgCertContext_t CCEcpkiKgFipsContext_t
#endif

/*!
  @}
  */
#endif  // _CC_CERT_CTX_H_
