/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

/*!
@file
@brief This file contains the enumerations and definitions that are used for the
        CryptoCell Library initialize and finish APIs, as well as the APIs themselves.
*/

/*!
 @addtogroup cc_lib_apis
 @{
    */

#ifndef __CC_LIB_H__
#define __CC_LIB_H__

#include "cc_pal_types.h"
#include "cc_rnd_common.h"
#include "cc_rnd.h"
#include "cc_cert_ctx.h"
#include "cc_axi_ctrl.h"

/*! Certification types */
typedef enum {
    CC_LIB_CERT_TYPE_NONE = 0,      /*!< Certification is not supported. */
    CC_LIB_CERT_TYPE_FIPS,          /*!< FIPS Certification. */
    CC_LIB_CERT_TYPE_CHINESE,       /*!< Chinese Certification. */
    CC_LIB_CERT_TYPE_RESERVE32B = 0x7FFFFFFFL
} CClibCertType_t;

/*! Return codes*/
typedef enum {
    CC_LIB_RET_OK = 0, /*!< Success. */
    CC_LIB_RET_EINVAL,        /*!< Invalid parameters */
    CC_LIB_RET_COMPLETION,    /*!< HW Failure. */
    CC_LIB_RET_HAL,           /*!< Error from the HAL layer. */
    CC_LIB_RET_EINVAL_PIDR,   /*!< Incorrect PID values. */
    CC_LIB_RET_EINVAL_CIDR,   /*!< Incorrect CID values. */
    CC_LIB_RET_RND_INST_ERR,  /*!< Random seeding operation failed. */
    CC_LIB_RET_PAL,           /*!< Error from the PAL layer. */
    CC_LIB_RET_EINVAL_CERT_TYPE,  /*!< Invalid certification type. */
    CC_LIB_RET_EFIPS,             /*!< FIPS tests error. */
    CC_LIB_RET_ECHCERT,           /*!< Chinese certification tests error. */
    CC_LIB_INCORRECT_HW_VERSION_SLIM_VS_FULL,      /*!< Mismatched HW/SW versions. */
    CC_LIB_RET_CACHE_PARAMS_ERROR, /*!< Error in setting cache parameters. */
    CC_LIB_OTP_ERROR,             /*!< OTP verification error. */
    CC_LIB_OTP_HUK_ERROR,         /*!< OTP verification - HUK error. */
    CC_LIB_OTP_TCI_PCI_ERROR,     /*!< OTP verification - TCI/PCI error. */
    CC_LIB_FATAL_ERR_IS_LOCKED_ERR, /*!< Device is locked in fatal error state. */
    CC_LIB_RESERVE32B = 0x7FFFFFFFL /*!< Reserved. */
} CClibRetCode_t;


/*!
@brief This function performs global initialization of the Arm CryptoCell TEE runtime library.
This function must be called once per cold boot cycle. As part of the global initialization the function verifies that
all of the cryptographic engines are working as expected, by running known answer tests. If a test fails (the function
returns an error), it signifies that there is a fatal error, and it should be handled accordingly.
Among other initializations, this function calls CC_RndInstantiation
to initialize the TRNG and the primary RND context. An initialized RND context is required for calling RND
APIs, and asymmetric cryptography key generation and signatures. The primary context returned by this
function can be used as a single global context for all RND needs. Alternatively, other contexts may
be initialized and used with a more noted scope (for specific applications or specific threads).
\note The Mutexes, if used, are initialized by this API. Therefore, unlike the other APIs in the library,
this API is not thread-safe. \par
\note If the certType flag is not '0', the cryptography APIs that follow (until the next cold boot) behave
according to FIPS/Chinese certification restrictions. For example, if one of the known answer tests returns an error, all other
cryptographic operations are disabled. For additional information, see the TEE Software Integration Guidelines -
Certification Support section.
@return CC_LIB_RET_OK on success.
@return A non-zero value in case of failure.
*/
CClibRetCode_t CC_LibInit(CCRndGenerateVectWorkFunc_t *f_rng,    /*!< [in] Pointers to a function used for random vector generation. */
                          void                  *p_rng,    /*!< [in/out] Pointer to the RND context buffer,
                                            allocated by the user. The context is used to maintain the RND state. This context must be saved and
                                            provided as parameter to any API that uses the RND module.*/
                          CCTrngWorkBuff_t      *pTrngWorkBuff      /*!< [in] Scratchpad for the RND module's work. */,
                          CClibCertType_t       certType,           /*!< [in] Define the type of certification - in case it is supported. */
                          CCCertKatContext_t    *pCertCtx,          /*!< [in] Buffer used if certification mode is on (may be \c NULL for all other cases). */
                          CCAxiFields_t  *pAxiFields              /*!< [in] AXI configuration control definitions*/);


/*!
 @brief This function finalizes the library operations. It frees the associated resources (mutexes) and calls HAL and PAL terminate functions.
This function also calls CC_RndUnInstantiation() to clean the RND context.
 @return \c CC_LIB_RET_OK on success.
 @return A non-zero value on failure.
*/
void CC_LibFini(CCRndGenerateVectWorkFunc_t *f_rng, /*!< [in] Pointer to DRBG function*/
        void *p_rng /*!< [in/out] Pointer to the RND context buffer that was initialized in CC_LibInit().*/);
/*!
 @}
 */


#endif /*__CC_LIB_H__*/


