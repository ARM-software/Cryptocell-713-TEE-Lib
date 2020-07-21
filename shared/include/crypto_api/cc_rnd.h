/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


#ifndef _CC_RND_H
#define _CC_RND_H

#include "cc_error.h"
#include "cc_aes_defs.h"
#include "cc_rnd_common.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*!
@file
@brief This file contains the CryptoCell APIs used for random number generation.
The random-number generation module implements referenced standard NIST Special Publication 800-90A: Recommendation for Random Number
Generation Using Deterministic Random Bit Generators.
 @addtogroup cc_rnd
 @{
*/

/*****************************************************************************/
/**********************            Defines           *************************/
/*****************************************************************************/
/*!  Maximal reseed counter - indicates maximal number of
requests allowed between reseeds; according to NIST 800-90
it is (2^48 - 1), our restriction is :  (0xFFFFFFFF - 0xF).*/
#define CC_RND_MAX_RESEED_COUNTER   (0xFFFFFFFF - 0xF)

/*! AES output block size in words. */
#define CC_RND_AES_BLOCK_SIZE_IN_WORDS  CC_AES_CRYPTO_BLOCK_SIZE_IN_WORDS

/* allowed sizes of AES Key, in words */
/*! AES key size (128 bits) in words. */
#define CC_RND_AES_KEY_128_SIZE_WORDS  4
/*! AES key size (192 bits) in words. */
#define CC_RND_AES_KEY_192_SIZE_WORDS  6
/*! AES key size (256 bits) in words. */
#define CC_RND_AES_KEY_256_SIZE_WORDS  8

/* Size of the expected output buffer used by FIPS KAT */
/*! FIPS Known answer test output size. */
#define CC_PRNG_FIPS_KAT_OUT_DATA_SIZE      64

/*! Size of additional random bits for generation random number in range: according to FIPS 186-3, B.4.1
 * use 128 and not 64 as in the FIPS, AES-CMAC need to be multiple of 128 bits.  */
#define CC_RND_FIPS_ADDIT_BITS_FOR_RND_IN_RANGE   128
/*! Size of additional random bytes for generation random number in range: according to FIPS 186-3, B.4.1. */
#define CC_RND_FIPS_ADDIT_BYTES_FOR_RND_IN_RANGE  (CC_RND_FIPS_ADDIT_BITS_FOR_RND_IN_RANGE>>3)


/*****************************************************************************/
/**********************            Structs           *************************/
/*****************************************************************************/
/*! Data structure required for internal FIPS verification for PRNG KAT. */
typedef  struct
{
       /*! Internal working buffer. */
       CCTrngWorkBuff_t      trngWorkBuff;
       /*! Output buffer. */
       uint8_t              rndOutputBuff[CC_PRNG_FIPS_KAT_OUT_DATA_SIZE];
} CCPrngFipsKatCtx_t;


/*****************************************************************************/
/**********************        Public Functions      *************************/
/*****************************************************************************/

/*!
@brief This function initializes the RND context.
It must be called at least once prior to using this context with any API that requires it as a
parameter (such as other RND APIs, asymmetric cryptography key generation and signatures).
It is called as part of Arm CryptoCell library initialization, which initializes and returns
the primary RND context. This primary context can be used as a single global context for all
RND needs.\n

Alternatively, other contexts may be initialized and used with a more limited scope for specific
applications or specific threads. It implements referenced standard section 10.2.1.3.2 - CTR-DRBG
of NIST Special Publication 800-90A: Recommendation for Random Number Generation Using Deterministic
Random Bit Generators, instantiate algorithm using AES (197FIPS Publication 197: AES Advanced Encryption
Standard) and Derivation Function (DF)).
\note Additional data can be mixed with the random seed (personalization data or nonce). If required,
this data should be provided by calling ::CC_RndAddAdditionalInput prior to using this API.

@return \c CC_OK on success.
@return A non-zero value from cc_rnd_error.h on failure.
*/
CIMPORT_C CCError_t CC_RndInstantiation(
        CCRndGenerateVectWorkFunc_t        *f_rng, /*!< [in] - Pointer to DRBG function*/
                        void               *p_rng,         /*!< [in/out] Pointer to the RND context buffer allocated by the user, which is used to
                                           maintain the RND state. This context must be saved and provided as a
                                           parameter to any API that uses the RND module.
                                           \note The buffer and its members must be allocated.
                                           \note The context must be cleared before sent to the function. */

                        CCTrngWorkBuff_t  *pTrngWorkBuff       /*!< [in/out] Scratchpad for the RND module's work. */
);

/*!
@brief This function is used for reseeding the RNG with additional entropy and additional user-provided input.
Additional data should be provided by calling ::CC_RndAddAdditionalInput prior to using this API.
It implements section - 10.2.1.4.2 - CTR-DRBG of NIST Special Publication 800-90A: Recommendation for Random Number Generation
Using Deterministic Random Bit Generators Reseeding algorithm, using AES (FIPS Publication 197: AES Advanced Encryption Standard)
and Derivation Function (DF).

@return \c CC_OK on success.
@return A non-zero value from cc_rnd_error.h on failure.
*/
CIMPORT_C CCError_t CC_RndReseeding(
                        CCRndGenerateVectWorkFunc_t *f_rng, /*!< [in] - Pointer to DRBG function*/
                        void *p_rng,                       /*!< [in/out]  - Pointer to the random context - the input to f_rng. */
                        CCTrngWorkBuff_t  *pTrngWorkBuff      /*!< [in/out] Scratchpad for the RND module's work. */
);


/****************************************************************************************/
/*!
@brief Generates a random vector according to the algorithm defined in section 10.2.1.5.2 - CTR-DRBG of NIST Special Publication
800-90A: Recommendation for Random Number Generation Using Deterministic Random Bit Generators.
The generation algorithm uses AES (FIPS Publication 197: AES Advanced Encryption Standard and Derivation Function (DF).

\note The RND module must be instantiated prior to invocation of this API. \par
\note Reseeding operation must be performed prior to vector generation if prediction resistance is required. \par
\note Reseeding operation must be performed prior to vector generation if the function returns
CC_RND_RESEED_COUNTER_OVERFLOW_ERROR, stating that the Reseed Counter has passed its upper-limit (2^32-2).

@return \c CC_OK on success.
@return A non-zero value from cc_rnd_error.h on failure.
*/
CIMPORT_C CCError_t CC_RndGenerateVector(
                            void *  p_rng,     /*!< [in/out] Pointer to the random context. */
                            unsigned char   *out_ptr,                  /*!< [out] The pointer to output buffer. */
                            size_t          outSizeBytes             /*!< [in]  The size in bytes of the random vector required. The maximal size is 2^16 -1 bytes. */
);

/*************************************************************************************/
/*!
@brief Used for adding additional input/personalization data provided by the user,
to be later used by the ::CC_RndInstantiation/::CC_RndReseeding/::CC_RndGenerateVector functions.

@return \c CC_OK on success.
@return A non-zero value from cc_rnd_error.h on failure.
*/
CIMPORT_C CCError_t CC_RndAddAdditionalInput(
                            void *p_rng,                       /*!< [in/out]  - Pointer to the random context - the input to f_rng. */
                            uint8_t *additonalInput_ptr,            /*!< [in]  The Additional Input buffer. */
                            size_t  additonalInputSize              /*!< [in]  The size of the Additional Input buffer (in bytes). Must be <= 48, and a multiple of 4. */
);



/*!
@brief The CC_RndEnterKatMode function sets KAT mode bit into StateFlag of global random context structure.

The user must call this function before calling functions performing KAT tests.

\note Total size of entropy and nonce must be not great than 126 words (maximal size of entropy and nonce).

@return \c CC_OK on success.
@return A non-zero value from cc_rnd_error.h on failure.
*/
CIMPORT_C CCError_t CC_RndEnterKatMode(
            void *p_rng,                       /*!< [in/out]  - Pointer to the random context - the input to f_rng. */
            uint8_t            *entrData_ptr,       /*!< [in] Entropy data. */
            size_t             entrSize,           /*!< [in] Entropy size in bytes. */
            uint8_t            *nonce_ptr,          /*!< [in] Nonce. */
            size_t             nonceSize,          /*!< [in] Entropy size in bytes. */
            CCTrngWorkBuff_t  *pTrngWorkBuff      /*!< [out] RND working buffer, must be the same buffer, which should be passed into
                            Instantiation/Reseeding functions. */
);

/**********************************************************************************************************/
/*!
@brief The CC_RndDisableKatMode function disables KAT mode bit into StateFlag of global random context structure.

The user must call this function after KAT tests before actual using RND module, for example, Instantiation.

@return \c CC_OK on success.
@return void.
*/
CIMPORT_C void CC_RndDisableKatMode(
        void *p_rng                       /*!< [in/out]  - Pointer to the random context - the input to f_rng. */
);


/*!
@brief Clears existing RNG instantiation state.

@return \c CC_OK on success.
@return A non-zero value from cc_rnd_error.h on failure.
*/
CIMPORT_C CCError_t CC_RndUnInstantiation(
        CCRndGenerateVectWorkFunc_t *f_rng, /*!< [in] - Pointer to DRBG function. */
        void *p_rng                       /*!< [in/out]  - Pointer to the random context - the input to f_rng. */
);
/*!
 @}
 */
#endif
