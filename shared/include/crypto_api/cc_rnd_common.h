/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */
/*!
 @file
 @brief This file contains the CryptoCell random-number generation APIs.

 The random-number generation module implements <em>NIST Special Publication 800-90A:
 Recommendation for Random Number Generation Using Deterministic Random Bit Generators.</em>
 */



 /*!
  @addtogroup cc_rnd
  @{
	  */

#ifndef _CC_RND_COMMON_H
#define _CC_RND_COMMON_H

#include "cc_error.h"
#include "cc_aes_defs.h"
#include "cc_rnd_common_trng.h"

#ifdef __cplusplus
extern "C"
{
#endif

/************************ Defines ******************************/

/* RND seed and additional input sizes */
/*! The maximal size of the random seed in words. */
#define CC_RND_SEED_MAX_SIZE_WORDS                  12

#ifndef CC_RND_ADDITINAL_INPUT_MAX_SIZE_WORDS
/*! The maximal size of the additional input-data in words. */
#define CC_RND_ADDITINAL_INPUT_MAX_SIZE_WORDS   CC_RND_SEED_MAX_SIZE_WORDS
#endif

/* Maximal requested size counter (12 bits active) - maximal count
of generated random 128 bit blocks allowed per one request of
Generate function according NIST 800-90 it is (2^12 - 1) = 0x3FFFF */
/* Maximal size for one RNG generation (in bits) =
  max_num_of_bits_per_request = 2^19 (FIPS 800-90 Tab.3) */

/*! The maximal size of the generated vector in bits. */
#define CC_RND_MAX_GEN_VECTOR_SIZE_BITS       0x7FFFF
/*! The maximal size of the generated random vector in Bytes. */
#define CC_RND_MAX_GEN_VECTOR_SIZE_BYTES    0xFFFF
/*! The maximal size of the generated vector in Bytes. */
#define CC_RND_REQUESTED_SIZE_COUNTER  0x3FFFF


/************************ Structs  *****************************/
/*!

  @brief The structure for the RND state.
  This includes internal data that must be saved by the user between boots.
 */
typedef  struct
{

    /* Seed buffer, consists from concatenated Key||V: max size 12 words */
	 /*! The random-seed buffer. */
    uint32_t  Seed[CC_RND_SEED_MAX_SIZE_WORDS];
    /* Previous value for continuous test */
	/*! The previous random data, used for continuous test. */
    uint32_t  PreviousRandValue[CC_AES_CRYPTO_BLOCK_SIZE_IN_WORDS];
	 /*! The previous additional-input buffer. */
    /* AdditionalInput buffer max size = seed max size words + 4w for padding*/
    uint32_t  PreviousAdditionalInput[CC_RND_ADDITINAL_INPUT_MAX_SIZE_WORDS+3];
	/*! The additional-input buffer. */
    uint32_t  AdditionalInput[CC_RND_ADDITINAL_INPUT_MAX_SIZE_WORDS+4];
	/*! The size of the additional input in words. */
    uint32_t  AddInputSizeWords;
	/*! The Reseed counter (32-bit active). Indicates the number of requests for entropy.
    since instantiation or reseeding. */
    uint32_t  ReseedCounter;
	/*! The key size according to security strength:<ul><li>128 bits: 4 words.</li><li>256 bits: 8 words.</li></ul> */
    uint32_t KeySizeWords;
    /* State flag (see definition of StateFlag above), containing bit-fields, defining:
    - b'0: instantiation steps:   0 - not done, 1 - done;
    - 2b'9,8: working or testing mode: 0 - working, 1 - KAT DRBG test, 2 -
      KAT TRNG test;
    b'16: flag defining is Previous random valid or not:
            0 - not valid, 1 - valid */
			/*! The state flag used internally in the code. */
    uint32_t StateFlag;
	/*! The validation tag used internally in the code. */
    uint32_t ValidTag;


     CCTrngState_t trngState; /*!< TRNG state */

} CCRndState_t;



/*! The RND vector-generation function pointer. */
typedef CCError_t (*CCRndGenerateVectWorkFunc_t)(        \
                void              *rndState_ptr, /*!< A pointer to the RND-state context. */   \
                unsigned char     *out_ptr,         /*!< A pointer to the output buffer. */ \
                size_t            outSizeBytes   /*!< The size of the output in Bytes. */  );


/*****************************************************************************/
/**********************        Public Functions      *************************/
/*****************************************************************************/


/**********************************************************************************************************/
/*!
@brief Generates a random vector with specific limitations by testing candidates (described and used in FIPS Publication 186-4: Digital
Signature Standard (DSS): for example: B.1.2 or B.4.2).

This function draws a random vector, compare it to the range limits, and if within range - return it in rndVect_ptr.
If outside the range, the function continues retrying until a conforming vector is found, or the maximal retries limit is exceeded.
If maxVect_ptr is provided, rndSizeInBits specifies its size, and the output vector must conform to the range [1 < rndVect < maxVect_ptr].
If maxVect_ptr is NULL, rndSizeInBits specifies the exact required vector size, and the output vector must be the exact same
bit size (with its most significant bit = 1).
\note The RND module must be instantiated prior to invocation of this API.

@return \c CC_OK on success.
@return A non-zero value from cc_rnd_error.h on failure.
*/
CIMPORT_C CCError_t CC_RndGenerateVectorInRange(
                    CCRndGenerateVectWorkFunc_t f_rng, /*!< [in] Pointer to DRBG function*/
                    void *p_rng,                           /*!< [in/out] Pointer to the random context - the input to f_rng. */
                    size_t   rndSizeInBits,                 /*!< [in]  The size in bits of the random vector required. The allowed size in range  2 <= rndSizeInBits < 2^19-1, bits. */
                    uint8_t  *maxVect_ptr,                  /*!< [in]  Pointer to the vector defining the upper limit for the random vector output, Given as little-endian byte array.
                                                                       If not NULL, its actual size is treated as [(rndSizeInBits+7)/8] bytes. */
                    uint8_t  *rndVect_ptr                   /*!< [in/out] Pointer to the output buffer for the random vector. Must be at least [(rndSizeInBits+7)/8] bytes.
                                                                 Treated as little-endian byte array. */
);


#ifdef __cplusplus
}
#endif
/*!
  @}
  */

#endif /* #ifndef _CC_RND_COMMON_H */
