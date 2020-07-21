/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


#ifndef _CC_DH_ERROR_H
#define _CC_DH_ERROR_H


#include "cc_error.h"


#ifdef __cplusplus
extern "C"
{
#endif

/*!
 @file
 @brief This file contains error codes definitions for CryptoCell Diffie-Hellman module.
*/

/*!
 @addtogroup cc_dh_error CryptoCell DH specific errors
 @{
*/

/************************ Defines ******************************/
/* DH module on the CryptoCell layer base address - 0x00F00500 */
/*! The CryptoCell DH module errors */
/*! Illegal input pointer.*/
#define CC_DH_INVALID_ARGUMENT_POINTER_ERROR			(CC_DH_MODULE_ERROR_BASE + 0x0UL)
/*! Illegal input size.*/
#define CC_DH_INVALID_ARGUMENT_SIZE_ERROR			(CC_DH_MODULE_ERROR_BASE + 0x1UL)
/*! Illegal operation mode.*/
#define CC_DH_INVALID_ARGUMENT_OPERATION_MODE_ERROR		(CC_DH_MODULE_ERROR_BASE + 0x2UL)
/*! Illegal hash mode.*/
#define CC_DH_INVALID_ARGUMENT_HASH_MODE_ERROR			(CC_DH_MODULE_ERROR_BASE + 0x3UL)

/*! Illegal secret key data size. */
#define CC_DH_SECRET_KEYING_DATA_SIZE_ILLEGAL_ERROR		(CC_DH_MODULE_ERROR_BASE + 0x4UL)
/*! Illegal L input. */
#define CC_DH_INVALID_L_ARGUMENT_ERROR				(CC_DH_MODULE_ERROR_BASE + 0x5UL)
/*! Prime is smaller than generator. */
#define CC_DH_ARGUMENT_PRIME_SMALLER_THAN_GENERATOR_ERROR	(CC_DH_MODULE_ERROR_BASE + 0x6UL)
/*! Generator is smaller than zero. */
#define CC_DH_ARGUMENT_GENERATOR_SMALLER_THAN_ZERO_ERROR    	(CC_DH_MODULE_ERROR_BASE + 0x7UL)
/*! Illegal private key size. */
#define CC_DH_ARGUMENT_PRV_SIZE_ERROR				(CC_DH_MODULE_ERROR_BASE + 0x8UL)
/*! Illegal buffer size. */
#define CC_DH_ARGUMENT_BUFFER_SIZE_ERROR			(CC_DH_MODULE_ERROR_BASE + 0x9UL)
/*! Invalid shared secret value. */
#define CC_DH_INVALID_SHARED_SECRET_VALUE_ERROR			(CC_DH_MODULE_ERROR_BASE + 0xAUL)
/*! DH is not supported. */
#define CC_DH_IS_NOT_SUPPORTED					(CC_DH_MODULE_ERROR_BASE + 0xFUL)
/*! Illegal X942 hybrid buffer size.*/
#define CC_DH_X942_HYBRID_SIZE1_BUFFER_ERROR			(CC_DH_MODULE_ERROR_BASE + 0x15UL)

/*The requested derived secret key size is invalid*/
/*! Illegal secret key size .*/
#define CC_DH_SECRET_KEY_SIZE_NEEDED_ERROR			(CC_DH_MODULE_ERROR_BASE + 0x16UL)
/*! Illegal output secret key size .*/
#define CC_DH_SECRET_KEY_SIZE_OUTPUT_ERROR			(CC_DH_MODULE_ERROR_BASE + 0x17UL)
/*! Illegal otherInfo size .*/
#define CC_DH_OTHERINFO_SIZE_ERROR                            	(CC_DH_MODULE_ERROR_BASE + 0x18UL)

/* DH domain and key generation and checking errors */
/*! Illegal modulus size. */
#define CC_DH_INVALID_MODULUS_SIZE_ERROR			(CC_DH_MODULE_ERROR_BASE + 0x20UL)
/*! Illegal order size. */
#define CC_DH_INVALID_ORDER_SIZE_ERROR				(CC_DH_MODULE_ERROR_BASE + 0x21UL)
/*! Illegal seed size. */
#define CC_DH_INVALID_SEED_SIZE_ERROR  				(CC_DH_MODULE_ERROR_BASE + 0x22UL)
/*! Illegal J factor pointer size. */
#define CC_DH_INVALID_J_FACTOR_PTR_OR_SIZE_ERROR 		(CC_DH_MODULE_ERROR_BASE + 0x23UL)
/*! Illegal generator pointer or size. */
#define CC_DH_INVALID_GENERATOR_PTR_OR_SIZE_ERROR 		(CC_DH_MODULE_ERROR_BASE + 0x24UL)
/*! Illegal domain primes. */
#define CC_DH_CHECK_DOMAIN_PRIMES_NOT_VALID_ERROR         	(CC_DH_MODULE_ERROR_BASE + 0x25UL)
/*! Illegal domain generator. */
#define CC_DH_CHECK_DOMAIN_GENERATOR_NOT_VALID_ERROR         	(CC_DH_MODULE_ERROR_BASE + 0x26UL)
/*! Illegal public key size. */
#define CC_DH_INVALID_PUBLIC_KEY_SIZE_ERROR                 	(CC_DH_MODULE_ERROR_BASE + 0x27UL)
/*! Illegal public key. */
#define CC_DH_CHECK_PUB_KEY_NOT_VALID_ERROR                 	(CC_DH_MODULE_ERROR_BASE + 0x28UL)
/*! Illegal generator size or pointer. */
#define CC_DH_CHECK_GENERATOR_SIZE_OR_PTR_NOT_VALID_ERROR    	(CC_DH_MODULE_ERROR_BASE + 0x29UL)
/*! Illegal seed size or pointer. */
#define CC_DH_CHECK_SEED_SIZE_OR_PTR_NOT_VALID_ERROR          	(CC_DH_MODULE_ERROR_BASE + 0x2AUL)
/*! Illegal generator. */
#define CC_DH_CHECK_GENERATOR_NOT_VALID_ERROR               	(CC_DH_MODULE_ERROR_BASE + 0x2BUL)
/*! Prime generation failed. */
#define CC_DH_PRIME_P_GENERATION_FAILURE_ERROR               	(CC_DH_MODULE_ERROR_BASE + 0x2CUL)
/*! Illegal public key. */
#define CC_DH_INVALID_PUBLIC_KEY_ERROR                    	(CC_DH_MODULE_ERROR_BASE + 0x2DUL)
/*! Illegal seed. */
#define CC_DH_PASSED_INVALID_SEED_ERROR                    	(CC_DH_MODULE_ERROR_BASE + 0x2EUL)
/*! Prime generation failed. */
#define CC_DH_PRIME_Q_GENERATION_FAILURE_ERROR                	(CC_DH_MODULE_ERROR_BASE + 0x2FUL)
/*! Internal PKI error */
#define CC_DH_INTERNAL_ERROR                                 	(CC_DH_MODULE_ERROR_BASE + 0x30UL)



/************************ Enums ********************************/


/************************ Typedefs  ****************************/


/************************ Structs  ******************************/


/************************ Public Variables **********************/


/************************ Public Functions **********************/




#ifdef __cplusplus
}
#endif
/**
@}
 */

#endif

