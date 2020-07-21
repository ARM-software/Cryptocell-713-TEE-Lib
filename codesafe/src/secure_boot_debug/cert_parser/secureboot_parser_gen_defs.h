/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _SECUREBOOT_PARSER_GEN_DEFS_H_
#define _SECUREBOOT_PARSER_GEN_DEFS_H_


#include "cc_address_defs.h"
#include "cc_pka_hw_plat_defs.h"
#include "rsa_bsv.h"
#include "secureboot_defs.h"
#include  "cc_certificate_defs.h"

/********* Supported algorithms definitions ***********/

/*! hash supported algorithms. */
typedef enum {
	HASH_SHA256_Alg_Output 		= 0x01, 	/*!< hash SHA 256 output. */
	HASH_SHA256_Alg_128_Output 	= 0x02,		/*!< hash SHA 256 output truncated to 128 bits. */
	HASH_Last              		= 0x7FFFFFFF

}CCSbHashAlg_t;


/*! RSA supported algorithms */
typedef enum {
	RSA_ALG_MIN,
	RSA_PSS_2048           = 0x01, 			/*!< RSA PSS 2048 after hash SHA 256 */
	RSA_PSS_3072           = 0x02, 			/*!< RSA PSS 3072 after hash SHA 256 */
	RSA_ALG_MAX,
	RSA_Last               = 0x7FFFFFFF
}CCSbSignAlg_t;

#endif /* _GEN_SECUREBOOT_PARSER_GEN_DEFS_H_ */
