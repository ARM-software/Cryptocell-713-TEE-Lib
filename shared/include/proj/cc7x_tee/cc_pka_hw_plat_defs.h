/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _CC_PKA_HW_PLAT_DEFS_H
#define _CC_PKA_HW_PLAT_DEFS_H

/*!
@file
@brief Contains the enums and definitions that are used in the PKA code.
*/

/*!
 @addtogroup cc_pka_defs
 @{
	 */

#ifdef __cplusplus
extern "C"
{
#endif


#include "cc_pal_types.h"


/*! The size of the PKA engine word. */
#define CC_PKA_WORD_SIZE_IN_BITS		     128

/*! The maximal supported size of modulus in RSA in bits. */
#define CC_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BITS      4096
/*! The maximal supported size of key-generation in RSA in bits. */
#define CC_RSA_MAX_KEY_GENERATION_HW_SIZE_BITS       4096

/*! Secure boot/debug certificate RSA public modulus key size in bits. */
#ifdef CC_CONFIG_BSV_RSA_CERT_3K_BIT_KEY_SUPPORTED
    #define BSV_CERT_RSA_KEY_SIZE_IN_BITS 3072
#else
    #define BSV_CERT_RSA_KEY_SIZE_IN_BITS 2048
#endif
/*! Secure boot/debug certificate RSA public modulus key size in bytes. */
#define BSV_CERT_RSA_KEY_SIZE_IN_BYTES    (BSV_CERT_RSA_KEY_SIZE_IN_BITS/CC_BITS_IN_BYTE)
/*! Secure boot/debug certificate RSA public modulus key size in words. */
#define BSV_CERT_RSA_KEY_SIZE_IN_WORDS    (BSV_CERT_RSA_KEY_SIZE_IN_BITS/CC_BITS_IN_32BIT_WORD)

/*! The maximal count of extra bits in PKA operations. */
#define PKA_EXTRA_BITS  8
/*! The number of memory registers in PKA operations. */
#define PKA_MAX_COUNT_OF_PHYS_MEM_REGS  32

/*! Size of buffer for Barrett modulus tag in words. */
#define RSA_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS  5
/*! Size of buffer for Barrett modulus tag in bytes. */
#define RSA_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_BYTES  (RSA_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS*CC_32BIT_WORD_SIZE)



#ifdef __cplusplus
}
#endif
/*!
 @}
 */
#endif //_CC_PKA_HW_PLAT_DEFS_H



