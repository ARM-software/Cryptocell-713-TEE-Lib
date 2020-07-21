/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


#ifndef _BSV_SBRT_CRYPTO_DEFS_H
#define _BSV_SBRT_CRYPTO_DEFS_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "cc_error.h"
#include "cc_sram_map.h"
#include "bsv_crypto_defs.h"

#define CC_SBRT_HASH_SIZE_IN_BYTES              32
#define CC_SBRT_NONCE_SIZE_IN_BYTES             16
#define CC_SBRT_IV_SIZE_IN_BYTES                32
#define CC_SBRT_KEY_SIZE                        16

typedef enum CCSbrtError_t {
    CC_SBRT_GENERAL_ERROR = CC_SBRT_MODULE_ERROR_BASE,
    CC_SBRT_ILLEGEL_PARAMETER,
    CC_SBRT_ILLEGEL_OPERATION,
    CC_SBRT_HBK_NOT_PROGRAMMED_ERR,
    CC_SBRT_HBK_ZERO_COUNT_ERR,
    CC_SBRT_OTP_ACCESS_ERROR,
    CC_SBRT_BUFFER_MAP_ERROR,
    CC_SBRT_BUFFER_UNMAP_ERROR,
    CC_SBRT_BUFFER_COHERENCY_NULL_PTR_ERROR,
    CC_SBRT_ILLIGAL_FLOW_ERROR,
    CC_SBRT_ILLIGAL_KEY_ERROR,
    CC_SBRT_ILLIGAL_KCE_ERROR,
    CC_SBRT_ILLIGAL_KCEICV_ERROR,
    CC_SBRT_SECURE_DISABLE_ERROR,
    CC_SBRT_FATAL_ERROR_ERROR,
    CC_SBRT_CHIP_INDICATION_ERROR,
    CC_SBRT_ILLIGAL_SW_VERSION_ERROR,
    CC_SBRT_INVALID_DATA_IN_POINTER_ERROR,
    CC_SBRT_INVALID_DATA_OUT_POINTER_ERROR,
    CC_SBRT_ERROR_RESERVED = 0x7FFFFFFF /*!< Reserved. */

} CCSbrtError_t;

typedef enum CCSbrtFlow_t {
    CC_SBRT_FLOW_HASH_MODE ,           /*!< Data goes into Hash engines. */
    CC_SBRT_FLOW_AES_AND_HASH_MODE ,   /*!< Data goes into the AES and Hash engines. */
    CC_SBRT_FLOW_AES_TO_HASH_MODE,     /*!< Data goes into the AES and from the AES to the Hash engine. */
    CC_SBRT_FLOW_NUM,
    CC_SBRT_FLOW_RESERVED = 0x7FFFFFFF /*!< Reserved. */
}CCSbrtFlow_t;

#ifdef __cplusplus
}
#endif

#endif /* _BSV_SBRT_CRYPTO_DEFS_H */

/**
@}
 */

