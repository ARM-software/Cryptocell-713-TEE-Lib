/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


#ifndef _BSV_SBRT_CRYPTO_INT_DEFS_H
#define _BSV_SBRT_CRYPTO_INT_DEFS_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "cc_error.h"
#include "cc_sram_map.h"
#include "cc_otp_defs.h"
#include "cc_sbrt_crypto_defs.h"

#define CC_SBRT_HASH_CURR_LENGTH_SIZE_IN_BYTES  16
#define CC_SBRT_256B_HASH_SIZE_IN_WORDS         8
#define CC_SBRT_128B_HASH_SIZE_IN_WORDS         4

/* Using these addresses must be under the CCSymCryptoMutex lock */
/* Sym_adaptor and sbrt verify both use same addresses */
#define CC_SBRT_IV_SRAM_OFFSET                  (CC_SRAM_DRIVER_ADAPTOR_CONTEXT_CACHE_ADDR)
#define CC_SBRT_NONCE_SRAM_OFFSET               (CC_SBRT_IV_SRAM_OFFSET + CC_SBRT_IV_SIZE_IN_BYTES)
#define CC_SBRT_HASH_SRAM_OFFSET                (CC_SBRT_NONCE_SRAM_OFFSET + CC_SBRT_NONCE_SIZE_IN_BYTES)
#define CC_SBRT_SRAM_LAST_OFFSET                (CC_SBRT_HASH_SRAM_OFFSET + CC_SBRT_HASH_SIZE_IN_BYTES)

/*! CryptoImage HW completion sequence mode */
typedef enum CCSbrtCompletionMode_t {
    CC_SBRT_COMPLETION_NO_WAIT,              /*!< The driver waits only before reading the output. */
    CC_SBRT_COMPLETION_WAIT_UPON_END,        /*!< The driver waits after each chunk of data. */
    CC_SBRT_COMPLETION_WAIT_UPON_START       /*!< The driver waits before each chunk of data. */
}CCSbrtCompletionMode_t;


#ifdef __cplusplus
}
#endif

#endif /* _BSV_SBRT_CRYPTO_INT_DEFS_H */

/**
@}
 */

