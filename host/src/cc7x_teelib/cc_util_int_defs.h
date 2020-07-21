/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef  _CC_UTIL_INT_DEFS_H
#define  _CC_UTIL_INT_DEFS_H

#include "cc_hal.h"
#include "cc_regs.h"
#include "cc_general_defs.h"

#ifdef CC_SUPPORT_FULL_PROJECT
#include "cc_otp_defs.h"

/* read otp word at offset (in words) */
#define CC_HAL_READ_OTP(otpOffset)                                                           \
                CC_HAL_READ_REGISTER(CC_OTP_BASE_ADDR + ((otpOffset) * sizeof(uint32_t)))

/* Check not in use flag in OTP */
#define CC_UTIL_IS_OTP_KEY_NOT_IN_USE(val, reg, key)                                         \
    do {                                                                                     \
        val = CC_HAL_READ_OTP(CC_ ## reg ## _OFFSET);                                        \
        val = CC_REG_FLD_GET(0, reg, key ## _NOT_IN_USE, val);                               \
    }while(0)

/* Check OTP TCI/PCI flag */
#define CC_UTIL_IS_OTP_PCI_TCI_SET(val, reg, flag)                                           \
    do {                                                                                     \
        val = CC_HAL_READ_OTP(CC_ ## reg ## _OFFSET);                                        \
        val = CC_REG_FLD_GET(0, reg, flag, val);                                             \
    }while(0)



#endif
/*
 * since we are using RcInitUserCtxLocation to initialize the context offset for a new buffer
 * we must crate a working buffer that is at least 2 of the size of  drv_ctx_cipher.
 * we also need to reserve sizeof(CCCtxBufProps_t)
 */
#define CC_UTIL_BUFF_IN_WORDS       (3 + sizeof(struct drv_ctx_cipher)/2)
#define CC_UTIL_BUFF_IN_BYTES       (CC_UTIL_BUFF_IN_WORDS * sizeof(uint32_t))


#define SECURE_DISABLE_FLAG_SET             1
#define FATAL_ERROR_FLAG_SET                1

/* session key definition */
#define CC_UTIL_SESSION_KEY_IS_UNSET        0


#define CC_UTIL_IS_AO_FIELD(val, field)                                                      \
    do {                                                                                     \
        val = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_AO_LOCK_BITS));              \
        val = CC_REG_FLD_GET(0, HOST_AO_LOCK_BITS, HOST_ ## field , val);                    \
    }while(0)

/* Check if HW Key is locked */
#define CC_UTIL_IS_OTP_KEY_LOCKED(val, key)         CC_UTIL_IS_AO_FIELD(val, key ## _LOCK)

/* Check if fatal error is on */
#define CC_UTIL_IS_FATAL_ERROR_SET(val)             CC_UTIL_IS_AO_FIELD(val, FATAL_ERR)

/* Check Key error bit in LCS register */
#define CC_UTIL_IS_OTP_KEY_ERROR(val, key)                                                   \
    do {                                                                                     \
        val = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, LCS_REG));                        \
        val = CC_REG_FLD_GET(0, LCS_REG_ERR, key ## _ZERO_CNT, val);                         \
    }while(0)


/* Check session key validity */
#define CC_UTIL_IS_SESSION_KEY_VALID(val)                                                    \
    do {                                                                                     \
        val = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF,AO_SESSION_KEY));                  \
        val = CC_REG_FLD_GET(0, AO_SESSION_KEY, VALUE, val);                                 \
    }while(0)

/* Poll on the session key validity */
#define CC_UTIL_WAIT_ON_SESSION_KEY_VALID_BIT(val)                                           \
    do {                                                                                     \
        do {                                                                                 \
            val = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, AO_SESSION_KEY));             \
            val = CC_REG_FLD_GET(0, AO_SESSION_KEY, VALUE, val);                             \
        }while( !val );                                                                      \
    }while(0)

/* Check if Kcust disable */
#define CC_UTIL_IS_KCUST_DISABLE(val)                                                        \
    do {                                                                                     \
        val = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF,HOST_KCST_DISABLE));               \
        val = CC_REG_FLD_GET(0, HOST_KCST_DISABLE, VALUE, val);                              \
    }while(0)

#define CC_UTIL_IS_SECURE_DISABLE_FLAG_SET(val)                                              \
    do {                                                                                     \
        val = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, AO_SECURITY_DISABLED_INDICATION));\
        val = CC_REG_FLD_GET(HOST_RGF, AO_SECURITY_DISABLED_INDICATION, VALUE, val);         \
    } while (0)


/* Get LCS register */                                                                       \
#define CC_UTIL_GET_LCS(val)                                                                 \
    do {                                                                                     \
        val = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF,LCS_REG));                         \
        val = CC_REG_FLD_GET(0, LCS_REG, LCS_REG, val);                                      \
    }while(0)


/* Wait until the reset has ended. */
#define CC_UTIL_WAIT_ON_NVM_IDLE_BIT()                                                      \
    do {                                                                                    \
        uint32_t regVal;                                                                    \
        do {                                                                                \
            regVal = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, NVM_IS_IDLE));            \
            regVal = CC_REG_FLD_GET(0, NVM_IS_IDLE, VALUE, regVal);                         \
        }while( !regVal );                                                                  \
    }while(0)

/* endorsement key definitions*/
#define UTIL_EK_CMAC_COUNT                          0x03
#define UTIL_EK_ECC256_ORDER_LENGTH                 0x20 /* 32 bytes for ECC256  */
#define UTIL_EK_ECC256_ORDER_LENGTH_IN_WORDS        (UTIL_EK_ECC256_ORDER_LENGTH>>2)
#define UTIL_EK_ECC256_FULL_RANDOM_LENGTH           (UTIL_EK_ECC256_ORDER_LENGTH + CC_RND_FIPS_ADDIT_BYTES_FOR_RND_IN_RANGE)
#define UTIL_EK_ECC256_FULL_RANDOM_LENGTH_IN_WORDS  (UTIL_EK_ECC256_FULL_RANDOM_LENGTH>>2)

#define UTIL_EK_LABEL                       0x45

/* set session key definitions*/
#define UTIL_SK_RND_DATA_BYTE_LENGTH        0x0C    /* 96bit */
#define UTIL_SK_LABEL                       0x53

#define CC_BSV_KCUST_IS_DISABLED_ON         1

typedef enum UtilKeyType_t {
    UTIL_USER_KEY = 0,
    UTIL_ROOT_KEY = 1,
    UTIL_SESSION_KEY = 2,
    UTIL_KCP_KEY = 3,
    UTIL_KPICV_KEY = 4,
    UTIL_END_OF_KEY_TYPE = 0x7FFFFFFF
} UtilKeyType_t;

#endif /*_CC_UTIL_INT_DEFS_H*/
