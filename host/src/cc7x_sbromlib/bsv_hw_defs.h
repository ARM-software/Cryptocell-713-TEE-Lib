/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */



#ifndef _BSV_HW_DEFS_H
#define _BSV_HW_DEFS_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "cc_pal_types.h"
#include "cc_registers.h"
#include "cc_hal_sb.h"

#define HIGH        1
#define LOW         0

/* ********************** Utility Macros ******************************* */

/* read a word directly from OTP memory */
#define CC_BSV_READ_OTP_WORD(hwBaseAddress, otpAddr, otpData, otpError)                 \
    do {                                                                                \
        uint32_t otpByteAddr = (otpAddr) * CC_32BIT_WORD_SIZE; /* convert to bytes */   \
        SB_HAL_READ_REGISTER((hwBaseAddress + CC_OTP_BASE_ADDR + otpByteAddr ), otpData);    \
        CC_BSV_IRR_OTP_ERR_GET(hwBaseAddress, otpError);                                \
        otpError = (otpError == 1) ? CC_BSV_OTP_ACCESS_ERR : CC_OK;                     \
    }while(0)

/* write a word directly from OTP memory */
#define CC_BSV_WRITE_OTP_WORD(hwBaseAddress, otpAddr, otpData, otpError)                \
    do {                                                                                \
        uint32_t otpByteAddr = (otpAddr) * CC_32BIT_WORD_SIZE; /* convert to bytes */   \
        SB_HAL_WRITE_REGISTER((hwBaseAddress + CC_OTP_BASE_ADDR + otpByteAddr), otpData);   \
        CC_BSV_WAIT_ON_AIB_ACK_BIT(hwBaseAddress);                                      \
        CC_BSV_IRR_OTP_ERR_GET(hwBaseAddress, otpError);                                \
        otpError = (otpError == 1) ? CC_BSV_OTP_ACCESS_ERR : CC_OK;                     \
    }while(0)

/* write a word and verify from OTP memory, otpAddr in words */
#define CC_BSV_WRITE_OTP_VERIFY_WORD(hwBaseAddress, otpAddr, otpData, otpError)         \
    do {                                                                                \
        uint32_t otpActualVal = 0;                                                      \
        otpError = CC_OK;                                                               \
        if (otpData != 0x0) {                                                           \
            CC_BSV_WRITE_OTP_WORD(hwBaseAddress, otpAddr, otpData, otpError);           \
            if (otpError == CC_OK) {                                                    \
                CC_BSV_READ_OTP_WORD(hwBaseAddress, otpAddr, otpActualVal, otpError);   \
                if ((otpError == CC_OK) && (otpActualVal != otpData)) {                 \
                    otpError = CC_BSV_OTP_WRITE_CMP_FAIL_ERR;                           \
                }                                                                       \
            }                                                                           \
        }                                                                               \
    } while(0)

/* read OTP flag */
#define CC_BSV_OTP_FLAG_GET(hwBaseAddress, flagRegister, flagName, regVal, error)                           \
    do {                                                                                                    \
        CC_BSV_READ_OTP_WORD(hwBaseAddress, CC_OTP_ ## flagRegister ## _FLAG_OFFSET, regVal, error);        \
        regVal = CC_REG_FLD_GET(0, OTP_ ## flagRegister ## _FLAG, flagName, regVal);                       \
    }while(0)

/* read a flag from an AO register */
#define CC_BSV_REG_GET(hwBaseAddress, reg, regVal)                                      \
    do {                                                                                \
        SB_HAL_READ_REGISTER(SB_REG_ADDR(hwBaseAddress, reg), regVal);                  \
    }while(0)

/* read a flag from an AO register */
#define CC_BSV_REG_FIELD_GET(hwBaseAddress, reg, field, regVal)                         \
    do {                                                                                \
        SB_HAL_READ_REGISTER(SB_REG_ADDR(hwBaseAddress, reg), regVal);                  \
        regVal = CC_REG_FLD_GET(0, reg, field, regVal);                                 \
    }while(0)

/* wait on a flag from an AO register */
#define CC_BSV_WAIT_ON_REG(hwBaseAddress, reg, waitTillHigh)                            \
    do {                                                                                \
        uint32_t regVal = 0;                                                            \
       do {                                                                             \
           SB_HAL_READ_REGISTER(SB_REG_ADDR(hwBaseAddress, reg), regVal);               \
       } while ( waitTillHigh > LOW ?  LOW == regVal : regVal > LOW);                   \
   }while(0)

/* wait on an AO register */
#define CC_BSV_WAIT_ON_REG_FIELD(hwBaseAddress, reg, key, waitTillHigh)                 \
    do {                                                                                \
       uint32_t regVal = 0;                                                             \
       do {                                                                             \
           CC_BSV_REG_FIELD_GET( hwBaseAddress, reg, key, regVal);                      \
       } while ( waitTillHigh > LOW ?  LOW == regVal : regVal > LOW);                   \
   }while(0)

/* ********************** Macros ******************************* */

/* OTP operations */
#define CC_BSV_IS_KEY_IN_USE(hwBaseAddress, flag, key, isKeyInUse, error)                   \
    do {                                                                                    \
        CC_BSV_OTP_FLAG_GET(hwBaseAddress, flag, key ## _NOT_IN_USE, isKeyInUse, error);    \
        isKeyInUse = 0x1 ^ isKeyInUse;                                                      \
    } while(0)

/* check Hbk configuration in OTP memory */
#define CC_BSV_IS_HBK_FULL(hwBaseAddress, isHbkFull, error)                             CC_BSV_OTP_FLAG_GET(hwBaseAddress, FIRST_MANUFACTURE, HBK0_NOT_IN_USE, isHbkFull, error)

/* check OEM RMA flag bit in OTP memory */
#define CC_BSV_IS_OEM_RMA_FLAG_SET(hwBaseAddress, isOemRmaFlag, error)                  CC_BSV_OTP_FLAG_GET(hwBaseAddress, SECOND_MANUFACTURE, OEM_RMA_MODE, isOemRmaFlag, error)

/* check ICV RMA flag bit in OTP memory */
#define CC_BSV_IS_ICV_RMA_FLAG_SET(hwBaseAddress, isIcvRmaFlag, error)                  CC_BSV_OTP_FLAG_GET(hwBaseAddress, SECOND_MANUFACTURE, ICV_RMA_MODE, isIcvRmaFlag, error)

/* check if fatal error bit is set to ON */
#define CC_BSV_IS_FATAL_ERR_ON(hwBaseAddress, isFatalErrOn)                             CC_BSV_REG_FIELD_GET(hwBaseAddress, HOST_AO_LOCK_BITS, HOST_FATAL_ERR, isFatalErrOn)

/* poll on the crypto busy till it is = 0 */
#define CC_BSV_WAIT_ON_CRYPTO_BUSY()                                                    CC_BSV_WAIT_ON_REG(hwBaseAddress, CRYPTO_BUSY, LOW)

/* poll NVM register to assure that the NVM boot is finished (and LCS and the keys are valid) */
#define CC_BSV_WAIT_ON_NVM_IDLE_BIT(hwBaseAddress)                                      CC_BSV_WAIT_ON_REG_FIELD(hwBaseAddress, NVM_IS_IDLE, VALUE, HIGH)

/* poll on the AIB acknowledge bit */
#define CC_BSV_WAIT_ON_AIB_ACK_BIT(hwBaseAddress)                                       CC_BSV_WAIT_ON_REG(hwBaseAddress, AIB_FUSE_PROG_COMPLETED, HIGH)

/* check KPICV error bit in LCS register */
#define CC_BSV_IS_KEY_ERROR(hwBaseAddress, key, isKeyError)                             CC_BSV_REG_FIELD_GET(hwBaseAddress, LCS_REG, ERR_ ## key ## _ZERO_CNT, isKeyError);

/* Check Kcst_disable register validity */
#define CC_BSV_IS_KCST_DISABLE(hwBaseAddress, isKcstDisabled)                           CC_BSV_REG_FIELD_GET(hwBaseAddress, HOST_KCST_DISABLE, VALUE, isKcstDisabled);

/* poll KCST valid bit to assure HW key is ready for use */
#define CC_BSV_WAIT_ON_KCST_VALID_BIT(hwBaseAddress)                                    CC_BSV_WAIT_ON_REG_FIELD(hwBaseAddress, HOST_KCST_VALID, VALUE, HIGH)

/* poll KPLT valid bit to assure HW key is ready for use */
#define CC_BSV_WAIT_ON_KPLT_VALID_BIT(hwBaseAddress)                                    CC_BSV_WAIT_ON_REG_FIELD(hwBaseAddress, HOST_KPLT_VALID, VALUE, HIGH)

/* read IS SD Disabled indication from AO */
#define CC_BSV_IS_SD_FLAG_SET(hwBaseAddress, isSDFlag)                                  CC_BSV_REG_FIELD_GET(hwBaseAddress, AO_SECURITY_DISABLED_INDICATION, VALUE, isSDFlag);

/* check if KEY _key bit is set to ON */
#define CC_BSV_IS_KEY_LOCKED(hwBaseAddress, key, isKeyLocked)                           CC_BSV_REG_FIELD_GET(hwBaseAddress, HOST_AO_LOCK_BITS, HOST_ ## key ## _LOCK, isKeyLocked);

/* Custom behaviour macros */

/* get OTP Error and clear */
#define CC_BSV_IRR_OTP_ERR_GET(hwBaseAddress, _err)                                     \
    do {                                                                                \
        CC_BSV_REG_FIELD_GET(hwBaseAddress, HOST_RGF_IRR, OTP_ERR_INT, _err);           \
    }while(0)

/* calc OTP memory length:
   read RTL OTP address width. The supported sizes are 6 (for 2 Kbits),7,8,9,10,11 (for 64 Kbits).
   convert value parameter to addresses of 32b words */
#define CC_BSV_GET_OTP_LENGTH(hwBaseAddress, otpLength)                                 \
    do {                                                                                \
        CC_BSV_REG_FIELD_GET(hwBaseAddress, OTP_ADDR_WIDTH_DEF, VALUE, otpLength);      \
        otpLength = (1 << otpLength);                                                   \
    }while(0)


/* Read raw bit value of chip indication */
#define CC_CHIP_INDICATION_GET(hwBaseAddress, isTci, isPci)                             \
    do {                                                                                \
        uint32_t regVal;                                                                \
        SB_HAL_READ_REGISTER(SB_REG_ADDR(hwBaseAddress, CHIP_MODE), regVal);            \
        isTci = CC_REG_FLD_GET(0, CHIP_MODE, TCI, regVal);                              \
        isPci = CC_REG_FLD_GET(0, CHIP_MODE, PCI, regVal);                              \
    }while(0)



/* Secure Provisioning macros */

/* setting SP-enable should cause CC reset and host CPU reset. In order to make sure CC completes its reset,
   we set a known register that is being cleared after reset - HOST_GPR_REG (32 bits).
   we write a pre-defined value before sp-enable bit is set, and expect to see it cleared after reset is completed */
#define BSV_SP_CC_RESET_INDICATION  0xdeadbeef

/* Write and verify by reading */
#define CC_BSV_SET_BEFORE_CC_RESET(hwBaseAddress)                                                   \
    do {                                                                                            \
        SB_HAL_WRITE_REGISTER(SB_REG_ADDR(hwBaseAddress, HOST_GPR), BSV_SP_CC_RESET_INDICATION);    \
    }while(0)

/* poll HOST_GPR to be sure CC reset completed */
#define CC_BSV_IS_CC_RESET_DONE(hwBaseAddress)                                          CC_BSV_WAIT_ON_REG(hwBaseAddress, HOST_GPR, LOW)

/* CC internal SRAM macros */
#define CC_BSV_CLEAR_SRAM(addr, size) \
    do { \
        uint32_t *p = NULL; \
        CC_BSV_WRITE_SRAM(addr, p, size); \
    } while (0)

/*
 * This Macro copies a buffer into sram.
 * passing buff NULL will set the value 0.
 */
#define CC_BSV_WRITE_SRAM(addr, buff, sizeWords) \
    do { \
        uint32_t ii; \
        uint32_t dummy = 0;  /* Trust in Soft initialization - __TRUSTINSOFT_ANALYZER__ */ \
        SB_HAL_WRITE_REGISTER(SB_REG_ADDR(hwBaseAddress, SRAM_ADDR), (addr) ); \
        for( ii = 0 ; ii < (sizeWords) ; ii++ ) { \
            uint32_t val = 0; \
            if (buff != NULL) { \
                UTIL_MemCopy((uint8_t*)&val, (uint8_t*)(buff) + (ii * sizeof(uint32_t)), sizeof(uint32_t)); \
            } \
            SB_HAL_WRITE_REGISTER( SB_REG_ADDR(hwBaseAddress,SRAM_DATA), val); \
            do { \
                SB_HAL_READ_REGISTER(SB_REG_ADDR(hwBaseAddress, SRAM_DATA_READY), dummy); \
            }while(!(dummy & 0x1)); \
        }\
    }while(0)

/* Get Cache parameters */
#define CC_BSV_CACHE_PARAMS_GET(hwBaseAddress, cacheParams)   \
        SB_HAL_READ_REGISTER(SB_REG_ADDR(hwBaseAddress, AXIM_CACHE_PARAMS), cacheParams)

/* Set Cache parameters */
#define CC_BSV_CACHE_PARAMS_SET(hwBaseAddress, cacheParams)   \
        SB_HAL_WRITE_REGISTER(SB_REG_ADDR(hwBaseAddress, AXIM_CACHE_PARAMS), cacheParams)



/******************************************************************************
*                CRYPTOGRAPHIC FLOW DEFINITIONS
******************************************************************************/
#define BSV_CONFIG_DIN_AES_DOUT_VAL                     0x1UL
#define BSV_CONFIG_DIN_AES_AND_HASH_VAL                 0x3UL
#define BSV_CONFIG_HASH_MODE_VAL                        0x7UL
#define BSV_CONFIG_AES_TO_HASH_AND_DOUT_VAL             0xAUL
/* ********************** Definitions ******************************* */

/* HW clocks */
#define CC_BSV_CLOCK_ENABLE     0x1UL
#define CC_BSV_CLOCK_DISABLE    0x0UL

#ifdef __cplusplus
}
#endif

#endif



