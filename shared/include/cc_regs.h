/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


/*!
 * @file
 * @brief This file contains macro definitions for accessing Arm CryptoCell
          registers.
 */

 /*!
  @addtogroup cc_regs
  @{
      */

#ifndef _CC_REGS_H_
#define _CC_REGS_H_

#include "cc_bitops.h"
#include "dx_reg_base_host.h"
#include "cc_registers.h"

/*! A macro to retrieve a register address. */
#define SB_REG_ADDR(base, reg_name)     (base + CC_REG_OFFSET(CRY_KERNEL, reg_name))
/*! A macro to retrieve a register address based on its unit. */
#define SB_REG_ADDR_UNIT(base, reg_name, unit)  (base + CC_REG_OFFSET(unit, reg_name))

#ifdef CC_IOT
/*! Register Offset macro. */
#define CC_REG_OFFSET(unit_name, reg_name)                  \
    (DX_BASE_ ## unit_name + DX_ ## reg_name ## _REG_OFFSET)

/*! Register bit shift. */
#define CC_REG_BIT_SHIFT(reg_name, field_name)              \
    (DX_ ## reg_name ## _ ## field_name ## _BIT_SHIFT)

/*! Register bit mask. */
#define CC_REG_BIT_MASK(reg_name, field_name)              \
    (BITMASK(DX_ ## reg_name ## _ ## field_name ## _BIT_SIZE) << (DX_ ## reg_name ## _ ## field_name ## _BIT_SHIFT))

/*! Register bit size. */
#define CC_REG_BIT_SIZE(reg_name, field_name)               \
    (DX_ ## reg_name ## _ ## field_name ## _BIT_SIZE)
#else /* !CC_IOT */
/*! Register Offset macro. */
#define CC_REG_OFFSET(unit_name, reg_name)                  \
    (CC_BASE_ ## unit_name + CC_ ## reg_name ## _REG_OFFSET)

/*! Register bit shift. */
#define CC_REG_BIT_SHIFT(reg_name, field_name)              \
    (CC_ ## reg_name ## _ ## field_name ## _BIT_SHIFT)

/*! Register bit mask. */
#define CC_REG_BIT_MASK(reg_name, field_name)              \
     (BITMASK(CC_ ## reg_name ## _ ## field_name ## _BIT_SIZE) << (CC_ ## reg_name ## _ ## field_name ## _BIT_SHIFT))

/*! Register bit size. */
#define CC_REG_BIT_SIZE(reg_name, field_name)               \
    (CC_ ## reg_name ## _ ## field_name ## _BIT_SIZE)
#endif /* !CC_IOT */

/* Register Offset macros (from registers base address in host) */
#if defined(CC_REE) || defined(CC_TEE) || defined(CC_IOT)


/*! Read-Modify-Write a field of a register */
#define MODIFY_REGISTER_FLD(unitName, regName, fldName, fldVal) \
do {                                                            \
    uint32_t regVal;                                            \
    regVal = READ_REGISTER(CC_REG_ADDR(unitName, regName));     \
    CC_REG_FLD_SET(unitName, regName, fldName, regVal, fldVal); \
    WRITE_REGISTER(CC_REG_ADDR(unitName, regName), regVal);     \
} while (0)

#else
#error Execution domain is not CC_REE/CC_TEE/CC_IOT
#endif

/* Registers address macros for ENV registers (development FPGA only) */
#ifdef CC_BASE_ENV_REGS

/*! This offset should be added to mapping address of \c CC_BASE_ENV_REGS. */
#define CC_ENV_REG_OFFSET(reg_name)     (CC_ENV_FPGA_ ## reg_name ## _REG_OFFSET)
/*! Register bit shift. */
#define CC_ENV_REG_BIT_SHIFT(reg_name)  (CC_ENV_FPGA_ ## reg_name ## _BIT_SHIFT)
/*! Register bit size. */
#define CC_ENV_REG_BIT_SIZE(reg_name)   (CC_ENV_FPGA_ ## reg_name ## _BIT_SIZE)

#endif /*CC_BASE_ENV_REGS*/

#ifdef DX_BASE_ENV_REGS

/*! This offset should be added to mapping address of DX_BASE_ENV_REGS */
#define CC_ENV_REG_OFFSET(reg_name)     (DX_ENV_ ## reg_name ## _REG_OFFSET)
/*! Environment register bit shift. */
#define CC_ENV_REG_BIT_SHIFT(reg_name)  (DX_ENV_ ## reg_name ## _BIT_SHIFT)
/*! Environment register bit size. */
#define CC_ENV_REG_BIT_SIZE(reg_name)   (DX_ENV_ ## reg_name ## _BIT_SIZE)
#endif /*DX_BASE_ENV_REGS*/

#ifdef CC_IOT
/*! Register fields get. */
#define CC_REG_FLD_GET(unit_name, reg_name, fld_name, reg_val)              \
    (DX_ ## reg_name ## _ ## fld_name ## _BIT_SIZE == 0x20 ?                \
    reg_val /*!< \internal Optimization for 32b fields */ :                 \
    BITFIELD_GET(reg_val, DX_ ## reg_name ## _ ## fld_name ## _BIT_SHIFT,   \
             DX_ ## reg_name ## _ ## fld_name ## _BIT_SIZE))
#else /* !CC_IOT */
/*! Bit fields get. */
#define CC_REG_FLD_GET(unit_name, reg_name, fld_name, reg_val)              \
    (CC_ ## reg_name ## _ ## fld_name ## _BIT_SIZE == 0x20 ?                \
    reg_val /*!< \internal Optimization for 32b fields */ :                 \
    BITFIELD_GET(reg_val, CC_ ## reg_name ## _ ## fld_name ## _BIT_SHIFT,   \
             CC_ ## reg_name ## _ ## fld_name ## _BIT_SIZE))
#endif /* !CC_IOT */

/* Bit fields set. */
#ifdef CC_IOT

/*! Bit fields set. */
#define CC_REG_FLD_SET(                                             \
    unit_name, reg_name, fld_name, reg_shadow_var, new_fld_val)     \
do {                                                                \
    if (DX_ ## reg_name ## _ ## fld_name ## _BIT_SIZE == 0x20)      \
        reg_shadow_var = new_fld_val; /*!< \internal Optimization for 32b fields */\
    else                                                     \
        BITFIELD_SET(reg_shadow_var,                         \
            DX_ ## reg_name ## _ ## fld_name ## _BIT_SHIFT,  \
            DX_ ## reg_name ## _ ## fld_name ## _BIT_SIZE,   \
            new_fld_val);                                    \
} while (0)


/*! Bit fields set. */
#define CC_REG_FLD_SET2(                                            \
    unit_name, reg_name, fld_name, reg_shadow_var, new_fld_val)     \
do {                                                                \
    if (CC_ ## reg_name ## _ ## fld_name ## _BIT_SIZE == 0x20)      \
        reg_shadow_var = new_fld_val; /*!< \internal Optimization for 32b fields */\
    else                                                    \
        BITFIELD_SET(reg_shadow_var,                        \
            CC_ ## reg_name ## _ ## fld_name ## _BIT_SHIFT, \
            CC_ ## reg_name ## _ ## fld_name ## _BIT_SIZE,  \
            new_fld_val);                                   \
} while (0)

#else /* !CC_IOT */

/*! Bit fields set. */
#define CC_REG_FLD_SET(                                             \
    unit_name, reg_name, fld_name, reg_shadow_var, new_fld_val)     \
do {                                                                \
    if (CC_ ## reg_name ## _ ## fld_name ## _BIT_SIZE == 0x20)      \
        reg_shadow_var = new_fld_val; /*!< \internal Optimization for 32b fields */\
    else                                                    \
        BITFIELD_SET(reg_shadow_var,                        \
            CC_ ## reg_name ## _ ## fld_name ## _BIT_SHIFT, \
            CC_ ## reg_name ## _ ## fld_name ## _BIT_SIZE,  \
            new_fld_val);                                   \
} while (0)

#endif /* !CC_IOT */

/* Usage example:
   uint32_t reg_shadow = READ_REGISTER(CC_REG_ADDR(CRY_KERNEL,AES_CONTROL));
   CC_REG_FLD_SET(CRY_KERNEL,AES_CONTROL,NK_KEY0,reg_shadow, 3);
   CC_REG_FLD_SET(CRY_KERNEL,AES_CONTROL,NK_KEY1,reg_shadow, 1);
   WRITE_REGISTER(CC_REG_ADDR(CRY_KERNEL,AES_CONTROL), reg_shadow);
 */
/*!
  @}
  */

#endif /*_CC_REGS_H_*/
