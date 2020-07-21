/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

 /*!
 @file
 @brief This file contains HAL definitions.
 */

 /*!
 @addtogroup cc_hal_defs
 @{
     */

#ifndef __CC_HAL_DEFS_H__
#define __CC_HAL_DEFS_H__

/******************************************************************************
*				DEFINITIONS
******************************************************************************/
/* Peripheral ID register values. */
#define CC_PID_0_VAL        0x000000D0UL
#define CC_PID_1_VAL        0x000000B0UL
#define CC_PID_2_VAL        0x0000000BUL
#define CC_PID_3_VAL        0x00000000UL
#define CC_PID_4_VAL        0x00000004UL
#define CC_PID_SIZE_WORDS   5

/* The verification should skip the customer fields (REVAND ( bits [3:0]) and CMOD (bits [7:4]) in PIDR[3]). */
#define CC_PID_3_IGNORE_MASK    0x000000FFUL

/* Component ID register values. */
#define CC_CID_0_VAL        0x0DUL
#define CC_CID_1_VAL        0xF0UL
#define CC_CID_2_VAL        0x05UL
#define CC_CID_3_VAL        0xB1UL
#define CC_CID_SIZE_WORDS   4

/* The removed hardware engines for slim and full configurations. */
#define CC_HW_ENGINES_SLIM_CONFIG   0x9FUL
#define CC_HW_ENGINES_FULL_CONFIG   0x00UL


/******************************************************************************
*                               MACROS
******************************************************************************/

/******************************************************************************
*                               TYPES
******************************************************************************/
/*! HAL interrupt request types */
typedef enum {
    /*! AXIM complete interrupt type.*/
    CC_HAL_IRQ_AXIM_COMPLETE,
    /*! RNG interrupt type.*/
    CC_HAL_IRQ_RNG,
    /*! reserved.*/
    CC_HAL_IRQ_MAX,
    /*! reserved.*/
    CC_HAL_IRQ_RESERVE = 0x7fffffffUL
} CCHalIrq_t;

/*!
 @}
 */
#endif /*__CC_HAL_DEFS_H__*/

