/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

/*! @file
@brief This file contains basic platform-dependent type definitions.
*/

#ifndef CC_PAL_TYPES_PLAT_H
#define CC_PAL_TYPES_PLAT_H
/* Host specific types for standard (ISO-C99) compilant platforms */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/*! Defines for virtual address. */
typedef uintptr_t       CCVirtAddr_t;
/*! Defines for boolean variable. */
typedef uint32_t        CCBool_t;
/*! Defines for return status. */
typedef uint32_t        CCStatus;

/*! Defines error return. */
#define CCError_t   		CCStatus
/*! Defines an unlimited (infinite) time frame. */
#define CC_INFINITE		0xFFFFFFFFUL

/*! Defines for C export. */
#define CEXPORT_C
/*! Defines for C import. */
#define CIMPORT_C

#endif /*CC_PAL_TYPES_PLAT_H*/
/*!
@}
 */
