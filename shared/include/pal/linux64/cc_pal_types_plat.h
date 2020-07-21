/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

/*! @file
@brief This file contains basic platform-dependent type definitions.
*/

/*!
 @addtogroup cc_pal_types
 @{
 */

#ifndef CC_PAL_TYPES_PLAT_H
#define CC_PAL_TYPES_PLAT_H
/* Host specific types for standard (ISO-C99) compilant platforms */

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#endif

typedef uintptr_t		CCVirtAddr_t;
#ifndef __KERNEL__
typedef uint32_t		CCBool_t;
typedef uint32_t		CCStatus;

#define CCError_t   		CCStatus
#define CC_INFINITE		0xFFFFFFFFUL

#define CEXPORT_C
#define CIMPORT_C
#endif // __KERNEL__

#endif /*CC_PAL_TYPES_PLAT_H*/
