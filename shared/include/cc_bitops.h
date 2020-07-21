/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

/*! @file
@brief This file defines bit-field operations macros.
*/

/*!
 @addtogroup bit_field_apis
 @{
*/

#ifndef _CC_BITOPS_H_
#define _CC_BITOPS_H_


/*! Definition of number of 32bit maximum value. */
#define CC_32BIT_MAX_VALUE  (0xFFFFFFFFUL)

/*! Definition for bitmask */
#define BITMASK(mask_size) (((mask_size) < 32) ?	\
	((1UL << (mask_size)) - 1) : 0xFFFFFFFFUL)
/*! Definition for bitmask in a given offset. */
#define BITMASK_AT(mask_size, mask_offset) (BITMASK(mask_size) << (mask_offset))

/*! Definition for getting bits value from a word. */
#define BITFIELD_GET(word, bit_offset, bit_size) \
	(((word) >> (bit_offset)) & BITMASK(bit_size))
/*! Definition for setting bits value from a word. */
#define BITFIELD_SET(word, bit_offset, bit_size, new_val)   do {    \
	word = ((word) & ~BITMASK_AT(bit_size, bit_offset)) |	    \
		(((new_val) & BITMASK(bit_size)) << (bit_offset));  \
} while (0)
/*!Right bit field shift*/
#define BITFIELD_U32_SHIFT_R(res, val, shift) \
    do { \
        if (((uint32_t)(shift)) < 32) { \
            (res) = (val) >> (shift); \
        } else {\
            (res) = 0; \
        } \
    } while (0)
/*! Left bit field shift*/
#define BITFIELD_U32_SHIFT_L(res, val, shift) \
    do { \
        if (((uint32_t)(shift)) < 32) { \
            (res) = (val) << (shift); \
        } else {\
            (res) = 0; \
        } \
    } while (0)

/*!Definition for is "val" aligned to "align" ("align" must be power of 2). */
#ifndef IS_ALIGNED
#define IS_ALIGNED(val, align)		\
	(((uintptr_t)(val) & ((align) - 1)) == 0)
#endif
/*!Swap endianity for 32 bits word. */
#define SWAP_ENDIAN(word)		\
	(((word) >> 24) | (((word) & 0x00FF0000) >> 8) | \
	(((word) & 0x0000FF00) << 8) | (((word) & 0x000000FF) << 24))

#ifdef BIG__ENDIAN
#define SWAP_TO_LE(word) SWAP_ENDIAN(word)
#define SWAP_TO_BE(word) word
#else
/*! Swap to little-end. */
#define SWAP_TO_LE(word) word
/*! Swap to big-end. */
#define SWAP_TO_BE(word) SWAP_ENDIAN(word)
#endif

/*!Align X to uint32_t size. */
#ifndef ALIGN_TO_4BYTES
#define ALIGN_TO_4BYTES(x)		(((unsigned long)(x) + (CC_32BIT_WORD_SIZE-1)) & ~(CC_32BIT_WORD_SIZE-1))
#endif



/*! Definition for is "val" a multiple of "mult" ("mult" must be power of 2). */
#define IS_MULT(val, mult)              \
	(((val) & ((mult) - 1)) == 0)

/*! Definition for is NULL address. */
#define IS_NULL_ADDR(adr)		\
	(!(adr))
  /*!
  @}
  */

#endif /*_CC_BITOPS_H_*/
