/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _TESTS_MEMORY_H_
#define _TESTS_MEMORY_H_

/**
 * The function copies src buffer to dst with reversed bytes order.
 *
 * Note: Overlapping is not allowed, besides reversing of the buffer in place.
 *
 * @param dst
 * @param src
 * @param sizeInBytes
 */
int Tests_MemCpyReversed( void* dst_ptr, void* src_ptr, unsigned int sizeInBytes);

#endif /* _TESTS_MEMORY_H_ */

