/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

/**
 * The function copies src buffer to dst with reversed bytes order.
 *
 * Note: Overlapping is not allowed, besides reversing of the buffer in place.
 *
 * @param dst
 * @param src
 * @param sizeInBytes
 */
int Tests_MemCpyReversed( void* dst_ptr, void* src_ptr, unsigned int sizeInBytes)
{
	unsigned int i;
	unsigned char *dst, *src;

	src = (unsigned char *)src_ptr;
	dst = (unsigned char *)dst_ptr;

	if (((dst < src) && (dst+sizeInBytes > src)) ||
	    ((src < dst) && (src+sizeInBytes > dst)))
		return -1;

	if (dst == src) {
		unsigned char tmp;
		for (i=0; i<sizeInBytes/2; i++) {
			tmp = dst[sizeInBytes-i-1];
			dst[sizeInBytes-i-1] = src[i];
			src[i] = tmp;
		}
	} else {
		for (i=0; i<sizeInBytes; i++) {
			dst[i] = src[sizeInBytes-i-1];
		}
	}

	return 0;
}
