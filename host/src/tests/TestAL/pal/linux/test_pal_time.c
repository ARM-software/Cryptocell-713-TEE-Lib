/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm’s non-OSI source license
 *
 */

#include <stdint.h>
#include <unistd.h>
#include <sys/time.h>
#include "test_pal_time.h"

/******************************************************************************/
void Test_PalDelay(const uint32_t usec)
{
	usleep(usec);
}

/******************************************************************************/
uint32_t Test_PalGetTimestamp(void)
{
	struct timeval te;
	uint32_t ms;

	/* Gets current time */
	gettimeofday(&te, NULL);

	/* Calculates timestamp in milliseconds */
	ms = te.tv_sec*1000LL + te.tv_usec/1000;

	return ms;
}
