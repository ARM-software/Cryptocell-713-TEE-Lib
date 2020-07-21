/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm’s non-OSI source license
 *
 */

#include <stdlib.h>
#include "test_pal_log.h"

/******************************************************************************/
size_t Test_PalFetchDataFromFile(const char *data_fname, uint8_t **data_pp)
{
	FILE *data_file;
	size_t data_size = 0;
	uint8_t *cur_buf_pos;
	unsigned int tmp;

	data_file = fopen(data_fname, "r");

	if (data_file == NULL) {
		TEST_PRINTF_ERROR("Failed opening %s\n", data_fname);
		exit(1);
	}

	/* Data size is unknown so the first reading just for calculating the
	 * number of bytes */
	while (!feof(data_file) && fscanf(data_file, "0x%02X,", &tmp))
		data_size++;

	if (data_size > 0) {
		*data_pp = malloc(data_size);
		if (*data_pp == NULL) {
			TEST_PRINTF_ERROR("Failed allocating %d B for data"
					" of %s\n", (int)data_size, data_fname);
			exit(1);
		}
		cur_buf_pos = *data_pp;
		rewind(data_file);
		while (!feof(data_file) && fscanf(data_file, "0x%02X,", &tmp)) {
			*cur_buf_pos = tmp;
			cur_buf_pos++;
		}
	}

	fclose(data_file);

	TEST_PRINTF_MESSAGE("Read %d B from %s\n", (int)data_size, data_fname);

	return data_size;
}
