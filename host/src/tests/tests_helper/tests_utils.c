/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

/**
 * Tests_InitRand() - Init the random seed for using rand()
 * This function should be called at least once before calls to Tests_FillRandBuf().
 */
void Tests_InitRand(void){
    srand(time(NULL));
}

/**
 * Tests_FillRandBuf() - Fill buffer with random bytes values
 *
 * @buf_p:          The buffer to fill
 * @buf_size:       The size in bytes to fill
 */
void Tests_FillRandBuf(uint8_t *buf_p, uint32_t buf_size)
{
    uint8_t cur_val = 0;
    uint32_t i = 0;

    for(i = 0; i < buf_size; i++){
        cur_val = rand() % 256;
        buf_p[i] = cur_val;
    }
}


/**
 * Tests_FillValueBuf() - Fill buffer with random bytes values
 *
 * @buf_p:          The buffer to fill
 * @buf_size:       The size in bytes to fill
 * @value:          The value to copy to each byte of the buffer
 */
void Tests_FillValueBuf(uint8_t *buf_p, uint32_t buf_size, uint8_t value)
{
    uint8_t cur_val = 0;
    uint32_t i = 0;

    for(i = 0; i < buf_size; i++){
        cur_val = value;
        buf_p[i] = cur_val;
    }
}


