/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _TEST_UTILS_H_
#define _TEST_UTILS_H_

#include <stdlib.h>
#include <string.h>

/* Test helper */
#include "tests_log.h"

/* TestAL*/
#include "test_pal_mem.h"

/*CryptoCell*/
#include "dx_reg_base_host.h" /* to know if the compilation is for zynq or not*/

/** Macros **/

/** used to avoid compilation errors */
#define TEST_UNUSED(_a)          (void)_a

/** defines the action that should be performed in case _cmd != _exp. use _err in case of failure. */
#define TEST_ASSERT_ERR(_cmd, _exp, _err) \
                do { \
                    int _res = 0; \
                    TEST_LOG_TRACE("running [%.200s]\n", #_cmd); \
                    if ((_res = (_cmd)) != (_exp)) { \
                        TEST_LOG_CRIT("failed with res[0x%08x]\n", _res); \
                        res = _err; \
                        goto bail; \
                    } \
                } while (0)

/** defines the action that should be performed in case _cmd != true. */
#define TEST_ASSERT(_cmd, _err) \
                do { \
                    TEST_LOG_TRACE("running [%.200s]\n", #_cmd); \
                    if ((_cmd) == 0) { \
                        TEST_LOG_CRIT("failed [%.100s]\n", #_cmd); \
                        res = _err; \
                        goto bail; \
                    } \
                } while (0)

/** defines the label that should be jumped to in case _cmd != true. */
#define TEST_ASSERT_JUMP(_cmd, _err, _label) \
                do { \
                    TEST_LOG_TRACE("running [%.200s]\n", #_cmd); \
                    if ((_cmd) == 0) { \
                        TEST_LOG_CRIT("failed [%.100s]\n", #_cmd); \
                        res = _err; \
                        goto _label; \
                    } \
                } while (0)

/** defines the action that should be performed in case _cmd != true. */
#define TEST_ASSERT_EXP(_cmd, _exp, _err) \
                do { \
                    int _res = 0; \
                    TEST_LOG_TRACE("running [%s]\n", #_cmd); \
                    if ((_res = (_cmd)) != _exp) { \
                        TEST_LOG_CRIT("failed [%.100s] with exp[0x%08x] res[0x%08x]\n", #_cmd, _exp, _res); \
                        res = _err; \
                        goto bail; \
                    } \
                } while (0)


/** allocates the memory with a DMA-contiguous memory location*/
#define TEST_TESTAL_DMA_CONTIG_ALLOC(_ptr, _size) \
                do { \
                    if (_size != 0) { \
                        _ptr = Test_PalDMAContigBufferAlloc(_size); \
                    } else { \
                        _ptr = Test_PalDMAContigBufferAlloc(1); /* in case the size is 0 allocate 1 byte */ \
                    }\
                    if (_ptr == NULL){ \
                        TEST_LOG_CRIT("failed to allocate [%s] of size[%zu]\n", #_ptr, (size_t)(_size)); \
                        res = 1; \
                        goto bail; \
                    } \
                    TEST_LOG_TRACE("allocated pointer[%s][%p] of size[%zu]\n", #_ptr, _ptr, (size_t)(_size)); \
                } while (0);

/** allocates the memory */
#define TEST_TESTAL_DMA_MALLOC(_ptr, _size) \
                do { \
                if (_size != 0) { \
                    _ptr = Test_PalMalloc(_size); \
                } else { \
                    _ptr = Test_PalMalloc(1); /* in case the size is 0 allocate 1 byte */ \
                }\
                if (_ptr == NULL){ \
                    TEST_LOG_CRIT("failed to allocate [%s] of size[%zu]\n", #_ptr, (size_t)(_size)); \
                    res = 1; \
                    goto bail; \
                } \
                TEST_LOG_TRACE("allocated pointer[%s][%p] of size[%zu]\n", #_ptr, _ptr, (size_t)(_size)); \
            } while (0);


/** allocates and initialises the memory */
#ifdef TEE_OS_IS_NO_OS
    #define TEST_ALLOC(_ptr, _size)  TEST_TESTAL_DMA_CONTIG_ALLOC(_ptr, _size)
#else
    #define TEST_ALLOC(_ptr, _size)  TEST_TESTAL_DMA_MALLOC(_ptr, _size)
#endif


/** frees the memory allocated by Test_PalDMAContigBufferAlloc */
#define TEST_TESTAL_DMA_CONTIG_FREE(_ptr) \
                do { \
                    if (_ptr) {\
                        TEST_LOG_TRACE("free pointer[%s][%p]\n", #_ptr, (void *)_ptr); \
                        Test_PalDMAContigBufferFree((void *)_ptr); \
                        _ptr = 0; \
                    } \
                } while (0);


/** frees the memory allocated by Test_PalMalloc */
#define TEST_TESTAL_MALLOC_FREE(_ptr) \
                do { \
                    if (_ptr) {\
                        TEST_LOG_TRACE("free pointer[%s][%p]\n", #_ptr, (void *)_ptr); \
                        Test_PalFree((void *)_ptr); \
                        _ptr = 0; \
                    } \
                } while (0);

/** frees the memory */
#ifdef TEE_OS_IS_NO_OS
    #define TEST_FREE(_ptr) TEST_TESTAL_DMA_CONTIG_FREE(_ptr)
#else
    #define TEST_FREE(_ptr) TEST_TESTAL_MALLOC_FREE(_ptr)
#endif

/** Function declarations **/


/**
 * Tests_FillRandBuf() - Fill buffer with random bytes values
 *
 * @buf_p:          The buffer to fill
 * @buf_size:       The size in bytes to fill
 */
void Tests_FillRandBuf(uint8_t *buf_p, uint32_t buf_size);


/**
 * Tests_FillValueBuf() - Fill buffer with random bytes values
 *
 * @buf_p:          The buffer to fill
 * @buf_size:       The size in bytes to fill
 * @value:          The value to copy to each byte of the buffer
 */
void Tests_FillValueBuf(uint8_t *buf_p, uint32_t buf_size, uint8_t value);
/**
 * Tests_InitRand() - Init the random seed for using rand()
 * This function should be called at least once before calls to Tests_FillRandBuf().
 */
void Tests_InitRand(void);

#endif /* _TEST_UTILS_H_ */
