/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef TEST_ENGINE_HELPER_H_
#define TEST_ENGINE_HELPER_H_

#include <stdlib.h>
#include <string.h>

#include "test_engine_log.h"

/** used to avoid compilation errors */
#define TE_UNUSED(_a)          (void)_a

/** defines the action that should be performed in case _cmd != _exp. use _err in case of failure. */
#define TE_ASSERT_PASS(_cmd, _exp) \
                do { \
                    TE_rc_t _res = TE_RC_SUCCESS; \
                    TE_LOG_TRACE("running [%s]\n", #_cmd); \
                    if ((_res = (_cmd)) != (TE_rc_t)(_exp)) { \
                        TE_LOG_CRIT("failed with res[0x%04x]\n", _res); \
                        res = _res; \
                        goto bail; \
                    } \
                } while (0)

#define TE_ASSERT_ERR(_cmd, _exp, _err) \
                do { \
                    TE_rc_t _res = TE_RC_SUCCESS; \
                    TE_LOG_TRACE("running [%s]\n", #_cmd); \
                    if ((_res = (_cmd)) != (TE_rc_t)(_exp)) { \
                        TE_LOG_CRIT("failed with res[0x%04x]\n", _res); \
                        res = _err; \
                        goto bail; \
                    } \
                } while (0)

/** defines the action that should be performed in case _cmd != true. */
#define TE_ASSERT(_cmd) \
                do { \
                    TE_LOG_TRACE("running [%s]\n", #_cmd); \
                    if ((_cmd) == 0) { \
                        TE_LOG_CRIT("failed\n"); \
                        res = TE_RC_FAIL; \
                        goto bail; \
                    } \
                } while (0)

/** allocates and initialises the memory */
#define TE_ALLOC(_ptr, _size) \
                do { \
                    _ptr = calloc(1, _size); \
                    if (_ptr == NULL){ \
                        TE_LOG_CRIT("failed to allocate [%s] of size[%zu]\n", #_ptr, _size); \
                        res = TE_RC_FAIL; \
                        goto bail; \
                    } \
                    TE_LOG_TRACE("allocated pointer[%s][%p] of size[%zu]\n", #_ptr, _ptr, _size); \
                } while (0);

/** frees the memory */
#define TE_FREE(_ptr) \
                do { \
                    if (_ptr) {\
                        TE_LOG_TRACE("free pointer[%s][%p]\n", #_ptr, _ptr); \
                        free(_ptr); \
                    } \
                } while (0);

#endif /* TEST_ENGINE_HELPER_H_ */
