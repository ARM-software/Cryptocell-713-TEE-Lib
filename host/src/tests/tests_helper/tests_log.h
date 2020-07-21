/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef TEST_LOG_H_
#define TEST_LOG_H_

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "test_pal_log.h"
#include "cc_pal_compiler.h"

/** defines the longest debug line in log */
#define TEST_MAX_LOG_LINE        256

/** defines the print output and the the function to use */
#define TEST_PRINT               TEST_PRINTF_MESSAGE

/** debug level */
#define _crit    0
#define _error   1
#define _warn    2
#define _info    3
#define _debug   4
#define _trace   5

/** default debug level */
#ifndef VERBOSE
#define VERBOSE                 _info
#endif

/** debug implementation */
#define TEST_LOG(_level, ...)                                                                                   \
                do {                                                                                            \
                    if (VERBOSE >= _level) {                                                                    \
                        char _buff[TEST_MAX_LOG_LINE];                                                          \
                        size_t bufLen = 0;                                                                      \
                        snprintf(_buff, TEST_MAX_LOG_LINE - 1, "%-20.20s:%-5u : %-5.5s : ",                     \
                                 __func__, __LINE__, _menuEitLevelToStr(_level));                               \
                        bufLen = strlen(_buff);                                                                 \
                        snprintf(_buff + bufLen, TEST_MAX_LOG_LINE - bufLen -1, ##__VA_ARGS__);                 \
                        TEST_PRINT("%s", _buff);                                                                \
                    }                                                                                           \
                } while (0)

/** printouts a formatted buffer */
#define TEST_LOG_BUFF(_level, _printBuff, _size)                                                                \
                do {                                                                                            \
                    if (VERBOSE >= _level) {                                                                    \
                        uint32_t i = 0, j = 0;                                                                  \
                        for (i = 0; i * 16 + j < (uint32_t)_size; i++, j = 0)                                   \
                        {                                                                                       \
                            char tmpBuff[TEST_MAX_LOG_LINE] = {0};                                              \
                            for (j = 0; i * 16 + j < (uint32_t)_size && j < 16; j++) {                          \
                                snprintf(tmpBuff + strlen(tmpBuff), TEST_MAX_LOG_LINE - strlen(tmpBuff) - 1,    \
                                         "%02x", ((uint8_t*)_printBuff)[i * 16 + j]);                           \
                            }                                                                                   \
                            TEST_LOG(_level, "%-30.30s %04x : %s\n", #_printBuff, i, tmpBuff);                  \
                        }                                                                                       \
                    }                                                                                           \
                } while(0)

/** main log function */
#define TEST_LOG_CRIT(...)          TEST_LOG(_crit, ##__VA_ARGS__)
#define TEST_LOG_ERROR(...)         TEST_LOG(_error, ##__VA_ARGS__)
#define TEST_LOG_WARN(...)          TEST_LOG(_warn, ##__VA_ARGS__)
#define TEST_LOG_INFO(...)          TEST_LOG(_info, ##__VA_ARGS__)
#define TEST_LOG_DEBUG(...)         TEST_LOG(_debug, ##__VA_ARGS__)
#define TEST_LOG_TRACE(...)         TEST_LOG(_trace, ##__VA_ARGS__)


/** buffer log function */
#define TEST_LOG_BUFF_CRIT(_printBuff, _size)           TEST_LOG_BUFF(_crit, _printBuff, _size)
#define TEST_LOG_BUFF_ERROR(_printBuff, _size)          TEST_LOG_BUFF(_error, _printBuff, _size)
#define TEST_LOG_BUFF_WARN(_printBuff, _size)           TEST_LOG_BUFF(_warn, _printBuff, _size)
#define TEST_LOG_BUFF_INFO(_printBuff, _size)           TEST_LOG_BUFF(_info,_printBuff, _size)
#define TEST_LOG_BUFF_DEBUG(_printBuff, _size)          TEST_LOG_BUFF(_debug, _printBuff, _size)
#define TEST_LOG_BUFF_TRACE(_printBuff, _size)          TEST_LOG_BUFF(_trace, _printBuff, _size)


/**
 * Retrieve the string representation of a debug level
 *
 * @param level         the level to retrieve
 *
 * @return              a string representing the debug level 'level'
 */
static inline const char *_menuEitLevelToStr(uint32_t level)
{
    static const char *levelStr[_trace + 1] = { "crit", "err", "warn", "info", "debug", "trace" };

    if (level <= _trace)
        return levelStr[level];

    return "Unknown";
}

#endif /* TEST_LOG_H_ */
