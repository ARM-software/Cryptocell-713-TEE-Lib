/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef TEST_ENGINE_LOG_H_
#define TEST_ENGINE_LOG_H_

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/** defines the longest debug line in log */
#define TE_MAX_LOG_LINE        256

/** defines the print output and the the function to use */
#define TE_PRINT               printf

/** debug level */
#define _crit    0
#define _error   1
#define _warn    2
#define _info    3
#define _debug   4
#define _trace   5

/** default debug level */
#ifndef VERBOSE
#define VERBOSE                 _error
#endif

/** debug implementation */
#define TE_LOG(_level, ...)                                                                                    \
                do {                                                                                            \
                    if (VERBOSE >= _level) {                                                                    \
                        char _buff[TE_MAX_LOG_LINE];                                                           \
                        size_t bufLen = 0;                                                                      \
                        snprintf(_buff, TE_MAX_LOG_LINE - 1, "%-20.20s:%-5u : %-5.5s : ",                      \
                                 __func__, __LINE__, _eitLevelToStr(_level));                                   \
                        bufLen = strlen(_buff);                                                                 \
                        snprintf(_buff + bufLen, TE_MAX_LOG_LINE - bufLen -1, ##__VA_ARGS__);                  \
                        TE_PRINT("%s", _buff);                                                                 \
                    }                                                                                           \
                } while (0)

/** printouts a formatted buffer */
#define TE_LOG_BUFF(_level, _printBuff, _size)                                                                 \
                do {                                                                                            \
                    uint32_t i = 0, j = 0;                                                                      \
                    for (i = 0; i * 16 + j < _size; i++, j = 0)                                                 \
                    {                                                                                           \
                        char tmpBuff[TE_MAX_LOG_LINE] = {0};                                                   \
                        for (j = 0; i * 16 + j < _size && j < 16; j++) {                                        \
                            snprintf(tmpBuff + strlen(tmpBuff), TE_MAX_LOG_LINE - strlen(tmpBuff) - 1,         \
                                     "%02x", ((uint8_t*)_printBuff)[i * 16 + j]);                               \
                        }                                                                                       \
                        TE_LOG(_##_level, "%-10.10s %04x : %s\n", #_printBuff, i, tmpBuff);                       \
                    }                                                                                           \
                } while(0)

/** main log function */
#define TE_LOG_CRIT(...)           TE_LOG(_crit, ##__VA_ARGS__)
#define TE_LOG_ERROR(...)          TE_LOG(_error, ##__VA_ARGS__)
#define TE_LOG_WARN(...)           TE_LOG(_warn, ##__VA_ARGS__)
#define TE_LOG_INFO(...)           TE_LOG(_info, ##__VA_ARGS__)
#define TE_LOG_DEBUG(...)          TE_LOG(_debug, ##__VA_ARGS__)
#define TE_LOG_TRACE(...)          TE_LOG(_trace, ##__VA_ARGS__)

/**
 * Retrieve the string representation of a debug level
 *
 * @param level         the level to retreive
 *
 * @return              a string represnting the debug level 'level'
 */
static inline const char *_eitLevelToStr(uint32_t level)
{
    static const char *levelStr[_trace + 1] = { "crit", "error", "warn", "info", "debug", "trace" };

    if (level <= _trace)
        return levelStr[level];

    return "Unknown";
}

#endif /* TEST_ENGINE_LOG_H_ */
