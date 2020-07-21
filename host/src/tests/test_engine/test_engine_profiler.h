/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef TEST_ENGINE_PROFILER_H_
#define TEST_ENGINE_PROFILER_H_

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define TE_PERF_PARAM_LEN          30
#define TE_PERF_NAME_LEN           50

typedef enum TE_perfType_t {
    TE_PERF_TYPE_TEST_NOT_SET,

    TE_PERF_MAX_ENTRIES = 1024,

    TE_RESERVE32 = 0x7FFFFFFF
} TE_perfIndex_t;

/**
 * @brief   initialise performance test mechanism
 *
 * @param[in]
 * *
 * @return None
 */
void TE_perfInit(void);

/**
 * register api to DB
 *
 * @param func          address of function
 * @param name          name of function
 * @param param         param ti distinguish between flows
 */
void TE_perfEntryInit(const char* name, const char* param);

/**
 * @brief   opens new entry in perf buffer to record new entry
 *
 * @param[in] entryType     entry type (defined in cc_pal_perf.h) to be recorded in buffer
 *
 * @return                  TE_PERF_MAX_ENTRIES in case of failure.
 */
TE_perfIndex_t TE_perfOpenNewEntry(const char* nameStr, const char* paramStr);

/**
 * @brief   closes entry in perf buffer previously opened by TE_perfOpenNewEntry
 *
 * @param[in] entryType -  entry type (defined in cc_pal_perf.h) to be recorded in buffer
 *
 */
void TE_perfCloseEntry(TE_perfIndex_t entryType);

/**
 * @brief   dumps the performance buffer
 *
 * @param[in] None
 *
 * @return None
 */
void TE_perfDump(void);

/**
 * @brief   terminates resources used for performance tests
 *
 * @param[in]
 * *
 * @return None
 */
void TE_perfFin(void);

#endif /* TEST_ENGINE_PROFILER_H_ */
