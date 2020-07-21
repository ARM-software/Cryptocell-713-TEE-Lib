/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <math.h>
#include <time.h>
#include <limits.h>
#include <errno.h>

#include "test_engine_profiler.h"


/* local */
#include "test_engine_helper.h"
#include "test_engine_log.h"
#include "test_engine_types.h"

/****************************************************************************
 *
 * defines
 *
 ****************************************************************************/
#define TE_DEBUG_PROFILER          0
#define TE_PERFDUMP_LENGTH         256

#define TE_MICROSECONDS            1000000U
#define TE_NANOSECONDS             1000000000U

#define MAX(a,b)            (a) > (b) ? (a) : (b)
#define MIN(a,b)            (a) < (b) ? (a) : (b)
#define DIV(a,b)            ((b) == 0) ? 0 : ((a)/(b))

/****************************************************************************
 *
 * Types
 *
 ****************************************************************************/
typedef struct TE_palPerfCounter_t {
    uint32_t numOfEntries;

    char param[TE_PERF_PARAM_LEN];
    char name[TE_PERF_NAME_LEN];

    uint64_t totalCycles;
    uint64_t totalStdDev;

    uint64_t max;
    uint64_t min;

    uint32_t prevCycles;
    uint32_t totalCounts;
} TE_palPerfCounter_t;

/****************************************************************************
 *
 * globals
 *
 ****************************************************************************/
/**
 * An array of results per function. Each function updated the data.
 */
static TE_palPerfCounter_t resultsArr[TE_PERF_MAX_ENTRIES];
static uint32_t nextFreeIndex = 0;

/****************************************************************************
 *
 * static prototypes
 *
 ****************************************************************************/
static TE_perfIndex_t TE_perfTypeFromName(const char* nameStr, const char* paramStr, bool shouldFind);
static uint32_t TE_getCycles(void);
static uint64_t TE_getMicroSec(uint64_t cycles);

/****************************************************************************
 *
 * static functions
 *
 ****************************************************************************/
static TE_perfIndex_t TE_perfTypeFromName(const char* nameStr, const char* paramStr, bool shouldFind)
{
    uint32_t index = 0;
    for (index = 0; index < nextFreeIndex; ++index)
    {
        TE_palPerfCounter_t* pCyclesData = &resultsArr[index];

        if ((strncmp(pCyclesData->name, nameStr, TE_PERF_NAME_LEN) == 0)
                        && (strncmp(pCyclesData->param, paramStr, TE_PERF_PARAM_LEN) == 0))
        {
            return (TE_perfIndex_t) index;
        }
    }

    if (shouldFind)
    {
        TE_LOG_ERROR("couldn't find name[%s] param[%s] in DB\n", nameStr, paramStr);
    }

    return TE_PERF_MAX_ENTRIES;
}


static uint32_t TE_getCycles(void)
{
    struct timespec t;

    int res = clock_gettime(CLOCK_REALTIME, &t);
    if (res)
    {
        TE_LOG_ERROR("failed to get nanoseconds[%s][%u]\n", strerror(errno), errno);
        return 0;
    }

    return (int64_t) (t.tv_sec) * (int64_t) TE_NANOSECONDS + (int64_t) (t.tv_nsec);
}

/**
 *
 * @param cycles
 * @return          microSeconds
 */
static uint64_t TE_getMicroSec(uint64_t cycles)
{
    return ((cycles * TE_MICROSECONDS) / TE_NANOSECONDS);
}

/****************************************************************************
 *
 * public
 *
 ****************************************************************************/
void TE_perfEntryInit(const char* name, const char* param)
{
    TE_palPerfCounter_t* pCyclesData = NULL;
    uint32_t index = 0;

    /* check if DB full */
    if (nextFreeIndex >= TE_PERF_MAX_ENTRIES)
    {
        TE_LOG_ERROR("nextFreeIndex is at maximum. Can't register test\n");
        return;
    }

    /* check if not duplicate registration */
    if ((index = TE_perfTypeFromName(name, param, 0)) != TE_PERF_MAX_ENTRIES)
    {
        (void) index;
        TE_LOG_DEBUG("func[%s] with param[%s] is already registered at index[%u]\n",
                     name,
                     param,
                     index);
        return;
    }

    /* store data into entry */
    pCyclesData = &resultsArr[nextFreeIndex];
    strncpy(pCyclesData->param, param, TE_PERF_PARAM_LEN - 1);
    strncpy(pCyclesData->name, name, TE_PERF_NAME_LEN - 1);

    /* advance next free index */
    nextFreeIndex++;
}

void TE_perfInit(void)
{
    TE_perfIndex_t funcIndex;

    (void) TE_getCycles;

    for (funcIndex = (TE_perfIndex_t) 0; funcIndex < TE_PERF_MAX_ENTRIES; ++funcIndex)
    {
        TE_palPerfCounter_t* pCyclesData = &resultsArr[funcIndex];

        memset(pCyclesData->param, 0, TE_PERF_PARAM_LEN);
        memset(pCyclesData->name, 0, TE_PERF_NAME_LEN);

        pCyclesData->prevCycles = 0;
        pCyclesData->totalCounts = 0;
        pCyclesData->totalStdDev = 0;
        pCyclesData->totalCycles = 0;
        pCyclesData->max = 0;
        pCyclesData->min = (uint64_t) -1;
    }

    nextFreeIndex = 0;
}

void TE_perfFin(void)
{
    // nothing to be done
}

TE_perfIndex_t TE_perfOpenNewEntry(const char* nameStr, const char* paramStr)
{
    TE_perfIndex_t entryType;

    /* check if not duplicate registration */
    if ((entryType = TE_perfTypeFromName(nameStr, paramStr, 1)) == TE_PERF_MAX_ENTRIES)
    {
        return TE_PERF_MAX_ENTRIES;
    }

    TE_palPerfCounter_t* pCyclesData = &resultsArr[entryType];

    pCyclesData->prevCycles = TE_getCycles();

    return entryType;
}

void TE_perfCloseEntry(TE_perfIndex_t entryIndex)
{
    TE_palPerfCounter_t* pCyclesData = &resultsArr[entryIndex];
    uint32_t cycles = TE_getCycles();

    /* in case pointer of of bounds, return  */
    if (entryIndex >= TE_PERF_MAX_ENTRIES)
        return;

#if TE_DEBUG_PROFILER
    {
        char buff[41];
        TE_perfTypeStr(entryType, buff, 40);
        TE_LOG_ERROR("type[%s] cycles[%u] prevCycles[%u] diff[%u]\n", buff, cycles, pCyclesData->prevCycles, cycles - pCyclesData->prevCycles);
    }
#endif

    cycles = cycles - pCyclesData->prevCycles;

    pCyclesData->totalCycles += cycles;
    pCyclesData->totalStdDev += cycles * cycles;
    pCyclesData->totalCounts += 1;

    pCyclesData->max = MAX(pCyclesData->max, cycles);
    pCyclesData->min = MIN(pCyclesData->min, cycles);
}

void TE_perfDump(void)
{
    TE_perfIndex_t i;
    char buff[TE_PERFDUMP_LENGTH];
    const char *dash = "-----------------------------------------------------------------"
                    "-----------------------------------------------------------------"
                    "-----------------------------------------------------------------";

    uint32_t length = snprintf(buff,
                               TE_PERFDUMP_LENGTH,
                               "| %-50.50s | %-30.30s | %-10.10s | %-15.15s | %-15.15s | %-15.15s | %-15.15s | %-15.15s |",
                               "Function",
                               "Param",
                               "countTests",
                               "TimePerCall,uS",
                               "CallsPerSec",
                               "ClocksPerCall",
                               "ClocksMin",
                               "ClocksMax");

    // Print header
    TE_PRINT("%*.*s\n%s\n%*.*s\n", length, length, dash, buff, length, length, dash);

    for (i = TE_PERF_TYPE_TEST_NOT_SET; i < nextFreeIndex; i++)
    {
        uint64_t totalCycles = 0;
        uint32_t totalCounts = 0;
        uint64_t avgCycles;
        uint64_t min;
        uint64_t max;
        uint64_t totalStdDev;
        uint64_t stdDev;

        (void) stdDev;
        (void) totalStdDev;

        totalCycles = resultsArr[i].totalCycles;
        totalCounts = resultsArr[i].totalCounts;
        totalStdDev = resultsArr[i].totalStdDev;
        min = totalCycles != 0 ? resultsArr[i].min : 0;
        max = resultsArr[i].max;

        if (totalCycles == 0)
            continue;

        avgCycles = DIV(totalCycles, totalCounts);

        TE_PRINT("| %-50.50s | %-30.30s | %10u | %15zu | %15" PRIu64 " | %15zu | %15zu | %15zu |\n",
                 resultsArr[i].name,
                 resultsArr[i].param,
                 totalCounts,
                 (size_t)TE_getMicroSec(avgCycles),
                 (int64_t )DIV(TE_MICROSECONDS, TE_getMicroSec(avgCycles)),
                 (size_t)avgCycles,
                 (size_t)min,
                 (size_t)max);
    }

    TE_PRINT("%*.*s\n", length, length, dash);
}

