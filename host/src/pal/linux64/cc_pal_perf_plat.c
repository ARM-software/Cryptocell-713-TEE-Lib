/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */
#define CC_PAL_LOG_CUR_COMPONENT CC_LOG_MASK_CC_SYM_DRIVER

#include "cc_pal_log.h"
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>  //memset()
#include <limits.h>
#include <unistd.h>
#include "dx_reg_base_host.h"
#include "cc_pal_perf.h"

#define SCU_PERIPH_BASE 0xF8F00000
#define SCU_PERIPH_LEN (4*1024)	//4 K length
#define SCU_GTC_VALUE_MSB 0x204
#define SCU_GTC_VALUE_LSB 0x200

#define READ_SCU_REG(offset) \
	(*((volatile uint32_t *)(scuBaseRegVirt + (offset))))


#define IGNORE_SYMMETRIC  1

static int halArmRegFileH = -1;
static uint32_t   scuBaseRegVirt = 0;

typedef struct {
	uint32_t opCount; /* Number of operations measured */
	CCPalPerfData_t totalVal; /* Accumulated cycles/uSec */
	CCPalPerfData_t maxVal; /* Maximum cycles/usec */
	CCPalPerfData_t minVal; /* Minimum cycles/usec */
} LibPerfStats_t;


/* Performance statistics for init/process/finalize/integrated */
LibPerfStats_t libPerfStats[PERF_TEST_TYPE_MAX];

static inline CCPalPerfData_t get_libCyclecount(void)
{
        uint32_t valMsb;
        uint32_t valMsbPrev;
        uint32_t valLsb;
	CCPalPerfData_t totalVal = 0;

	if (scuBaseRegVirt <= 0) {
		CC_PAL_LOG_ERR("Invalid scuBaseRegVirt\n");
		return 0;
	}

        valMsbPrev = READ_SCU_REG(SCU_GTC_VALUE_MSB);
        valLsb = READ_SCU_REG(SCU_GTC_VALUE_LSB);
        valMsb = READ_SCU_REG(SCU_GTC_VALUE_MSB);
        if (valMsbPrev != valMsb) {
                /* MSB change detected. Retry reading MSB */
                valMsbPrev = valMsb;
                valLsb = READ_SCU_REG(SCU_GTC_VALUE_LSB);
                valMsb = READ_SCU_REG(SCU_GTC_VALUE_MSB);
                if(valMsbPrev != valMsb) { /* This time MSB couldn't have changed so quickly */
			CC_PAL_LOG_ERR("valMsbPrev != valMsb\n");
			return 0;
		}
        }
        /* Assume Zynq global counter running at half CPU rate of 333Mhz */
	totalVal = (((CCPalPerfData_t)valMsb<<32) | valLsb)<<1;
        return (totalVal);
}

void init_Perfcounters()
{
	uint32_t *pMapBase = NULL;
	/* Open device file if not already opened */
	if (halArmRegFileH >= 0) { /* already opened */
		return;
	}
	scuBaseRegVirt = 0;
	halArmRegFileH = open("/dev/mem", O_RDWR|O_SYNC);
	if (halArmRegFileH < 0) {
		CC_PAL_LOG_ERR("Invalid halArmRegFileH\n");
		return;
	}
	(void)fcntl(halArmRegFileH, F_SETFD, FD_CLOEXEC);

	pMapBase = mmap(0, SCU_PERIPH_LEN, PROT_READ|PROT_WRITE, MAP_SHARED, halArmRegFileH, SCU_PERIPH_BASE);
	if ((pMapBase == NULL) || (pMapBase == MAP_FAILED)) {
		close(halArmRegFileH);
		halArmRegFileH = -1;
		CC_PAL_LOG_ERR("Invalid pMapBase\n");
		return;
	}
	scuBaseRegVirt =  (uint32_t)pMapBase;
}

void finish_Perfcounters()
{
	munmap((uint32_t *)scuBaseRegVirt, SCU_PERIPH_LEN);
	close(halArmRegFileH);
	halArmRegFileH = -1;
	scuBaseRegVirt = 0;
}

/*!
 * Accumulate given cycles or latency (in nSec) to the statistics
 *
 * \param val cycles/time in nsec
 * \param opType Operation type
 */
void LibStatsValAccum(CCPalPerfData_t val,  CCPalPerfType_t opType)
{
	libPerfStats[opType].opCount++;
	libPerfStats[opType].totalVal += val;
	if ((val < libPerfStats[opType].minVal) ||
	    (1 == libPerfStats[opType].opCount)) {
		libPerfStats[opType].minVal = val;
	}
	if (val > libPerfStats[opType].maxVal) {
		libPerfStats[opType].maxVal = val;
	}

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////  cycle implemetation ///////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#if CC_PLAT_ZYNQ7000

/**
 * @brief   initialize performance test mechanism
 *
 * @param[in]
 * *
 * @return None
 */
void CC_PalPerfInit(void)
{
	init_Perfcounters();
	memset(&libPerfStats, 0, sizeof(libPerfStats));
}

/**
 * @brief   terminates resources used for performance tests
 *
 * @param[in]
 * *
 * @return None
 */
void CC_PalPerfFin(void)
{
	finish_Perfcounters();
	memset(&libPerfStats, 0, sizeof(libPerfStats));
}

/**
 * @brief   opens new entry in perf buffer to record new entry
 *
 * @param[in] entryType -  entry type (defined in cc_pal_perf.h) to be recorded in buffer
 *
 * @return Returns a non-zero value in case of failure
 */
CCPalPerfData_t CC_PalPerfOpenNewEntry(CCPalPerfType_t perfType)
{
	CCPalPerfData_t curCycles = 0;
	curCycles =  get_libCyclecount();
	CC_PAL_LOG_INFO("CC_PalPerfOpenNewEntry ended 0x%x \n", curCycles);
	return curCycles;
}

/**
 * @brief   closes entry in perf buffer previously opened by CC_PalPerfOpenNewEntry
 *
 * @param[in] idx -  index of the entry to be closed, the return value of CC_PalPerfOpenNewEntry
 * @param[in] entryType -  entry type (defined in cc_pal_perf.h) to be recorded in buffer
 *
 * @return Returns a non-zero value in case of failure
 */
void CC_PalPerfCloseEntry(CCPalPerfData_t startCycles, CCPalPerfType_t opType)
{
	CCPalPerfData_t curCycles = 0;
	CCPalPerfData_t totalVal = 0;

	if ((opType >= PERF_TEST_TYPE_MAX) ||
	    (0 == startCycles)) {
		CC_PAL_LOG_ERR("%s Invalid opType=%d or startCycles %lld\n", __FUNCTION__, opType, startCycles);
		return;
	}
#if IGNORE_SYMMETRIC
	if ((opType < PERF_TEST_TYPE_PKA_ModExp) ||
	    (opType >= PERF_TEST_TYPE_TEST_BASE)) {
		return;
	}
#endif
	curCycles = get_libCyclecount();
	if (0 == curCycles) {
		CC_PAL_LOG_ERR("0 == curCycles\n");
		return;
	}
	if (curCycles < startCycles) {
		totalVal = (UINT64_MAX-startCycles)+curCycles;
	} else {
		totalVal = curCycles - startCycles;
	}
	LibStatsValAccum(totalVal,  opType);
	CC_PAL_LOG_INFO("CC_PalPerfCloseEntry ended 0x%x\n", totalVal);
}

/**
 * @brief   dumps the performance buffer
 *
 * @param[in] None
 *
 * @return None
 */
void CC_PalPerfDump()
{
	int i;
	CCPalPerfData_t avgCycles;

#if IGNORE_SYMMETRIC
	for (i = PERF_TEST_TYPE_PKA_ModExp; i < PERF_TEST_TYPE_TEST_BASE; i++) {
#else
	for (i = PERF_TEST_TYPE_CC_AES_INTGR; i < PERF_TEST_TYPE_MAX; i++) {
#endif
		if (libPerfStats[i].opCount != 0) {
			avgCycles = libPerfStats[i].totalVal / libPerfStats[i].opCount;
		} else {
			continue;
		}
		CC_PAL_LOG_INFO("0x%x: count=%d  cycles=[min,avg,max,sum] %lld %lld %lld %lld \n",
		     i, libPerfStats[i].opCount, libPerfStats[i].minVal, avgCycles, libPerfStats[i].maxVal, libPerfStats[i].totalVal );
	}
}


#else  //CC_PLAT_ZYNQ7000
/**
 * @brief   initialize performance test mechanism
 *
 * @param[in]
 * *
 * @return None
 */
void CC_PalPerfInit(void)
{
}

/**
 * @brief   terminates resources used for performance tests
 *
 * @param[in]
 * *
 * @return None
 */
void CC_PalPerfFin(void)
{
}

/**
 * @brief   opens new entry in perf buffer to record new entry
 *
 * @param[in] entryType -  entry type (defined in cc_pal_perf.h) to be recorded in buffer
 *
 * @return Returns a non-zero value in case of failure
 */
CCPalPerfData_t CC_PalPerfOpenNewEntry(CCPalPerfType_t perfType)
{
}

/**
 * @brief   closes entry in perf buffer previously opened by CC_PalPerfOpenNewEntry
 *
 * @param[in] idx -  index of the entry to be closed, the return value of CC_PalPerfOpenNewEntry
 * @param[in] entryType -  entry type (defined in cc_pal_perf.h) to be recorded in buffer
 *
 * @return Returns a non-zero value in case of failure
 */
void CC_PalPerfCloseEntry(CCPalPerfData_t startCycles, CCPalPerfType_t opType)
{
}

/**
 * @brief   dumps the performance buffer
 *
 * @param[in] None
 *
 * @return None
 */
void CC_PalPerfDump()
{
}
#endif  //CC_PLAT_ZYNQ7000
