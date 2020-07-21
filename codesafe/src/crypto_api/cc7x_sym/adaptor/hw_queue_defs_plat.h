/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef __HW_QUEUE_DEFS_PLAT_H__
#define __HW_QUEUE_DEFS_PLAT_H__

#include "cc_pal_barrier.h"

/*****************************/
/* Descriptor packing macros */
/*****************************/

#define HW_QUEUE_FREE_SLOTS_GET() (CC_HAL_READ_REGISTER(CC_REG_OFFSET(CRY_KERNEL, DSCRPTR_QUEUE_CONTENT)) & HW_QUEUE_SLOTS_MAX)

#define HW_QUEUE_POLL_QUEUE_UNTIL_FREE_SLOTS(seqLen)						\
	do {											\
	} while (HW_QUEUE_FREE_SLOTS_GET() < (seqLen))

#define HW_DESC_PUSH_TO_QUEUE(pDesc) do {        				\
	LOG_HW_DESC(pDesc);							\
	HW_DESC_DUMP(pDesc);							\
	CC_HAL_WRITE_REGISTER(GET_HW_Q_DESC_WORD_IDX(0), (pDesc)->word[0]); 	\
	CC_HAL_WRITE_REGISTER(GET_HW_Q_DESC_WORD_IDX(1), (pDesc)->word[1]); 	\
	CC_HAL_WRITE_REGISTER(GET_HW_Q_DESC_WORD_IDX(2), (pDesc)->word[2]); 	\
	CC_HAL_WRITE_REGISTER(GET_HW_Q_DESC_WORD_IDX(3), (pDesc)->word[3]); 	\
	CC_HAL_WRITE_REGISTER(GET_HW_Q_DESC_WORD_IDX(4), (pDesc)->word[4]); 	\
	CC_PalWmb();                                       			\
	CC_HAL_WRITE_REGISTER(GET_HW_Q_DESC_WORD_IDX(5), (pDesc)->word[5]); 	\
	CC_PalWmb();                                       			\
} while (0)

#endif /*__HW_QUEUE_DEFS_PLAT_H__*/
