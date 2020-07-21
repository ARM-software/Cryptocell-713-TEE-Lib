/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef  _HW_QUEUE_H
#define  _HW_QUEUE_H

#include "hw_queue_plat.h"
#include "completion_plat.h"
#include "cc_hw_queue_defs.h"
#include "hw_queue_defs_plat.h"
#include "completion.h"

/******************************************************************************
 *                FUNCTION PROTOTYPES
 ******************************************************************************/

/*!
 * This function adds a HW descriptor sequence to a HW queue. If not
 * enough free slot are available in the HW queue, the function will set
 * up the "Water Mark" register and wait on an event until free slots are
 * available.
 *
 * \param descSeq A pointer to a HW descriptor sequence. All descriptor
 *              structures are 6 words.
 *              The sequence buffer is a group of word aligned sequential
 *              descriptor buffers.
 */
void AddHWDescSequence(HwDesc_s* descSeq);

#endif /*FW_HW_QUEUE_H*/

