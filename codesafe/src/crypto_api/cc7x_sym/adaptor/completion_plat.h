/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef  TEE_COMPLETION_PLAT_H
#define  TEE_COMPLETION_PLAT_H

#include "cc_pal_types.h"

/******************************************************************************
*				DEFINES
******************************************************************************/


/******************************************************************************
*				TYPE DEFINITIONS
******************************************************************************/


/*!
 * This function initializes the completion counter event, clears the
 * state structure and sets completion counter "0" as the first available
 * counter to be used when calling "AllocCounter".
 *
 * \return int one of the error codes defined in err.h
 */
void InitCompletionPlat(void);

/*!
 * This function waits for current descriptor sequence completion.
 * \param isPreempt - enable descriptor preemption indication
 *
 */
void WaitForSequenceCompletionPlat(CCBool isPreempt);

/*!
 * This function allocates a reserved word for dummy completion descriptor.
 *
 * \return a non-zero value in case of failure
 */
int AllocCompletionPlatBuffer(void);


/*!
 * This function free resources previuosly allocated by AllocCompletionPlatBuffer.
 */
void FreeCompletionPlatBuffer(void);

#endif /*TEE_COMPLETION_PLAT_H*/

