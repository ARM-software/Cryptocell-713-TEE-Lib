/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef  _COMPLETION_H
#define  _COMPLETION_H

#include "completion_plat.h"

/******************************************************************************
 *                       MACROS
 ******************************************************************************/

/******************************************************************************
 *                FUNCTION PROTOTYPES
 ******************************************************************************/

/*!
 * This function calls the platform specific Completion Initializer function.
 *
 * \return int one of the error codes defined in err.h
 */
#define InitCompletion InitCompletionPlat

/*!
 * This function waits for current descriptor sequence completion.
 * The "WaitForSequenceCompletionPlat" function must implement by
 * the platform port layer.
 */
#define WaitForSequenceCompletion WaitForSequenceCompletionPlat

#endif /*_COMPLETION_H*/

