/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

/*!
 @file
 @brief This file includes all PAL APIs.
 */


  /*!
  @addtogroup cc_pal_abort
  @{
	*/
#ifndef _CC_PAL_ABORT_H
#define _CC_PAL_ABORT_H


#include "cc_pal_abort_plat.h"


/*!
  @brief This function performs the "Abort" operation. It must be implemented according to the specific platform and OS.
*/
void CC_PalAbort(const char * exp);

/*!
  @}
  */

#endif

