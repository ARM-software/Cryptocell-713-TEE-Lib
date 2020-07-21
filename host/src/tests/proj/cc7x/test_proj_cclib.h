/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _TEST_PROJ_CCLIB_H_
#define _TEST_PROJ_CCLIB_H_

#ifdef CC_SUPPORT_FULL_PROJECT
#ifdef CC_SUPPORT_FIPS
#include "cc_fips.h"
#endif /* CC_SUPPORT_FIPS */
#endif /* CC_SUPPORT_FULL_PROJECT */

/****************************************************************************/
/*
 * @brief This function
 *
 * @param[in/out]
  *
 * @return rc -
 */
int Test_Proj_CC_LibInit_Wrap(void);

void Test_Proj_CC_LibFini_Wrap(void);

#ifdef CC_SUPPORT_FULL_PROJECT
#ifdef CC_SUPPORT_FIPS
int Test_ProjSetReeFipsError(uint32_t  reeError, CCFipsState_t expfipsState);
#endif /* CC_SUPPORT_FIPS */
#endif /* CC_SUPPORT_FULL_PROJECT */

#endif /* _TEST_PROJ_CCLIB_H_ */

