/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef CC_ECPKI_DOMAIN_BP256R1_H
#define CC_ECPKI_DOMAIN_BP256R1_H

/*
 * All the includes that are needed for code using this module to
 * compile correctly should be #included here.
 */
#include "cc_pal_types.h"
#include "cc_ecpki_types.h"

#ifdef __cplusplus
extern "C"
{
#endif

/**
 @brief    the function returns the domain pointer
 @return   return domain pointer

*/
const CCEcpkiDomain_t *CC_EcpkiGetBp256r1DomainP(void);

#ifdef __cplusplus
}
#endif

#endif
