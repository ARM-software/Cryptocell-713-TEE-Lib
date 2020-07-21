/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef CC_ECPKI_DOMAIN_SM2_H
#define CC_ECPKI_DOMAIN_SM2_H



/*!
@file
@brief This file defines the SM2 get domain API.
*/

/*!
 @addtogroup cc_sm2
 @{
 */

#include "cc_pal_types.h"
#include "cc_ecpki_types.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*!
 @brief    Returns the domain pointer of SM2.
 @return   Domain pointer.

*/
const CCEcpkiDomain_t *CC_EcpkiGetSm2Domain(void);

#ifdef __cplusplus
}
#endif
/*!
 @}
 */
#endif /* CC_ECPKI_DOMAIN_SM2_H */

