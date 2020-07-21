/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _CC_ECPKI_DOMAIN_DEFS_H
#define _CC_ECPKI_DOMAIN_DEFS_H

/*!
@file
@brief This file contains domains supported by project.
*/
 /*!
 @addtogroup ecpki_domain_defs
 @{
     */

#ifdef __cplusplus
extern "C"
{
#endif

#include "cc_ecpki_domain_secp192r1.h"
#include "cc_ecpki_domain_secp224r1.h"
#include "cc_ecpki_domain_secp256r1.h"
#include "cc_ecpki_domain_secp521r1.h"
#include "cc_ecpki_domain_secp192k1.h"
#include "cc_ecpki_domain_secp224k1.h"
#include "cc_ecpki_domain_secp256k1.h"
#include "cc_ecpki_domain_secp384r1.h"


 /*! Definition of domain function. */
typedef const CCEcpkiDomain_t * (*getDomainFuncP)(void);

#ifdef __cplusplus
}
#endif
 /*!
 @}
 */
#endif



