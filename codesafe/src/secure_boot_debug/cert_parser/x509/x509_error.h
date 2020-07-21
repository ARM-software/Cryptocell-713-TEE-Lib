/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _SB_X509_ERROR_H
#define _SB_X509_ERROR_H

#include "secureboot_error.h"

#ifdef __cplusplus
extern "C"
{
#endif


#define CC_SB_X509_CERT_INV_PARAM              			CC_SB_X509_CERT_BASE_ERROR + 0x00000001
#define CC_SB_X509_CERT_PARSE_ILLEGAL_VAL      			CC_SB_X509_CERT_BASE_ERROR + 0x00000002


#ifdef __cplusplus
}
#endif

#endif


