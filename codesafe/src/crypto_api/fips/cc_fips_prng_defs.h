/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef  _CC_FIPS_PRNG_DEFS_H
#define  _CC_FIPS_PRNG_DEFS_H

#include "cc_rnd_common.h"

CCFipsError_t CC_FipsPrngKat(CCRndGenerateVectWorkFunc_t *f_rng, void *p_prng, CCPrngFipsKatCtx_t *pPrngCtx);

#endif  // _CC_FIPS_PRNG_DEFS_H

