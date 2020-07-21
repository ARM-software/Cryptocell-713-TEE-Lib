/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef  _CC_UTIL_RPMB_ADAPTOR_H
#define  _CC_UTIL_RPMB_ADAPTOR_H

/************* Include Files ****************/
#include "cc_util.h"
#include "cc_util_rpmb.h"
#include "cc_util_int_defs.h"
#include "cc_sym_error.h"
#include "cc_hmac.h"
#include "cc_pal_mutex.h"
#include "sym_adaptor_driver.h"
#include "sym_adaptor_driver_int.h"

/************************ Defines ******************************/
#define CC_HMAC_USER_CTX_ACTUAL_SIZE_IN_WORDS	((CC_HMAC_USER_CTX_SIZE_IN_WORDS - 3)/2)
typedef struct CCHmacPrivateContext_t {
	uint32_t isLastBlockProcessed;
} CCHmacPrivateContext_t;

#define RPMB_KEY_DERIVATION_LABAL	0x52,0x50,0x4D,0x42,0x20,0x4B,0x45,0x59 // "RPMB KEY"
#define RPMB_KEY_DERIVATION_CONTEXT	0x41,0x52,0x4D,0x20 // "ARM "

/* To perform hash update, we join 64 data frames together to one chunk (284*64).
   Hence, in case of un-contiguous frames, there is up to 128 MLLI entries */
#define RPMB_MAX_BLOCKS_PER_UPDATE	64
#define RPMB_MAX_PAGES_PER_BLOCK	2

typedef struct {
	uint32_t				numOfBlocks[RPMB_MAX_BLOCKS_PER_UPDATE];
	CCPalDmaBlockInfo_t  	pBlockEntry[RPMB_MAX_PAGES_PER_BLOCK];
}RpmbDmaBuffBlocksInfo_t;

typedef struct {
	mlliTable_t 			devBuffer;
	RpmbDmaBuffBlocksInfo_t	blocksList;
	CC_PalDmaBufferHandle	buffMainH[RPMB_MAX_BLOCKS_PER_UPDATE];
	CC_PalDmaBufferHandle	buffMlliH;
}RpmbDmaBuildBuffer_t;


/************************ Extern variables *********************/
extern CC_PalMutex CCSymCryptoMutex;


/****************************************************************
*				          RPMB internal functions
*****************************************************************/

int RpmbSymDriverAdaptorModuleInit(void);

int RpmbSymDriverAdaptorModuleTerminate(void);

CCError_t RpmbHmacInit(CCHmacUserContext_t *ContextID_ptr,
                                uint8_t *key_ptr,
                                size_t keySize);

CCError_t RpmbHmacUpdate(CCHmacUserContext_t  *ContextID_ptr,
								unsigned long   *pListOfDataFrames,
								uint32_t          		listSize);

CCError_t RpmbHmacFinish(CCHmacUserContext_t  *ContextID_ptr,
								CCHashResultBuf_t       HmacResultBuff );

#endif /*_CC_UTIL_RPMB_ADAPTOR_H */
