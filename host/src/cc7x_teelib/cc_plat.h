/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef  CC_PLAT_H
#define  CC_PLAT_H

#include "cc_pal_types.h"
#include "cc_address_defs.h"

#ifndef CMPU_UTIL
#include "cc_pal_mutex.h"
#include "cc_pal_abort.h"

extern CC_PalMutex CCSymCryptoMutex;
#endif


#define NULL_SRAM_ADDR ((CCSramAddr_t)0xFFFFFFFF)

#define IS_SCHEDULER_RUNNING() (1) /*in signle task application always busy*/


/******************************************************************/
/******************************************************************/
/* The below MACROS are used by the driver to access the context. */
/* Since the context is in the SRAM it must use indirect access to*/
/* the ARM TrustZone CryptoCell internal SRAM.                                          */
/******************************************************************/
/******************************************************************/
#define _WriteWordsToSram(addr, data, size) \
do { \
	uint32_t ii; \
	uint32_t dummy; \
	CC_HAL_WRITE_REGISTER( CC_REG_OFFSET (HOST_RGF,SRAM_ADDR), (addr)); \
	for( ii = 0 ; ii < size/sizeof(uint32_t) ; ii++ ) { \
		   CC_HAL_WRITE_REGISTER( CC_REG_OFFSET (HOST_RGF,SRAM_DATA), SWAP_TO_LE(((uint32_t *)data)[ii])); \
		   do { \
		     dummy = CC_HAL_READ_REGISTER( CC_REG_OFFSET (HOST_RGF, SRAM_DATA_READY)); \
		   }while(!(dummy & 0x1)); \
	} \
}while(0)



#define _ClearSram(addr, size) \
do { \
	uint32_t ii; \
	uint32_t dummy; \
	CC_HAL_WRITE_REGISTER( CC_REG_OFFSET(HOST_RGF, SRAM_ADDR), (addr) ); \
	for( ii = 0 ; ii < size/sizeof(uint32_t) ; ii++ ) { \
		CC_HAL_WRITE_REGISTER( CC_REG_OFFSET (HOST_RGF,SRAM_DATA), 0 ); \
		do { \
			dummy = CC_HAL_READ_REGISTER( CC_REG_OFFSET(HOST_RGF, SRAM_DATA_READY)); \
		}while(!(dummy & 0x1)); \
	}\
}while(0)


#define _ReadValueFromSram(addr, Val) \
do { \
	uint32_t dummy; \
	CC_HAL_WRITE_REGISTER( CC_REG_OFFSET (HOST_RGF,SRAM_ADDR), (addr) ); \
	dummy = CC_HAL_READ_REGISTER( CC_REG_OFFSET (HOST_RGF,SRAM_DATA)); \
	do { \
		dummy = CC_HAL_READ_REGISTER( CC_REG_OFFSET (HOST_RGF, SRAM_DATA_READY)); \
	}while(!(dummy & 0x1)); \
	dummy = CC_HAL_READ_REGISTER( CC_REG_OFFSET (HOST_RGF,SRAM_DATA)); \
	(Val) = SWAP_TO_LE(dummy);\
	do { \
		dummy = CC_HAL_READ_REGISTER( CC_REG_OFFSET (HOST_RGF, SRAM_DATA_READY) ); \
	}while(!(dummy & 0x1)); \
}while(0)


#define _ReadWordsFromSram( addr , data , size ) \
do { \
	uint32_t ii; \
	uint32_t dummy; \
	CC_HAL_WRITE_REGISTER( CC_REG_OFFSET (HOST_RGF,SRAM_ADDR) ,(addr) ); \
	dummy = CC_HAL_READ_REGISTER( CC_REG_OFFSET (HOST_RGF,SRAM_DATA)); \
	for( ii = 0 ; ii < size/sizeof(uint32_t) ; ii++ ) { \
		do { \
			dummy = CC_HAL_READ_REGISTER( CC_REG_OFFSET (HOST_RGF, SRAM_DATA_READY)); \
		}while(!(dummy & 0x1)); \
		dummy = CC_HAL_READ_REGISTER( CC_REG_OFFSET (HOST_RGF,SRAM_DATA));\
		((uint32_t*)data)[ii] = SWAP_TO_LE(dummy); \
	} \
	do { \
		dummy = CC_HAL_READ_REGISTER( CC_REG_OFFSET (HOST_RGF, SRAM_DATA_READY)); \
	}while(!(dummy & 0x1)); \
}while(0)


/****************************************************************************************/
/**
 *
 * @brief The function gets one word from the context.
 *
 *
 * @param[in] addr - The address of the word ( pointer to a word in the context).
 *
 * @return uint32_t - The value of that address.
 */
uint32_t ReadContextWord(const CCSramAddr_t addr);


/****************************************************************************************/
/**
 *
 * @brief The function writes one word to the context.
 *
 *
 * @param[in] addr - The address of the word ( pointer to a word in the context).
 *
 * @param[in] data - The vaule to be written.
 *
 * @return void.
 */
void WriteContextWord(CCSramAddr_t addr, uint32_t data);

/****************************************************************************************/
/**
 *
 * @brief The function clears field in the context.
 *
 *
 * @param[in] addr - The address of the field ( pointer to the field in the context).
 *
 * @param[in] size - The size of the field in bytes.
 *
 * @return void.
 */
void ClearCtxField(CCSramAddr_t addr, uint32_t size);

/****************************************************************************************/
/**
 *
 * @brief The function update array field in the context (more than one word).
 *
 *
 * @param[in] addr - The address of the field ( pointer to the field in the context).
 *
 * @param[in] data - The data to write to the field.
 *
 * @param[in] size - The size of the field in bytes.
 *
 * @return void.
 */
void WriteContextField(CCSramAddr_t addr, const uint32_t *data, uint32_t size);

/****************************************************************************************/
/**
 *
 * @brief The function reads array field in the context (more than one word).
 *
 *
 * @param[in] addr - The address of the field ( pointer to the field in the context).
 *
 * @param[in] data - buffer to read the data into.
 *
 * @param[in] size - The size of the field in bytes.
 *
 * @return void.
 */
void ReadContextField(const CCSramAddr_t addr, const uint32_t *data, uint32_t size);
#endif
