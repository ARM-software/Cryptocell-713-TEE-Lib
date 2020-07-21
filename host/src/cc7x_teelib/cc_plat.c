/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include "cc_pal_types.h"
#include "cc_pal_log.h"
#include "cc_hal.h"
#include "cc_plat.h"
#include "cc_regs.h"

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
uint32_t ReadContextWord(const CCSramAddr_t addr)
{
	uint32_t val;
	_ReadValueFromSram(addr, val);
	return val;
}

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
void WriteContextWord(CCSramAddr_t addr, uint32_t data)
{
	_WriteWordsToSram(addr, &data, 4);
}

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
void ClearCtxField(CCSramAddr_t addr, uint32_t size)
{
	_ClearSram(addr, size);
}

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
void ReadContextField(const CCSramAddr_t addr, const uint32_t *buff, uint32_t size)
{
	_ReadWordsFromSram(addr, buff, size);
}

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
void WriteContextField(CCSramAddr_t addr, const uint32_t *data, uint32_t size)
{
	_WriteWordsToSram(addr, data, size);
}
