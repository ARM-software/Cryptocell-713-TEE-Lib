/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include "cc_util_hw_key.h"
#include "cc_hal.h"
#include "cc_regs.h"
#include "cc_fips_defs.h"
#include "cc_pal_mem.h"
#include "cc_registers.h"
#include "cc_util_int_defs.h"

/* HW KFDE key is 256b */
#define CC_KFDE_SIZE_WORDS 8
#define CC_KFDE_SIZE_BYTES (CC_KFDE_SIZE_WORDS<<2)

CCUtilHwKeyRetCode_t CC_UtilHwKeySet(uint8_t *pKey,
				     size_t keySize,
				     CCUtilSlotNum_t slotNum)
{
	uint32_t kfde[CC_KFDE_SIZE_WORDS] = {0};
	int i;
	uint32_t reg_offset;
    uint32_t isSecureDisableSet = 0;
    uint32_t isFatalErrorSet = 0;

	CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

	if (pKey == NULL) {
		return CC_HW_KEY_RET_NULL_KEY_PTR;
	}

	if (keySize > CC_KFDE_SIZE_BYTES) {
		return CC_HW_KEY_RET_BAD_KEY_SIZE;
	}

    /* The function should refuse to operate if the secure disable bit is set */
    CC_UTIL_IS_SECURE_DISABLE_FLAG_SET(isSecureDisableSet);
    if (isSecureDisableSet == SECURE_DISABLE_FLAG_SET) {
        return CC_HW_KEY_RET_SD_ENABLED_ERROR;
    }

    /* The function should refuse to operate if the Fatal Error bit is set */
    CC_UTIL_IS_FATAL_ERROR_SET(isFatalErrorSet);
    if (isFatalErrorSet == FATAL_ERROR_FLAG_SET) {
        return CC_HW_KEY_RET_FATAL_ERR_IS_LOCKED_ERR;
    }

	switch (slotNum) {
	case CC_HW_KEY_SLOT_0:
		reg_offset = CC_REG_OFFSET(HOST_RGF, AO_FDE0);
		break;
	case CC_HW_KEY_SLOT_1:
		reg_offset = CC_REG_OFFSET(HOST_RGF, AO_FDE1);
		break;
	case CC_HW_KEY_SLOT_2:
		reg_offset = CC_REG_OFFSET(HOST_RGF, AO_FDE2);
		break;
	case CC_HW_KEY_SLOT_3:
		reg_offset = CC_REG_OFFSET(HOST_RGF, AO_FDE3);
		break;
	default:
		return CC_HW_KEY_RET_BAD_SLOT_NUM;
	}

	CC_PalMemCopy((uint8_t*)kfde, pKey, keySize);

	for (i = 0; i < CC_KFDE_SIZE_WORDS; ++i) {
		CC_HAL_WRITE_REGISTER(reg_offset, kfde[i]);
	}

	return CC_HW_KEY_RET_OK;
}

