/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _TEST_PROJ_DEFS_H_
#define _TEST_PROJ_DEFS_H_

#include <stdint.h>

#include "test_proj.h"

#include "cc_registers.h"
#include "dx_reg_base_host.h"
#include "dx_env.h"
#include "cc_regs.h"

#define BITS_IN_32BIT_WORD 32

#define TEST_PROJ_LCS_CM 0
#define TEST_PROJ_LCS_DM 1
#define TEST_PROJ_LCS_SECURE 5
#define TEST_PROJ_LCS_RMA 7
#define INVALID_LCS     (-1)

#define TEST_PROJ_LCS_NUM 4


/* poll NVM register to be assure that the NVM boot is finished (and LCS and the keys are valid) */
#define WAIT_NVM_IDLE() \
    do {                                            \
        uint32_t regVal;                                \
        do {                                        \
            regVal = TEST_READ_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, NVM_IS_IDLE));            \
            regVal = CC_REG_FLD_GET(0, NVM_IS_IDLE, VALUE, regVal);         \
        }while( !regVal );                              \
    }while(0)

/* poll LCS register to be assure that the HW is ready */
#define WAIT_LCS_VALID() \
	do { 											\
		uint32_t regVal; 								\
		do { 										\
            regVal = TEST_READ_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, LCS_IS_VALID)); \
            regVal = CC_REG_FLD_GET(0, LCS_IS_VALID, VALUE, regVal);        \
		}while( !regVal ); 								\
	}while(0)

/****************************************************************************/
/*   							External API  								*/
/****************************************************************************/
/*
 * @brief This function reads LCS register and verifies that LCS value is as expected.
 *
 * @param[in] LCS correct value.
 *
 * @param[out]
 *
 * @return rc - 0 for success, 1 for failure.
 */
uint32_t Test_ProjCheckLcs(uint32_t nextLcs);


/****************************************************************************/
/*
 * @brief This function reads LCS register, verifies that LCS value is as
 *          expected and no HW errors exist in HUK, Kcp* and Kce*.
 *
 * @param[in] LCS correct value.
 *
 * @param[out]
 *
 * @return rc - 0 for success, 1 for failure.
 */
unsigned int Test_ProjCheckLcsAndError(unsigned int  nextLcs);


/****************************************************************************/
/*
 * @brief This function returns the current LCS value.
 *
 * @param[in]
 *
 * @param[out] LCS value.
 *
 * @return 0.
 */
uint32_t Test_ProjGetLcs(uint32_t *lcs);


/*
 * @brief This function needs to be called after reset to set the endianess and
 * the cache parameters.
 *
 * @param[in]   cacheType      TEST_PROJ_HW_CACHE or TEST_PROJ_SW_CACHE
 *
 * @param[out]
 *
 * @return
 */
void Test_ProjSetCCParamsAfterReset(TestProjCache_t cacheType);

/****************************************************************************/
/*
 * @brief This function perform setting to Fatal Error bit in AO.
 *
 * @param[in]
 *
 * @param[out]
 *
 * @return
 */
void Test_ProjSetFatalError(void);


#endif /* _TEST_PROJ_DEFS_H_ */
