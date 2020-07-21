/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include "cc_pal_types.h"
#include "test_proj.h"
#include "test_proj_defs.h"
#include "test_pal_time.h"
#include "tests_log.h"

const uint32_t g_lcsList[TEST_PROJ_LCS_NUM] = {TEST_PROJ_LCS_CM,
        TEST_PROJ_LCS_DM,
        TEST_PROJ_LCS_SECURE,
        TEST_PROJ_LCS_RMA};

const char *g_lcsList2str[TEST_PROJ_LCS_NUM] = {
        /*TEST_PROJ_LCS_CM     */   "TEST_PROJ_LCS_CM",
        /*TEST_PROJ_LCS_DM     */   "TEST_PROJ_LCS_DM",
        /*TEST_PROJ_LCS_SECURE */   "TEST_PROJ_LCS_SECURE",
        /*TEST_PROJ_LCS_RMA    */   "TEST_PROJ_LCS_RMA"};


unsigned int Test_ProjCheckLcs(unsigned int  nextLcs)
{
    unsigned int regVal = 0;

    /* poll NVM register to be assure that the NVM boot is finished (and LCS and the keys are valid) */
    WAIT_LCS_VALID();

    /* Read the LCS register */
    regVal = TEST_READ_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, LCS_REG));
    regVal = CC_REG_FLD_GET(0, LCS_REG, LCS_REG, regVal);

    /* Verify lcs */
    if(regVal != nextLcs) {
        TEST_LOG_ERROR("actual LCS %d != expected LCS %d\n", regVal, nextLcs);
        return TEST_COMPARE_ERR;
    }

    return TEST_OK;
}



unsigned int Test_ProjGetLcs(unsigned int  *lcs)
{
    unsigned int regVal = 0;

    /* poll NVM register to be assure that the NVM boot is finished (and LCS and the keys are valid) */
    WAIT_LCS_VALID();

    /* Read the LCS register */
    regVal = TEST_READ_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, LCS_REG));
    regVal = CC_REG_FLD_GET(0, LCS_REG, LCS_REG, regVal);

    *lcs = regVal;

    return TEST_OK;
}

/* PoR - reset towards CryptoCell, the AO module and the ENV REGs (without the ROSC) */
void Test_ProjPerformPowerOnReset(void)
{
    uint32_t aceRegVal = 0;
    uint32_t cacheRegVal = 0;

    aceRegVal = TEST_READ_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, AXIM_ACE_CONST));
    cacheRegVal = TEST_READ_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, AXIM_CACHE_PARAMS));

    TEST_WRITE_ENV_REG(CC_REG_OFFSET(HOST_RGF, ENV_FPGA_CC_POR_N_ADDR) , 0x1UL);
    Test_PalDelay(1000);

    /* poll NVM register to assure that the NVM boot is finished (and LCS and the keys are valid) */
    WAIT_NVM_IDLE();

#ifdef BIG__ENDIAN
    /* Set DMA endianess to big */
    TEST_WRITE_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, HOST_RGF_ENDIAN) , 0xCCUL);
#else /* LITTLE__ENDIAN */
    TEST_WRITE_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, HOST_RGF_ENDIAN) , 0x00UL);
#endif

    /* Set Original Cache Parameter */
    TEST_WRITE_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, AXIM_ACE_CONST) ,aceRegVal);
    TEST_WRITE_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, AXIM_CACHE_PARAMS), cacheRegVal);
    Test_ProjSetSecureMode();

    return;

}

/* Set cache and endianess parameters after reset */
void Test_ProjSetCCParamsAfterReset(TestProjCache_t cacheType)
{

#ifdef BIG__ENDIAN
    /* Set DMA endianess to big */
    TEST_WRITE_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, HOST_RGF_ENDIAN) , 0xCCUL);
#else /* LITTLE__ENDIAN */
    TEST_WRITE_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, HOST_RGF_ENDIAN) , 0x00UL);
#endif

    Test_ProjSetCacheParams(cacheType);
    Test_ProjSetSecureMode();

    return;

}

/* Reset both CC and AO regs */
void Test_ProjPerformColdReset(void)
{
    uint32_t aceRegVal = 0;
    uint32_t cacheRegVal = 0;

    aceRegVal = TEST_READ_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, AXIM_ACE_CONST));
    cacheRegVal = TEST_READ_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, AXIM_CACHE_PARAMS));

    TEST_WRITE_ENV_REG(CC_REG_OFFSET(HOST_RGF, ENV_FPGA_CC_COLD_RST), 0x1UL);
    Test_PalDelay(1000);

    /* poll NVM register to assure that the NVM boot is finished (and LCS and the keys are valid) */
    WAIT_NVM_IDLE();

#ifdef BIG__ENDIAN
    /* Set DMA endianess to big */
    TEST_WRITE_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, HOST_RGF_ENDIAN) , 0xCCUL);
#else /* LITTLE__ENDIAN */
    TEST_WRITE_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, HOST_RGF_ENDIAN), 0x00UL);
#endif

    /* Set Original Cache Parameter */
    TEST_WRITE_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, AXIM_ACE_CONST) ,aceRegVal);
    TEST_WRITE_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, AXIM_CACHE_PARAMS), cacheRegVal);

    return;
}

/* Reset only CC regs */
void Test_ProjPerformWarmReset(void)
{
    uint32_t aceRegVal = 0;
    uint32_t cacheRegVal = 0;

    aceRegVal = TEST_READ_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, AXIM_ACE_CONST));
    cacheRegVal = TEST_READ_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, AXIM_CACHE_PARAMS));

    TEST_WRITE_ENV_REG(CC_REG_OFFSET(HOST_RGF, ENV_FPGA_CC_RST_N) , 0x1UL);
    Test_PalDelay(1000);

    /* poll NVM register to assure that the NVM boot is finished (and LCS and the keys are valid) */
    WAIT_NVM_IDLE();

#ifdef BIG__ENDIAN
    /* Set DMA endianess to big */
    TEST_WRITE_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, HOST_RGF_ENDIAN) , 0xCCUL);
#else /* LITTLE__ENDIAN */
    TEST_WRITE_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, HOST_RGF_ENDIAN) , 0x00UL);
#endif

    /* Set Original Cache Parameter */
    TEST_WRITE_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, AXIM_ACE_CONST) ,aceRegVal);
    TEST_WRITE_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, AXIM_CACHE_PARAMS), cacheRegVal);

    return;

}

/* Set SP Enable bit */
void Test_ProjSetSpEnable(void)
{
    uint32_t regVal = 0;
    uint32_t aceRegVal = 0;
    uint32_t cacheRegVal = 0;

    aceRegVal = TEST_READ_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, AXIM_ACE_CONST));
    cacheRegVal = TEST_READ_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, AXIM_CACHE_PARAMS));

    /* Read HOST_AO_LOCK_BITS */
    regVal = TEST_READ_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, HOST_AO_LOCK_BITS));
    /* set sp_enable bit f */
    CC_REG_FLD_SET(0, HOST_AO_LOCK_BITS, HOST_SP_EN, regVal, CC_TRUE);
    /* Write HOST_AO_LOCK_BITS */
    TEST_WRITE_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, HOST_AO_LOCK_BITS), regVal);

    Test_PalDelay(1000);

#ifdef BIG__ENDIAN
    /* Set DMA endianess to big */
    TEST_WRITE_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, HOST_RGF_ENDIAN) , 0xCCUL);
#else /* LITTLE__ENDIAN */
    TEST_WRITE_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, HOST_RGF_ENDIAN) , 0x00UL);
#endif

    /* Set Original Cache Parameter */
    TEST_WRITE_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, AXIM_ACE_CONST) ,aceRegVal);
    TEST_WRITE_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, AXIM_CACHE_PARAMS), cacheRegVal);

    return;

}

/* Set Cache Parameter */
void Test_ProjSetCacheParams(TestProjCache_t cacheType)
{
    uint32_t aceRegVal = 0;
    uint32_t cacheRegVal = 0;

    if (cacheType == TEST_PROJ_HW_CACHE) {
        /* AxDOMAIN - HW - system(0x3) */
        BITFIELD_SET(aceRegVal, CC_AXIM_ACE_CONST_ARDOMAIN_BIT_SHIFT, CC_AXIM_ACE_CONST_ARDOMAIN_BIT_SIZE, 0x3);
        BITFIELD_SET(aceRegVal, CC_AXIM_ACE_CONST_AWDOMAIN_BIT_SHIFT, CC_AXIM_ACE_CONST_AWDOMAIN_BIT_SIZE, 0x3);
        TEST_WRITE_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, AXIM_ACE_CONST) ,aceRegVal);

        /* AxCACHE - HW - write back read and write alloc(0xf) */
        BITFIELD_SET(cacheRegVal, CC_AXIM_CACHE_PARAMS_AWCACHE_LAST_BIT_SHIFT, CC_AXIM_CACHE_PARAMS_AWCACHE_LAST_BIT_SIZE, 0xf);
        BITFIELD_SET(cacheRegVal, CC_AXIM_CACHE_PARAMS_AWCACHE_BIT_SHIFT, CC_AXIM_CACHE_PARAMS_AWCACHE_BIT_SIZE, 0xf);
        BITFIELD_SET(cacheRegVal, CC_AXIM_CACHE_PARAMS_ARCACHE_BIT_SHIFT, CC_AXIM_CACHE_PARAMS_ARCACHE_BIT_SIZE, 0xf);
        TEST_WRITE_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, AXIM_CACHE_PARAMS), cacheRegVal);
    } else {
        /* AxDOMAIN - SW - Non-sharable(0x0) */
        BITFIELD_SET(aceRegVal, CC_AXIM_ACE_CONST_ARDOMAIN_BIT_SHIFT, CC_AXIM_ACE_CONST_ARDOMAIN_BIT_SIZE, 0x0);
        BITFIELD_SET(aceRegVal, CC_AXIM_ACE_CONST_AWDOMAIN_BIT_SHIFT, CC_AXIM_ACE_CONST_AWDOMAIN_BIT_SIZE, 0x0);
        TEST_WRITE_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, AXIM_ACE_CONST) ,aceRegVal);

        /* AxCACHE - SW - device non buffarable(0x0) */
        BITFIELD_SET(cacheRegVal, CC_AXIM_CACHE_PARAMS_AWCACHE_LAST_BIT_SHIFT, CC_AXIM_CACHE_PARAMS_AWCACHE_LAST_BIT_SIZE, 0x0);
        BITFIELD_SET(cacheRegVal, CC_AXIM_CACHE_PARAMS_AWCACHE_BIT_SHIFT, CC_AXIM_CACHE_PARAMS_AWCACHE_BIT_SIZE, 0x0);
        BITFIELD_SET(cacheRegVal, CC_AXIM_CACHE_PARAMS_ARCACHE_BIT_SHIFT, CC_AXIM_CACHE_PARAMS_ARCACHE_BIT_SIZE, 0x0);
        TEST_WRITE_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, AXIM_CACHE_PARAMS), cacheRegVal);

    }

#ifdef CC_PLAT_ZYNQ7000
    if (cacheType == TEST_PROJ_HW_CACHE) {
        /* AxUSER - HW - 1 */
        uint32_t axiUserVal = 0;
        BITFIELD_SET(axiUserVal, CC_ENV_FPGA_AXIM_USER_PARAMS_ARUSER_BIT_SHIFT, CC_ENV_FPGA_AXIM_USER_PARAMS_ARUSER_BIT_SIZE, 0x1);
        BITFIELD_SET(axiUserVal, CC_ENV_FPGA_AXIM_USER_PARAMS_AWUSER_BIT_SHIFT, CC_ENV_FPGA_AXIM_USER_PARAMS_AWUSER_BIT_SIZE, 0x1);
        TEST_WRITE_ENV_REG(CC_REG_OFFSET(HOST_RGF, ENV_FPGA_AXIM_USER_PARAMS), axiUserVal);
    } else {
        /* AxUSER - SW - 0 */
        uint32_t axiUserVal = 0;
        BITFIELD_SET(axiUserVal, CC_ENV_FPGA_AXIM_USER_PARAMS_ARUSER_BIT_SHIFT, CC_ENV_FPGA_AXIM_USER_PARAMS_ARUSER_BIT_SIZE, 0x1);
        BITFIELD_SET(axiUserVal, CC_ENV_FPGA_AXIM_USER_PARAMS_AWUSER_BIT_SHIFT, CC_ENV_FPGA_AXIM_USER_PARAMS_AWUSER_BIT_SIZE, 0x1);
        TEST_WRITE_ENV_REG(CC_REG_OFFSET(HOST_RGF, ENV_FPGA_AXIM_USER_PARAMS), axiUserVal);
    }
#endif

}

/*!
 * \brief Test_ProjSetFatalError() -
 *        set fatal error bit0 to AO register
 *
 * \param - (input) - cacheType     - axi cache value
 *
 * \return None
 */
void Test_ProjSetFatalError(void)
{
    uint32_t	temp_reg_value;
    uint32_t aceRegVal = 0;
    uint32_t cacheRegVal = 0;

    aceRegVal = TEST_READ_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, AXIM_ACE_CONST));
    cacheRegVal = TEST_READ_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, AXIM_CACHE_PARAMS));

    /* read AO Lock bits Register */
    temp_reg_value = TEST_READ_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, HOST_AO_LOCK_BITS));

    /* set Fatal Error bit */
    temp_reg_value |=
            (0x1 << CC_HOST_AO_LOCK_BITS_HOST_FATAL_ERR_BIT_SHIFT);

    /* set AO LOCK BITS register - set fatal error cause to CC reset */
    TEST_WRITE_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, HOST_AO_LOCK_BITS), temp_reg_value);

    /* poll NVM register to assure that the NVM boot is finished */
    WAIT_NVM_IDLE();

    /* setting to fatal error cause to CC HW reset, so need to update
     * the AXI register to correct value, and other setting
     */
#ifdef BIG__ENDIAN
    /* Set DMA endianess to big */
    TEST_WRITE_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, HOST_RGF_ENDIAN), 0xCCUL);
#else
    /* LITTLE__ENDIAN */
    TEST_WRITE_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, HOST_RGF_ENDIAN), 0x00UL);
#endif
    /* Set Original Cache Parameter */
    TEST_WRITE_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, AXIM_ACE_CONST) ,aceRegVal);
    TEST_WRITE_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, AXIM_CACHE_PARAMS), cacheRegVal);
}


/*!
 * \brief Test_ProjSetSecureMode() -
 *        set secure mode in case the platform is JUNO
 *
 * \param None
 *
 * \return None
 */
void Test_ProjSetSecureMode(void)
{
#ifdef CC_PLAT_JUNO
    TEST_WRITE_ENV_REG(CC_REG_OFFSET(HOST_RGF, ENV_FPGA_SECURITY_MODE_OVERRIDE) , 0xfUL);
#endif
}


/*!
 * \brief Test_ProjSetFlavor() -
 *        set slim bit to 1 if cc_lib was compiled for slim flavor.
 *
 * \return None
 */
void Test_ProjSetFlavor(void)
{
    uint32_t flavorVal = 0;
#ifdef CC_SUPPORT_FULL_PROJECT
    BITFIELD_SET(flavorVal, CC_ENV_FPGA_CC_SLIM_BIT_SHIFT, CC_ENV_FPGA_CC_SLIM_BIT_SIZE, 0x0);
    TEST_WRITE_ENV_REG(CC_REG_OFFSET(HOST_RGF, ENV_FPGA_CC_STATIC_CONFIGURATION) , flavorVal);
#else
    BITFIELD_SET(flavorVal, CC_ENV_FPGA_CC_SLIM_BIT_SHIFT, CC_ENV_FPGA_CC_SLIM_BIT_SIZE, 0x1);
    TEST_WRITE_ENV_REG(CC_REG_OFFSET(HOST_RGF, ENV_FPGA_CC_STATIC_CONFIGURATION) , flavorVal);
#endif
}

/*!
 * \brief Test_ProjSetFullFlavor() -
 *        reset the FPGA to the original flavor it was in - full.
 *
 * \return None
 */
void Test_ProjSetFullFlavor(void)
{
    uint32_t flavorVal = 0;
    BITFIELD_SET(flavorVal, CC_ENV_FPGA_CC_SLIM_BIT_SHIFT, CC_ENV_FPGA_CC_SLIM_BIT_SIZE, 0x0);
    TEST_WRITE_ENV_REG(CC_REG_OFFSET(HOST_RGF, ENV_FPGA_CC_STATIC_CONFIGURATION) , flavorVal);
}
