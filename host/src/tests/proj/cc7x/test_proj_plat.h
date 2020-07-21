/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _TEST_PROJ_PLAT_H_
#define _TEST_PROJ_PLAT_H_

#include <stdint.h>

/*!
  @file
  @brief This file contains definitions and APIs that set the testing
  environment.
 */

  /*!
  @addtogroup cc_env_tests
  @{
 */
/******************************************************************
 * Defines
 ******************************************************************/

/*! Defines the cache parameters group set for the environment register. */
typedef enum TestProjCache_t {
     /*! AxUSER - HW - 1. */
     TEST_PROJ_HW_CACHE,
     /*! AxUSER - HW - 0. */
     TEST_PROJ_SW_CACHE
} TestProjCache_t;


/*! Defines Environment register read.
\note You must implement the read environment register that is compatible
      with your system.
 */
#define TEST_READ_ENV_REG(offset) \
        *(volatile uint32_t *)(processMap.processTeeHwEnvBaseAddr + (offset))

/*! Defines delay function. */
#define DELAY(number_of_loops)  { \
        volatile uint32_t ii1; \
        for(ii1=0; ii1<number_of_loops; ii1++); \
}

/*! Defines Environment register write.
\note You must implement the write environment register that is compatible
      with your system.
*/
#define TEST_WRITE_ENV_REG(offset, val)  { \
        (*(volatile uint32_t *)(processMap.processTeeHwEnvBaseAddr + (offset))) = (uint32_t)(val); \
        DELAY(500); \
}



/****************************************************************************
 * Functions
****************************************************************************/
/*!
@brief This function maps the CryptoCell base register and environment base
       register.
\note You must replace the environment mapping with implementation that is
          compatible with your system.

@return \c TEST_OK on success.
@return A non-zero value from test_proj_common.h on failure.
*/
uint32_t Test_ProjMap(void);


/*!
@brief This function unmaps the CryptoCell base register and environment base
register.
\note You must replace the environment un-mapping with implementation that
      is compatible with your system.

@return Void.
 */
void Test_ProjUnmap(void);


/*!
@brief This function performs power-on reset to CryptoCell, AO and environment
modules using environment register.
\note You must define power-on-reset implementation that is compatible with your
      system.

@return Void.
 */
void Test_ProjPerformPowerOnReset(void);

/*!
@brief This function performs Cold reset to CryptoCell and AO modules using
       environment register.
\note  You must define cold-reset implementation that is compatible with
       your system.

@return Void.
 */
void Test_ProjPerformColdReset(void);

/*!
@brief This function performs Warm reset to CryptoCell module using environment
       register.
\note  You must define warm-reset implementation that is compatible with
       your system.

@return Void.
 */
void Test_ProjPerformWarmReset(void);


/*!
@brief This function sets the stack pointer enable bit to CryptoCell module.

@return Void.
 */
void Test_ProjSetSpEnable(void);


/*!
@brief This function sets the cache parameters.
The set operation is done using environment registers.
\note  You must replace TEST_READ_OTP_BY_ENV() macro with the implementation
       that is compatible with your system.

@return Void.
 */
void Test_ProjSetCacheParams(TestProjCache_t cacheType);


/*!
@brief This function sets the device security mode.
The set operation is done using environment registers.
\note  You must replace TEST_READ_OTP_BY_ENV() macro with the implementation
       that is compatible with your system.

@return Void.
 */
void Test_ProjSetSecureMode(void);

/*!
@brief This function sets the FPGA to slim or full mode according to
       CC_SUPPORT_FULL_PROJECT flag.
The set operation is done using environment registers.
This function is needed for testing with FPGA.

@return Void.
 */
void Test_ProjSetFlavor(void);

/*!
@brief This function resets the FPGA to its original flavor (full).
The set operation is done using environment registers.
This function is needed for testing with FPGA.

@return Void.
 */
void Test_ProjSetFullFlavor(void);

#endif /*_TEST_PROJ_PLAT_H_ */

 /*!
  @}
  */
