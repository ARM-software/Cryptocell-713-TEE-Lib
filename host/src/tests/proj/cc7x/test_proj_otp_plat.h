/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _TEST_PROJ_OTP_PLAT_H__
#define _TEST_PROJ_OTP_PLAT_H__

#include <stdint.h>
#include "cc_pal_types.h"
#include "cc_otp_defs.h"

/*!
  @file
  @brief This file contains definitions and APIs for the tests OTP interface.
         The APIs here must have a specific implementation for the integrated
         platform.
 */


 /*!
 @addtogroup otp_apis
 @{
 */
/******************************************************************
 * Defines
 ******************************************************************/
/*! Enumeration definition chip state indication. */
typedef enum {
    /*! Chip state not initialized. */
    PROJ_OTP_CHIP_STATE_NOT_INITIALIZED = 0,
    /*! Chip state for test chip. */
    PROJ_OTP_CHIP_STATE_TEST = 1,
    /*! Chip state for production chip. */
    PROJ_OTP_CHIP_STATE_PRODUCTION = 2,
    /*! Chip state error indication. */
    PROJ_OTP_CHIP_STATE_ERROR = 3,
    /*! Reserved value. */
    PROJ_OTP_CHIP_STATE_RESERVED = CC_MAX_UINT32_VAL,
} ProjOtp_ChipState_t;


/*! Enumeration definition chip state indication. */
typedef enum {
    /*! No RMA mode. */
    PROJ_OTP_RMA_NO = 0,
    /*! Only ICV RMA bit is set. */
    PROJ_OTP_RMA_ICV = 1,
    /*! Only OEM RMA bit is set. */
    PROJ_OTP_RMA_OEM = 2,
    /*! Both OEM and ICV RMA bits are set. */
    PROJ_OTP_RMA_FULL = 3,
    /*! Reserved value. */
    PROJ_OTP_RMA_RESERVED = CC_MAX_UINT32_VAL,
} ProjOtp_Rma_t;


/*! Defines the memory offset used for OTP region.
 *  \note You must implement OTP access that is compatible with your system.
 */
#define ENV_OTP_START_OFFSET        0x2000UL

/*! Defines OTP word write.
 *   \note You must implement OTP write that is compatible with your system.
 */
#define TEST_WRITE_OTP_BY_ENV(wordOffset, val) \
        TEST_WRITE_ENV_REG(ENV_OTP_START_OFFSET + ((wordOffset)*CC_32BIT_WORD_SIZE), val)

/*! Defines OTP word read.
 *   \note You must implement OTP write that is compatible with your system.
 */
#define TEST_READ_OTP_BY_ENV(wordOffset) \
        TEST_READ_ENV_REG(ENV_OTP_START_OFFSET + ((wordOffset)*CC_32BIT_WORD_SIZE))


/******************************************************************
 * Externs
 ******************************************************************/

/*! The random OTP mask (a representation of the mask that is located in the RTL
    used for OTP masking).
 * CryptoCell FPGA implementation includes two different values,
 * you can put the same value in both definitions.
 * This is the first of two arrays that hold values.

 *   \note You must implement the OTP masking that is compatible with your
           system.
 */
extern uint32_t gTestOtpMaskV1[];

/*! The random OTP mask (a representation of the mask that is located in the RTL
    used for OTP masking).
 * CryptoCell FPGA implementation includes two different values,
 * you can put the same value in both definitions.
 * This is the second of two arrays that hold values.

 *   \note You must implement the OTP masking that is compatible with your
           system.
 */
extern uint32_t gTestOtpMaskV2[];


/******************************/
/*   Function declaration     */
/*****************************/

/*!
@brief This function reads a word from the OTP using environment (test
       dedicated) registers.
*  \note You must replace TEST_READ_OTP_BY_ENV() macro with implementation that
         is compatible with your system.

@return The OTP read word
 */
unsigned int Test_ProjReadOtpWord (
                            /*! [in] OTP word offset to be read. */
                            uint32_t offsetInWords
);


/*!
@brief This function burns the OTP buffer with the defined mask.
       You must set chipIndication before calling this function explicitly by
       calling Test_ProjSetChipIndication() or by calling
       Test_ProjBuildDefaultOtp().

   \note Words with 0 value are not being burned.
   \note You must replace TEST_WRITE_OTP_BY_ENV() and TEST_WRITE_ENV_REG()
         macros with implementation that is compatible with your system.

@return \c TEST_OK on success.
@return A non-zero value from test_proj_common.h on failure.
 */
unsigned int Test_ProjBurnOtp(
                                   /*! [in] OTP buffer to be burned. */
                                   unsigned int  *otpBuff,
                                   /*! [in] The LCS expected after burning the
                                   OTP. */
                                   unsigned int  nextLcs
);

/*!
@brief This function sets the OTP buffer with mandatory fields (LCS changing
fields): HUK and HBK.
   \note Setting class keys is outside the scope of this function. You must set
         class keys by calling Test_ProjSetOtpField().
   \note baseLcs valid values are CM/DM/SE only. If RMA is needed, set rmaMode
         to \c PROJ_OTP_RMA_FULL.
   \note baseLcs should be based on required fields in OTP to be filled.
   \note You must replace TEST_WRITE_OTP_BY_ENV() and TEST_WRITE_ENV_REG()
         macros with implementation that is compatible with your system.

@return \c TEST_OK on success.
@return A non-zero value from test_proj_common.h on failure.
 */
unsigned int Test_ProjBuildDefaultOtp(
                                      /*! [in] OTP buffer to be built. */
                                      unsigned int  *otpBuff,
                                      /*! [in] The size in words of otpBuffer.
                                      */
                                      uint32_t  otpBuffWordSize,  /*is this the prevous param otpBuff?*/
                                      /*! [in] The OTP buffer base CM/DM/SE. */
                                      unsigned int  baseLcs,
                                      /*! [in] The OTP chip indication. */
                                      ProjOtp_ChipState_t chipIndication,
                                      /*! [in] The OTP RMA mode. */
                                      ProjOtp_Rma_t rmaMode,
                                      /*! [in] The OTP Secure Disable flag. */
                                      uint32_t  isSd,
                                      /*! [in] The OTP HBK full flag. */
                                      uint32_t isHbkFull
);

/*!
 @}
 */

#endif //_TEST_PROJ_OTP_PLAT_H__
