/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


#ifndef _TEST_PROJ_OTP_H__
#define _TEST_PROJ_OTP_H__

#include <stdint.h>
#include "cc_pal_types.h"
#include "cc_otp_defs.h"
#include "test_proj.h"
#include "test_proj_otp_plat.h"

/* OTP memory mapping */
#define TEST_OTP_SIZE_IN_WORDS      CC_OTP_USER_DEFINED_OFFSET
#define TEST_OTP_SIZE_IN_BYTES      (TEST_OTP_SIZE_IN_WORDS*CC_32BIT_WORD_SIZE)
#define MAX_OTP_SIZE_IN_WORDS       0x7FF
#define TEST_OTP_LAST_WORD_IN_MASK  TEST_OTP_SIZE_IN_WORDS
#define TEST_OTP_ZERO_COUNT_128BIT_KEY_NOT_IN_USE   0x0

/* indication of FULL HBK or not */
#define FULL_HBK        1
#define NOT_FULL_HBK    0

/* indication of SECURE DISABLE or not */
#define SD_ENABLE       1
#define NOT_SD_ENABLE   0

/* indication of KEY USED or not */
#define KEY_NOT_IN_USE  1
#define KEY_IN_USE      0

#define TEST_PROJ_NOT_PROVIDED      0xffffffff

typedef enum {
    PROJ_OTP_HUK_FIELD,
    PROJ_OTP_KPICV_FIELD,
    PROJ_OTP_KCEICV_FIELD,
    PROJ_OTP_KCP_FIELD,
    PROJ_OTP_KCE_FIELD,
    PROJ_OTP_EKCST_FIELD,
    PROJ_OTP_HBK_FIELD,
    PROJ_OTP_HBK0_FIELD,
    PROJ_OTP_HBK1_FIELD,
    PROJ_OTP_DCU_FIELD,
    PROJ_OTP_SW_VERSION_TRUSTED_FIELD,
    PROJ_OTP_SW_VERSION_NOT_TRUSTED_FIELD,
    PROJ_OTP_MAX_FIELD,
} ProjOtp_FieldsType_t;

#define TEST_CALC_BUFF_ZEROS(wordBuf, buffWordSize, zeros) {\
        uint32_t i = 0;\
        uint32_t j = 0;\
        uint32_t mask = 0;\
        zeros = 0;\
        for (i = 0; i< buffWordSize; i++) {\
            for (j = 0; j< BITS_IN_32BIT_WORD; j++) {\
                mask = 0x1;\
                if (!(*(wordBuf+i) & (mask << j))) {\
                    zeros++;\
                }\
            }\
        }\
}

#define GET_OTP_FIELD_INFO(fielsName, fieldWordSize, fieldOffset)   do {    \
        fieldWordSize = CC_OTP_ ## fieldWordSize ##_SIZE_IN_WORDS; \
        fieldOffset = CC_OTP_## fieldWordSize ##_OFFSET; \
} while (0)

#define SET_OTP_FIELD(otpBuff, wordName, fieldName, val)   do {    \
        BITFIELD_SET(otpBuff[CC_OTP_ ## wordName ## _OFFSET], \
                     CC_OTP_## wordName ##_## fieldName ##_BIT_SHIFT,\
                     CC_OTP_## wordName ##_## fieldName ##_BIT_SIZE, \
                     val); \
} while (0)

#define SET_OTP_BITFIELD(otpBuff, wordName, fieldName, bitsName, val)   do {    \
        BITFIELD_SET(otpBuff[CC_OTP_ ## wordName ## _OFFSET], \
                     CC_OTP_## wordName ##_## fieldName ##_## bitsName ##_BIT_SHIFT,\
                     CC_OTP_## wordName ##_## fieldName ##_## bitsName ##_BIT_SIZE, \
                     val); \
} while (0)

#define GET_OTP_BITFIELD(otpBuff, wordName, fieldName, bitsName, val)   do {    \
        val = BITFIELD_GET(otpBuff[CC_OTP_ ## wordName ## _OFFSET], \
                     CC_OTP_## wordName ##_## fieldName ##_## bitsName ##_BIT_SHIFT,\
                     CC_OTP_## wordName ##_## fieldName ##_## bitsName ##_BIT_SIZE); \
} while (0)


#define SET_OTP_SECURE_DISBALE(otpBuff, isSd) \
    SET_OTP_FIELD(otpBuff, SECOND_MANUFACTURE_FLAG, SECURE_DISABLE, isSd)

#define TEST_WRITE_OTP_BY_REG(offset, val)  \
        TEST_WRITE_TEE_CC_REG(CC_OTP_BASE_ADDR +(offset*CC_32BIT_WORD_SIZE), val)

#define TEST_READ_OTP_BY_REG(offset)   \
        TEST_READ_TEE_CC_REG(CC_OTP_BASE_ADDR+ (offset*CC_32BIT_WORD_SIZE))


#define SET_OTP_DCU_LOCK(otpBuff, val)   do {    \
        uint32_t ii = 0; \
        for (ii = 0; ii < CC_OTP_DCU_SIZE_IN_WORDS; ii++) { \
            otpBuff[CC_OTP_DCU_OFFSET+ii] = val; \
        } \
}while(0)

/* calc OTP memory length:
   read RTL OTP address width. The supported sizes are 6 (for 2 Kbits),7,8,9,10,11 (for 64 Kbits).
   convert value parameter to addresses of 32b words */
#define GET_OTP_LENGTH(otpLength)                           \
        do {                                                \
            otpLength = TEST_READ_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, OTP_ADDR_WIDTH_DEF));  \
            otpLength = CC_REG_FLD_GET(0, OTP_ADDR_WIDTH_DEF, VALUE, otpLength);            \
            otpLength = (1 << otpLength);                               \
        }while(0)

typedef struct TestOtpMask_t {
    uint32_t isPCI;
    uint32_t* mask;
} TestOtpMask_t;

typedef struct{
   uint32_t OffsetInWords;
   uint32_t sizeInWords;
}ProjOtpInfo_t;

extern uint32_t gHukBuff[CC_OTP_HUK_SIZE_IN_WORDS];
extern uint32_t gHbk0Buff[CC_OTP_HBK0_SIZE_IN_WORDS];
extern uint32_t gHbk1Buff[CC_OTP_HBK1_SIZE_IN_WORDS];
extern uint32_t gHbk256Buff[CC_OTP_HBK_SIZE_IN_WORDS];
extern uint32_t gClassKeyBuff[CC_OTP_KPICV_SIZE_IN_WORDS];
extern uint32_t gClear128Buff[TEST_PROJ_128BIT_KEY_SIZE_WORDS];
extern uint32_t gClear256Buff[TEST_PROJ_256BIT_KEY_SIZE_WORDS];
extern TestOtpMask_t gOtpStatus;


/******************************/
/*   function declaration     */
/*****************************/

/*!
@brief This function dumps the currently burned OTP.

@return \c None.
 */
void Test_ProjDumpOtp(uint32_t startOffset, /*!< [in] OTP start offset. */
                      uint32_t wordLength  /*!< [in] number of words to dump. */
);

/*!
@brief This function sets the test OTP mask to use

@return \c None.
 */
void Test_ProjSetOtpBufState(uint8_t isPCIMode /*!< [in] Flag indicating PCI mode. */
);

/*!
@brief This function sets chip indication in the OTP buffer and also
        calls Test_ProjSetOtpBufState()

@return \c None.
 */
void Test_ProjSetChipIndication(uint32_t   *otpValues,  /*!< [in] OTP buffer to be updated. */
                                ProjOtp_ChipState_t   chipIndication /*!< [in] Chip indication type. */
);

/*!
@brief This function sets RMA bits in the OTP buffer

@return \c None.
 */
void Test_ProjSetRma(uint32_t   *otpValues,  /*!< [in] OTP buffer to be updated. */
                     ProjOtp_Rma_t rmaMode  /*!< [in] rma mode to be set. */
);


/*!
@brief This function burns the OTP word with the previously defined mask done by  est_ProjSetOtpBufState()

@return \c None.
 */
void Test_ProjWriteOtpWord (uint32_t offsetInWords,  /*!< [in] OTP word offset to be burned. */
                            uint32_t value   /*!< [in] New OTP word value to be burned. */
);

/*!
@brief This function burns buffer to OTP with the previously defined mask done by  est_ProjSetOtpBufState()

@return \c None.
 */
void Test_ProjWriteOtpBuff (uint32_t offsetInWords,  /*!< [in] OTP word offset to be burned. */
                             uint32_t sizeWords,   /* size in words of buff*/
                             uint32_t *buff     /* the buffer to burn to OTP */
);

/*!
@brief This function calculates and sets the number of zero bits of the provided fieldType in the provided OTP buffer

@return \c TEST_OK on success.
@return A non-zero value from test_proj_common.h on failure.
 */
unsigned int Test_ProjSetZeroBitsOtpBuff(uint32_t *otpBuff,  /*!< [in/out] OTP buffer with the buffer. */
                                         ProjOtp_FieldsType_t fieldType, /*!< [in] OTP field to calculate its zeros. */
                                         uint32_t isNotInUse, /*!< [in] Flag indicating whether the  field is used or not. */
                                         bool isWrongNumOfZeros /*!< [in] should the number of zeros be wrong in OTP */
);

/*!
@brief This function sets the not in use flag of the provided fieldType in the provided OTP buffer

@return \c TEST_OK on success.
@return A non-zero value from test_proj_common.h on failure.
 */
unsigned int Test_ProjSetNotInUseOtpBuff(uint32_t *otpBuff,  /*!< [in/out] OTP buffer with the buffer. */
                                         ProjOtp_FieldsType_t fieldType, /*!< [in] OTP field to set not in use flag. */
                                         uint32_t isNotInUse  /*!< [in] Flag indicating whether the  field is used or not. */
);

/*!
@brief This function sets field in OTP buffer with its zero count and not is use bits

@return \c TEST_OK on success.
@return A non-zero value from test_proj_common.h on failure.
 */
unsigned int Test_ProjSetOtpField(unsigned int *otpBuff,  /*!< [in/out] OTP buffer with the buffer. */
                                  unsigned int *fieldBuff, /*!< [in] Field buffer to be set in OTP. */
                                 ProjOtp_FieldsType_t fieldType, /*!< [in] OTP field to set not-in-use flag. */
                                 uint32_t isNotInUse  /*!< [in] not-in-use flag indication. */
);

/*!
@brief This function sets the HBK fields, zero count and not-in-use of the provided hbkType in the provided OTP buffer

@return \c TEST_OK on success.
@return A non-zero value from test_proj_common.h on failure.
 */
unsigned int Test_ProjSetHbkInOtpBuff(unsigned int *otp, /*!< [in/out] OTP buffer with the buffer. */
                                      unsigned char *hbkBuff, /*!< [in] The HBK buffer to set in OTP. */
                                      uint32_t  hbkBuffWordSize, /*!< [in] The HBK buffer size in words. */
                                      ProjOtp_FieldsType_t hbkType, /*!< [in] The HBK type. */
                                      uint32_t nextLcs); /*!< [in] The LCS expected of the OTP (after burning). */
/*!
@brief This function Build default OTP according to lcs and burns it.


@return \c TEST_OK on success.
@return A non-zero value from test_proj_common.h on failure.
 */
unsigned int Test_ProjBuildAndBurnOtp(unsigned int  *otpBuff, /*!< [in] OTP buffer to be built. */
                                      unsigned int  nextLcs,  /*!< [in] The OTP buffer base CM/DM/SE/RMA. */
                                      ProjOtp_ChipState_t chipIndication, /*!< [in] The OTP chip indication. */
                                      uint32_t  isSd,  /*!< [in] The OTP secure disable flag. */
                                      uint32_t isHbkFull  /*!< [in] The OTP  hbk full flag. */
                                      );

/*!
@brief This function writes a key using shadow registers.


@return \c TEST_OK on success.
@return A non-zero value from test_proj_common.h on failure.
 */
unsigned int Test_ProjSetShadowKey(uint32_t *pKey, /*!< [in] The key to burn */
                                   size_t keyLenWords, /*!< [in] key length in words */
                                   ProjOtp_FieldsType_t fieldType /*!< [in] The OTP field type to burn */);
#endif //_TEST_PROJ_OTP_H__


