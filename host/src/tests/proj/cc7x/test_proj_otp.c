/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include <stddef.h>
#include <string.h>
#include <stdbool.h>

#include "cc_otp_defs.h"
#include "cc_regs.h"
#include "cc_registers.h"

#include "test_proj_otp.h"
#include "test_proj_defs.h"
#include "test_proj_common.h"

#include "tests_log.h"
#include "test_pal_time.h"



#define AXI_CACHE_OFF           0x000UL
#define AXI_CACHE_DEFAULT       0x777UL
struct TestOtpMask_t gOtpStatus;

ProjOtpInfo_t  otpFieldInfo[PROJ_OTP_MAX_FIELD] = {
        /* PROJ_OTP_HUK_FIELD,                    */ {CC_OTP_HUK_OFFSET, CC_OTP_HUK_SIZE_IN_WORDS},
        /* PROJ_OTP_KPICV_FIELD,                  */ {CC_OTP_KPICV_OFFSET, CC_OTP_KPICV_SIZE_IN_WORDS},
        /* PROJ_OTP_KCEICV_FIELD,                 */ {CC_OTP_KCEICV_OFFSET, CC_OTP_KCEICV_SIZE_IN_WORDS},
        /* PROJ_OTP_KCP_FIELD,                    */ {CC_OTP_KCP_OFFSET, CC_OTP_KCP_SIZE_IN_WORDS},
        /* PROJ_OTP_KCE_FIELD,                    */ {CC_OTP_KCE_OFFSET, CC_OTP_KCE_SIZE_IN_WORDS},
        /* PROJ_OTP_EKCST_FIELD,                  */ {CC_OTP_EKCST_OFFSET, CC_OTP_EKCST_SIZE_IN_WORDS},
        /* PROJ_OTP_HBK_FIELD,                    */ {CC_OTP_HBK_OFFSET, CC_OTP_HBK_SIZE_IN_WORDS},
        /* PROJ_OTP_HBK0_FIELD,                   */ {CC_OTP_HBK0_OFFSET, CC_OTP_HBK0_SIZE_IN_WORDS},
        /* PROJ_OTP_HBK1_FIELD,                   */ {CC_OTP_HBK1_OFFSET, CC_OTP_HBK1_SIZE_IN_WORDS},
        /* PROJ_OTP_DCU_FIELD,                    */ {CC_OTP_DCU_OFFSET, CC_OTP_DCU_SIZE_IN_WORDS},
        /* PROJ_OTP_SW_VERSION_TRUSTED_FIELD,     */ {CC_OTP_SECURE_MIN_SW_VERSION_FLAG_OFFSET, CC_OTP_SECURE_MIN_SW_VERSION_SIZE_IN_WORDS},
        /* PROJ_OTP_SW_VERSION_NOT_TRUSTED_FIELD, */ {CC_OTP_NON_SECURE_MIN_SW_VERSION_FLAG_OFFSET, CC_OTP_NON_SECURE_MIN_SW_VERSION_SIZE_IN_WORDS}
};
uint32_t gDcuDefaults[CC_OTP_DCU_SIZE_IN_WORDS] = {0};

static int Test_ProjDumpOtpImage(uint32_t *otpBuff, uint32_t startOffset, uint32_t length)
{
    uint32_t i;
    uint32_t readWord;

    (void)readWord;

    TEST_LOG_INFO("OTP using buff\n");
    TEST_LOG_INFO("--------------------\n");
    for (i = 0; i < length; ++i)
    {
        readWord = *(otpBuff + startOffset + i);

        TEST_LOG_INFO("%02x: 0x%08x\n", i, readWord);
    }

    return 0;
}

void Test_ProjDumpOtp(uint32_t otpAddress, uint32_t wordLength)
{
    uint32_t i;

    TEST_LOG_INFO("OTP using enviorment\n");
    TEST_LOG_INFO("--------------------\n");
    for (i = 0; i < wordLength; ++i)
    {
        uint32_t readWord = Test_ProjReadOtpWord(otpAddress + i);
        (void)readWord;
        TEST_LOG_INFO("%02x: 0x%08x\n", i, readWord);
    }
}

void Test_ProjSetOtpBufState(uint8_t isPCIMode)
{
    memset((uint8_t*)&gOtpStatus, 0, sizeof(struct TestOtpMask_t));
    if (isPCIMode)
    {
        gOtpStatus.isPCI = true;
        // choose mask by FPGA minor version
        if ((TEST_READ_ENV_REG(CC_REG_OFFSET(HOST_RGF, ENV_FPGA_VERSION)) & 0xFF) == 0x1)
        {
            gOtpStatus.mask = gTestOtpMaskV1;
        }else
        {
            gOtpStatus.mask = gTestOtpMaskV2;
        }
    }
}


void Test_ProjSetChipIndication(uint32_t   *otpValues, ProjOtp_ChipState_t   chipIndication)
{
    SET_OTP_FIELD(otpValues, SECOND_MANUFACTURE_FLAG, TCI, (chipIndication & PROJ_OTP_CHIP_STATE_TEST)?1:0);
    SET_OTP_FIELD(otpValues, SECOND_MANUFACTURE_FLAG, PCI, (chipIndication & PROJ_OTP_CHIP_STATE_PRODUCTION)?1:0);
    Test_ProjSetOtpBufState((chipIndication & PROJ_OTP_CHIP_STATE_PRODUCTION));
}

void Test_ProjSetRma(uint32_t   *otpValues,
                     ProjOtp_Rma_t rmaMode)
{
    SET_OTP_FIELD(otpValues, SECOND_MANUFACTURE_FLAG, ICV_RMA_MODE, (rmaMode & PROJ_OTP_RMA_ICV)?1:0);
    SET_OTP_FIELD(otpValues, SECOND_MANUFACTURE_FLAG, OEM_RMA_MODE, (rmaMode & PROJ_OTP_RMA_OEM)?1:0);
}


void Test_ProjWriteOtpWord (uint32_t offsetInWords, uint32_t value)
{
    //if TCI - OTP mask not in used - write in a regular way
    //XOR with zero remains the same
    // if PCI - OTP mask should be applied
    uint32_t mask = 0;

    if ((gOtpStatus.isPCI) && (offsetInWords <= TEST_OTP_LAST_WORD_IN_MASK))
    {
        mask = gOtpStatus.mask[offsetInWords];
    }


    TEST_WRITE_OTP_BY_ENV(offsetInWords, value^mask);
}

void Test_ProjWriteOtpBuff (uint32_t offsetInWords, uint32_t sizeWords, uint32_t *buff)
{
    uint32_t i = 0;

    for (i = 0; i < sizeWords; i++) {
        Test_ProjWriteOtpWord (offsetInWords+i, buff[i]);
        Test_PalDelay(1000);
    }
}

unsigned int Test_ProjReadOtpWord (uint32_t offsetInWords)
{
    //if TCI - OTP mask not in used - write in a regular way
    //XOR with zero remains the same
    // if PCI - OTP mask should be applied
    unsigned int read_value = 0;
    uint32_t mask = 0;

    if ((gOtpStatus.isPCI) && (offsetInWords <= TEST_OTP_LAST_WORD_IN_MASK))
    {
        mask = gOtpStatus.mask[offsetInWords];
    }

    read_value = TEST_READ_OTP_BY_ENV(offsetInWords);
    read_value = read_value^mask;

    return read_value;
}

unsigned int Test_ProjSetZeroBitsOtpBuff(uint32_t *otpBuff,
                                         ProjOtp_FieldsType_t fieldType,
                                         uint32_t isNotInUse,
                                         bool isWrongNumOfZeros)
{
    uint32_t zeroCount = 0;
    uint32_t i = 0;
    uint32_t keyWithMask[TEST_PROJ_256BIT_KEY_SIZE_WORDS] = {0};
    uint32_t fieldSizeInWords = 0;
    uint32_t fieldOffsetInOtp = 0;

    /* number of zeros is not relevant for the following fields */
    switch(fieldType) {
    case PROJ_OTP_DCU_FIELD:
    case PROJ_OTP_SW_VERSION_TRUSTED_FIELD:
    case PROJ_OTP_SW_VERSION_NOT_TRUSTED_FIELD:
        return TEST_NOT_SUPPORTED_FIELD;
    default:
        break;
    }

    fieldSizeInWords = otpFieldInfo[fieldType].sizeInWords;
    fieldOffsetInOtp = otpFieldInfo[fieldType].OffsetInWords;

    if (fieldSizeInWords > TEST_PROJ_256BIT_KEY_SIZE_WORDS) {
        TEST_LOG_ERROR("ERROR: field is too big, probably not a key %d, fieldSizeInWords %d\n", fieldType, fieldSizeInWords);
        return TEST_INVALID_PARAM_ERR;
    }
    /* if mask is applied, set it before the calculation */
    if (isNotInUse == 0) {
        if (gOtpStatus.isPCI) {
            TEST_LOG_DEBUG("Otp mask is applied - adjust zero counter for key %d\n", fieldType);
            for (i = 0; i<fieldSizeInWords; i++) {
                keyWithMask[i] = otpBuff[fieldOffsetInOtp+i]^gOtpStatus.mask[fieldOffsetInOtp+i];
            }
            TEST_CALC_BUFF_ZEROS(keyWithMask, fieldSizeInWords, zeroCount);
        }else{
            TEST_CALC_BUFF_ZEROS((otpBuff + fieldOffsetInOtp), fieldSizeInWords, zeroCount);
        }
    } else {
        /* Reducing 1 since key with all 0's is not valid */
        zeroCount = TEST_OTP_ZERO_COUNT_128BIT_KEY_NOT_IN_USE;
    }
    TEST_LOG_DEBUG(" zero counter for key %d is 0x%x\n", fieldType, zeroCount);

    if (isWrongNumOfZeros == true) {
        /* change the zero count to be wrong */
        zeroCount = (zeroCount + 1) & 0xff;

        /* make sure zero count is not zero */
        if (zeroCount == 0) {
            zeroCount = 1;
        }
    }

    switch (fieldType){
    case PROJ_OTP_HUK_FIELD:
        SET_OTP_BITFIELD(otpBuff, FIRST_MANUFACTURE_FLAG, HUK, ZERO_BITS, zeroCount);
        break;
    case PROJ_OTP_KCP_FIELD:
        SET_OTP_BITFIELD(otpBuff, OEM_FLAG, KCP, ZERO_BITS, zeroCount);
        break;
    case PROJ_OTP_KCE_FIELD:
        SET_OTP_BITFIELD(otpBuff, OEM_FLAG, KCE, ZERO_BITS, zeroCount);
        break;
    case PROJ_OTP_KPICV_FIELD:
        SET_OTP_BITFIELD(otpBuff, FIRST_MANUFACTURE_FLAG, KPICV, ZERO_BITS, zeroCount);
        break;
    case PROJ_OTP_KCEICV_FIELD:
        SET_OTP_BITFIELD(otpBuff, FIRST_MANUFACTURE_FLAG, KCEICV, ZERO_BITS, zeroCount);
        break;
    case PROJ_OTP_EKCST_FIELD:
        SET_OTP_BITFIELD(otpBuff, OEM_FLAG, EKCST, ZERO_BITS, zeroCount);
        break;
    case PROJ_OTP_HBK_FIELD:
        SET_OTP_BITFIELD(otpBuff, OEM_FLAG, HBK, ZERO_BITS, zeroCount);
        break;
    case PROJ_OTP_HBK0_FIELD:
        SET_OTP_BITFIELD(otpBuff, FIRST_MANUFACTURE_FLAG, HBK0, ZERO_BITS, zeroCount);
        break;
    case PROJ_OTP_HBK1_FIELD:
        SET_OTP_BITFIELD(otpBuff, OEM_FLAG, HBK1, ZERO_BITS, zeroCount);
        break;
    default:
        TEST_LOG_ERROR("ERROR: can't set zero bits for this type of key %d\n", fieldType);
        return TEST_INVALID_PARAM_ERR;
    }
    return TEST_OK;
}

unsigned int Test_ProjSetNotInUseOtpBuff(uint32_t *otpBuff,
                                         ProjOtp_FieldsType_t fieldType,
                                         uint32_t isNotInUse)
{

    switch (fieldType){
    case PROJ_OTP_KCP_FIELD:
        SET_OTP_BITFIELD(otpBuff, OEM_FLAG, KCP, NOT_IN_USE, isNotInUse);
        break;
    case PROJ_OTP_KCE_FIELD:
        SET_OTP_BITFIELD(otpBuff, OEM_FLAG, KCE, NOT_IN_USE, isNotInUse);
        break;
    case PROJ_OTP_KPICV_FIELD:
        SET_OTP_BITFIELD(otpBuff, FIRST_MANUFACTURE_FLAG, KPICV, NOT_IN_USE, isNotInUse);
        break;
    case PROJ_OTP_KCEICV_FIELD:
        SET_OTP_BITFIELD(otpBuff, FIRST_MANUFACTURE_FLAG, KCEICV, NOT_IN_USE, isNotInUse);
        break;
    case PROJ_OTP_EKCST_FIELD:
        SET_OTP_BITFIELD(otpBuff, OEM_FLAG, EKCST, NOT_IN_USE, isNotInUse);
        break;
    case PROJ_OTP_HBK0_FIELD:
        SET_OTP_BITFIELD(otpBuff, FIRST_MANUFACTURE_FLAG, HBK0, NOT_IN_USE, isNotInUse);
        break;
    case PROJ_OTP_HUK_FIELD:
    case PROJ_OTP_HBK_FIELD:
    case PROJ_OTP_HBK1_FIELD:
    case PROJ_OTP_DCU_FIELD:
    case PROJ_OTP_SW_VERSION_TRUSTED_FIELD:
    case PROJ_OTP_SW_VERSION_NOT_TRUSTED_FIELD:
        return TEST_NOT_SUPPORTED_FIELD;

    default:
        TEST_LOG_ERROR("ERROR: can't set notInUse bit for this type of fieldType %d\n", fieldType);
        return TEST_INVALID_PARAM_ERR;

    }
    return TEST_OK;
}

unsigned int Test_ProjSetOtpField(unsigned int *otpBuff,
                                  unsigned int *fieldBuff,
                                  ProjOtp_FieldsType_t fieldType,
                                  uint32_t isNotInUse)
{
    uint32_t fieldSizeInWords = 0;
    uint32_t fieldOffsetInOtp = 0;
    uint32_t rc = 0;

    fieldSizeInWords = otpFieldInfo[fieldType].sizeInWords;
    fieldOffsetInOtp = otpFieldInfo[fieldType].OffsetInWords;

    /* Copy buffer into gOtpBuff */
    if (fieldBuff != NULL) {
        memcpy((uint8_t *) (otpBuff + fieldOffsetInOtp), (uint8_t *)fieldBuff, (fieldSizeInWords * CC_32BIT_WORD_SIZE));
    }
     /* set not in use in field */
    rc = Test_ProjSetNotInUseOtpBuff(otpBuff, fieldType, isNotInUse);
    if ((rc != TEST_OK) &&
        (rc != TEST_NOT_SUPPORTED_FIELD)) {
        return rc;
    }
     /* set number of zeros in field */
    rc = Test_ProjSetZeroBitsOtpBuff(otpBuff, fieldType, isNotInUse, false);
    if ((rc != TEST_OK) &&
        (rc != TEST_NOT_SUPPORTED_FIELD)) {
        return rc;
    }
    return 0;
}



unsigned int Test_ProjSetHbkInOtpBuff(unsigned int *otp,
                                      unsigned char *hbkBuff,
                                      uint32_t  hbkBuffWordSize,
                                      ProjOtp_FieldsType_t hbkType,
                                      uint32_t nextLcs)
{
    uint32_t i = 0;
    uint32_t rc = 0;
    uint32_t otpWordSize =
            (hbkType == PROJ_OTP_HBK_FIELD) ? CC_OTP_HBK_SIZE_IN_WORDS : CC_OTP_HBK0_SIZE_IN_WORDS;
    uint32_t otpStartOffset =
            (hbkType == PROJ_OTP_HBK1_FIELD) ? CC_OTP_HBK1_OFFSET : CC_OTP_HBK0_OFFSET;

    if ((otp == NULL)||
            ((hbkType != PROJ_OTP_HBK_FIELD) &&
                    (hbkType != PROJ_OTP_HBK0_FIELD) &&
                    (hbkType != PROJ_OTP_HBK1_FIELD))) {
        TEST_LOG_ERROR("ilegal type %d\n", hbkType);
        return TEST_INVALID_PARAM_ERR;
    }
    if (nextLcs == TEST_PROJ_LCS_CM) {
        return TEST_OK;
    }

    /* clear OTP HBK value */
    memset(&otp[otpStartOffset], 0, otpWordSize * CC_32BIT_WORD_SIZE);

    if (hbkType == PROJ_OTP_HBK_FIELD) {
        rc = Test_ProjSetOtpField(otp, NULL, PROJ_OTP_HBK0_FIELD, KEY_NOT_IN_USE);
        if (rc != TEST_OK) {
            TEST_LOG_ERROR("Failed to set HBK0 fields 0x%x\n", rc);
            return rc;
        }
        /* If next lcs is DM, HBK256 should remain clear and overwritten by hbkBuff and its zero count */
        if (nextLcs == TEST_PROJ_LCS_DM) {
            return TEST_OK;
        }
    }
    if ((hbkBuff == NULL) ||
            (hbkBuffWordSize != otpWordSize)) {
        TEST_LOG_ERROR("ilegal type %d\n", hbkType);
        return TEST_INVALID_PARAM_ERR;
    }


    TEST_LOG_DEBUG("writing hbk otpStartOffset %d, hbkBuffWordSize %d\n",
                  otpStartOffset,
                  hbkBuffWordSize);

    for (i = 0; i < hbkBuffWordSize; i++) {
        TEST_CONVERT_BYTE_ARR_TO_WORD(&hbkBuff[i * CC_32BIT_WORD_SIZE],
                                      otp[otpStartOffset + i]);
    }

    switch (hbkType) {
    case PROJ_OTP_HBK_FIELD:
        if (nextLcs > TEST_PROJ_LCS_DM) {
            rc = Test_ProjSetOtpField(otp, NULL, PROJ_OTP_HBK_FIELD, KEY_IN_USE);
        }
        break;
    case PROJ_OTP_HBK0_FIELD:
        rc = Test_ProjSetOtpField(otp, NULL, PROJ_OTP_HBK0_FIELD, KEY_IN_USE);
        break;
    case PROJ_OTP_HBK1_FIELD:
        if (nextLcs > TEST_PROJ_LCS_DM) {
            rc = Test_ProjSetOtpField(otp, NULL, PROJ_OTP_HBK1_FIELD, KEY_IN_USE);
        }
        break;
    default:
        return TEST_INVALID_PARAM_ERR;
    }
    if (rc != TEST_OK) {
        return rc;
    }
    return rc;
}

unsigned int Test_ProjBurnOtp(unsigned int  *otpBuff,
                              unsigned int  nextLcs)
{

    uint32_t error = 0;
    unsigned int i = 0;


    /* Clean OTP */
    for (i = 0; i < TEST_OTP_SIZE_IN_WORDS; i++) {
        TEST_WRITE_OTP_BY_ENV(i, 0);
        Test_PalDelay(1000);
    }
    /* Perform SW reset to reach CM LCS */
    Test_ProjPerformPowerOnReset();
    Test_PalDelay(1000);
    error = Test_ProjCheckLcs(TEST_PROJ_LCS_CM);
    if (error != 0) {
        TEST_LOG_ERROR("Error: Failed to clear OTP!!\n");
    }

    /* Copy new OTP buffer */
     for (i = 0; i < TEST_OTP_SIZE_IN_WORDS; i++) {
         if (otpBuff[i] != 0) {
            Test_ProjWriteOtpWord(i, otpBuff[i]);
            TEST_LOG_TRACE(" OTP[0x%x] - 0x%08x \n", i, otpBuff[i]);
            Test_PalDelay(1000);
         }
     }

    /*  Perform SW reset after writing to OTP new values */
    Test_ProjPerformPowerOnReset();

    /* verify LCS */
    error = Test_ProjCheckLcs(nextLcs);
    if (error == 0) {
        TEST_LOG_TRACE(" OTP burn succeeded with new LCS = 0x%02x \n", nextLcs);
    } else {
        TEST_LOG_ERROR("Error: Failed to burn OTP!!\n");
        Test_ProjDumpOtpImage(otpBuff, 0, TEST_OTP_SIZE_IN_WORDS);
    }
    for (i = 0; i < CC_OTP_DCU_SIZE_IN_WORDS; i++) {
        gDcuDefaults[i] = TEST_READ_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, HOST_DCU_EN0) + i * CC_32BIT_WORD_SIZE);
    }

    return error;
}

/* Set mandatory fields: HUK and HBK#. class keys should be set by the
 * user out of this function scope by calling Test_ProjSetOtpField().
 * baseLcs==CM/DM/SECURE only, if RMA is needed set rmaMode to PROJ_OTP_RMA_FULL and
 *       baseLcs should be based of required fields in OTP to be filled */
unsigned int Test_ProjBuildDefaultOtp(unsigned int  *otpBuff,
                                      uint32_t  otpBuffWordSize,
                                      unsigned int  baseLcs,
                                      ProjOtp_ChipState_t chipIndication,
                                      ProjOtp_Rma_t rmaMode,
                                      uint32_t  isSd,
                                      uint32_t isHbkFull)
{

    uint32_t error = 0;

    if (otpBuffWordSize < TEST_OTP_SIZE_IN_WORDS) {
        return TEST_INVALID_PARAM_ERR;
    }
    /* Clear OTP buffer */
    memset((uint8_t *)otpBuff, 0, TEST_OTP_SIZE_IN_BYTES);

    /* In case user want RMA OTP, the default is based on secure LCS OTP,
     * another option: User can get RMA OTP based on other LCS by using the API with the required baseLcs,
     * and set rmaMode to PROJ_OTP_RMA_FULL */
    if (baseLcs == TEST_PROJ_LCS_RMA) {
        rmaMode = PROJ_OTP_RMA_FULL;
        baseLcs = TEST_PROJ_LCS_SECURE;
    }

    /* Prepare OTP */
    Test_ProjSetChipIndication(otpBuff, chipIndication);
    SET_OTP_SECURE_DISBALE(otpBuff, isSd);
    Test_ProjSetRma(otpBuff, rmaMode);

    switch(baseLcs) {
    case TEST_PROJ_LCS_CM:
        return TEST_OK;
        break;
    case TEST_PROJ_LCS_DM:
        error = Test_ProjSetOtpField(otpBuff, gHukBuff, PROJ_OTP_HUK_FIELD, KEY_IN_USE);
        if (error != TEST_OK) {
            return error;
        }
        if (isHbkFull == 1) {
            error =  Test_ProjSetHbkInOtpBuff(otpBuff, NULL, 0, PROJ_OTP_HBK_FIELD, baseLcs);
            if (error != TEST_OK) {
                return error;
            }
        } else {
            error = Test_ProjSetHbkInOtpBuff(otpBuff, (uint8_t *)gHbk0Buff, CC_OTP_HBK0_SIZE_IN_WORDS, PROJ_OTP_HBK0_FIELD, baseLcs);
            if (error != TEST_OK) {
                return error;
            }
        }
        error = Test_ProjSetOtpField(otpBuff, NULL, PROJ_OTP_KPICV_FIELD, KEY_NOT_IN_USE);
        if (error != TEST_OK) {
            return error;
        }
        error = Test_ProjSetOtpField(otpBuff, NULL, PROJ_OTP_KCEICV_FIELD, KEY_NOT_IN_USE);
        if (error != TEST_OK) {
            return error;
        }
        break;
    case TEST_PROJ_LCS_SECURE:
        error = Test_ProjSetOtpField(otpBuff, gHukBuff, PROJ_OTP_HUK_FIELD, KEY_IN_USE);
        if (error != TEST_OK) {
            return error;
        }
        if (isHbkFull == 1) {
            error = Test_ProjSetHbkInOtpBuff(otpBuff, (uint8_t *)gHbk256Buff, CC_OTP_HBK_SIZE_IN_WORDS, PROJ_OTP_HBK_FIELD, baseLcs);
            if (error != TEST_OK) {
                return error;
            }
        } else {
            error = Test_ProjSetHbkInOtpBuff(otpBuff, (uint8_t *)gHbk0Buff, CC_OTP_HBK0_SIZE_IN_WORDS, PROJ_OTP_HBK0_FIELD, baseLcs);
            if (error != TEST_OK) {
                return error;
            }
            error = Test_ProjSetHbkInOtpBuff(otpBuff, (uint8_t *)gHbk1Buff, CC_OTP_HBK1_SIZE_IN_WORDS, PROJ_OTP_HBK1_FIELD, baseLcs);
            if (error != TEST_OK) {
                return error;
            }
        }
        error = Test_ProjSetOtpField(otpBuff, NULL, PROJ_OTP_KCP_FIELD, KEY_NOT_IN_USE);
        if (error != TEST_OK) {
            return error;
        }
        error = Test_ProjSetOtpField(otpBuff, NULL, PROJ_OTP_KCE_FIELD, KEY_NOT_IN_USE);
        if (error != TEST_OK) {
            return error;
        }
        error = Test_ProjSetOtpField(otpBuff, NULL, PROJ_OTP_EKCST_FIELD, KEY_NOT_IN_USE);
        if (error != TEST_OK) {
            return error;
        }
        break;

    default:
        TEST_LOG_ERROR("Error: Invalid nextLcs %d!!\n", baseLcs);
        return TEST_INVALID_PARAM_ERR;
    }

    return error;
}

unsigned int Test_ProjBuildAndBurnOtp(unsigned int  *otpBuff,
                                      unsigned int  nextLcs,
                                      ProjOtp_ChipState_t chipIndication,
                                      uint32_t  isSd,
                                      uint32_t isHbkFull)
{
    uint32_t rc = TEST_OK;
    ProjOtp_Rma_t rmaMode = PROJ_OTP_RMA_NO;
    unsigned int  baseLcs = nextLcs;

    if (nextLcs == TEST_PROJ_LCS_RMA) {
        baseLcs = TEST_PROJ_LCS_SECURE;
        rmaMode = PROJ_OTP_RMA_FULL;
    }
    rc = Test_ProjBuildDefaultOtp(otpBuff, TEST_OTP_SIZE_IN_WORDS, baseLcs, chipIndication, rmaMode, isSd, isHbkFull);
    if (rc != TEST_OK) {
        TEST_LOG_ERROR("Test_ProjBuildDefaultOtp failed!!\n");
        return rc;
    }
    rc = Test_ProjBurnOtp(otpBuff, nextLcs);
    if (rc != TEST_OK) {
        TEST_LOG_ERROR("Test_ProjBurnOtp failed!!\n");
        return rc;
    }
    return TEST_OK;
}

unsigned int Test_ProjSetShadowKey(uint32_t *pKey, size_t keyLenWords, ProjOtp_FieldsType_t fieldType) {
    size_t i;
    switch (fieldType) {
        case PROJ_OTP_HUK_FIELD:
            if (keyLenWords != CC_OTP_HUK_SIZE_IN_WORDS) {
                TEST_LOG_ERROR("Wrong key len %zu!!\n", keyLenWords);;
                return 1;
            }
            for (i = 0; i < keyLenWords; ++i) {
                TEST_WRITE_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, HOST_SHADOW_HUK_REG), pKey[i]);
            }
            break;
        case PROJ_OTP_KCP_FIELD:
            if (keyLenWords != CC_OTP_KCP_SIZE_IN_WORDS) {
                TEST_LOG_ERROR("Wrong key len %zu!!\n", keyLenWords);;
                return 1;
            }
            for (i = 0; i < keyLenWords; ++i) {
                TEST_WRITE_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, HOST_SHADOW_KCP_REG), pKey[i]);
            }
            break;
        case PROJ_OTP_KCE_FIELD:
            if (keyLenWords != CC_OTP_KCE_SIZE_IN_WORDS) {
                TEST_LOG_ERROR("Wrong key len %zu!!\n", keyLenWords);;
                return 1;
            }
            for (i = 0; i < keyLenWords; ++i) {
                TEST_WRITE_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, HOST_SHADOW_KCE_REG), pKey[i]);
            }
            break;
        case PROJ_OTP_KPICV_FIELD:
            if (keyLenWords != CC_OTP_KPICV_SIZE_IN_WORDS) {
                TEST_LOG_ERROR("Wrong key len %zu!!\n", keyLenWords);;
                return 1;
            }
            for (i = 0; i < keyLenWords; ++i) {
                TEST_WRITE_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, HOST_SHADOW_KPICV_REG), pKey[i]);
            }
            break;
        case PROJ_OTP_KCEICV_FIELD:
            if (keyLenWords != CC_OTP_KCEICV_SIZE_IN_WORDS) {
                TEST_LOG_ERROR("Wrong key len %zu!!\n", keyLenWords);;
                return 1;
            }
            for (i = 0; i < keyLenWords; ++i) {
                TEST_WRITE_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, HOST_SHADOW_KCEICV_REG), pKey[i]);
            }
            break;
        case PROJ_OTP_EKCST_FIELD:
            if (keyLenWords != CC_OTP_EKCST_SIZE_IN_WORDS) {
                TEST_LOG_ERROR("Wrong key len %zu!!\n", keyLenWords);;
                return 1;
            }
            for (i = 0; i < keyLenWords; ++i) {
                TEST_WRITE_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, HOST_SHADOW_EKCST_REG), pKey[i]);
            }
            break;
        default:
            TEST_LOG_ERROR("unsopprted field %u!!\n", fieldType);
            return 1;
    }

    return 0;
}
