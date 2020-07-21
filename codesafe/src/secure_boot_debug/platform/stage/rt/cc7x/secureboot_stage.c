/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#define CC_PAL_LOG_CUR_COMPONENT CC_LOG_MASK_SECURE_BOOT

/************* Include Files ****************/

#include "secureboot_defs.h"
#include "bootimagesverifier_error.h"
#include "secureboot_stage_defs.h"
#include "cc_sbrt_crypto_int_defs.h"
#include "cc_pal_log.h"
#include "cc_pal_mem.h"
#include "cc_hal_plat.h"
#include "cc_otp_defs.h"
#include "bsv_hw_defs.h"

/************************ Defines ******************************/
/*! Definition for all ones word. */
#define CC_SBRT_U32_ALL_ONES_VALUE               0xffffffffUL

/*! Definition for number of bits in a 32bit word. */
#define CC_SBRT_U32_ALL_ONES_NUM_BITS            32

#define CC_SBRT_COUNT_ZEROES(regVal, regZero)                           \
    do {                                                                \
        uint32_t val = regVal;                                          \
        val = val - ((val >> 1) & 0x55555555);                          \
        val = (val & 0x33333333) + ((val >> 2) & 0x33333333);           \
        val = ((((val + (val >> 4)) & 0xF0F0F0F) * 0x1010101) >> 24);   \
        regZero    += (32 - val);                                       \
    }while(0)

/************************ Enums ******************************/

/************************ Typedefs ******************************/

/************************ Global Data ******************************/

/************************ Internal Functions ******************************/

/************************ Public Functions ******************************/
static CCError_t SbrtGetSwVersionInfo(CCSbSwVersionId_t swVersionId,
                                      uint32_t *swVersionWidth,
                                      uint32_t *swVersionOffset,
                                      uint32_t *swVersionVal)
{
    uint32_t cntrWidth = 0;
    uint32_t cntrOffset = 0;
    uint32_t cntrMax = 0;

    switch (swVersionId) {
        case CC_SW_VERSION_TRUSTED:
            cntrWidth = CC_OTP_SECURE_MIN_SW_VERSION_SIZE_IN_WORDS;
            cntrOffset = CC_OTP_SECURE_MIN_SW_VERSION_FLAG_OFFSET;
            break;
        case CC_SW_VERSION_NON_TRUSTED:
            cntrWidth = CC_OTP_NON_SECURE_MIN_SW_VERSION_SIZE_IN_WORDS;
            cntrOffset = CC_OTP_NON_SECURE_MIN_SW_VERSION_FLAG_OFFSET;
            break;
        default:
            return CC_BSV_ILLEGAL_INPUT_PARAM_ERR;
    }

    cntrMax = cntrWidth * CC_SBRT_U32_ALL_ONES_NUM_BITS;

    if (swVersionWidth != NULL) {
        *swVersionWidth = cntrWidth;
    }
    if (swVersionOffset != NULL) {
        *swVersionOffset = cntrOffset;
    }
    if (swVersionVal != NULL) {
        *swVersionVal = cntrMax;
    }
    return CC_OK;
}

static uint32_t SbrtIsHbkVerifyAgainstOtp(unsigned long hwBaseAddress, CCSbPubKeyIndexType_t keyIndex, CCBool_t *pIsVerify)
{
    CCError_t error = CC_OK;
    uint32_t lcs = 0;
    CCBool_t isVerify = CC_TRUE;

    if (pIsVerify == NULL) {
        CC_PAL_LOG_ERR("pIsVerify is NULL\n");
        return CC_SBRT_ILLEGEL_PARAMETER;
    }

    /* get current lcs */
    error = SbrtLcsGet(hwBaseAddress, &lcs);
    if (error) {
        return error;
    }

    switch (lcs) {
        case CC_BSV_SECURE_LCS:
            /* case SE, return true */
            isVerify = CC_TRUE;
            break;
        case CC_BSV_DEVICE_MANUFACTURE_LCS:
            /* case DM & HBK0, return true */
            if (keyIndex == CC_SB_HASH_BOOT_KEY_0_128B) {
                isVerify = CC_TRUE;
            } else {
                isVerify = CC_FALSE;
            }
            break;
        case CC_BSV_CHIP_MANUFACTURE_LCS:
        case CC_BSV_RMA_LCS:
            isVerify = CC_FALSE;
            break;
        default:
            CC_PAL_LOG_ERR("unknown lcs mode[%u]\n", lcs);
            error = CC_SBRT_ILLEGEL_PARAMETER;
            break;
    }

    *pIsVerify = isVerify;

    return error;
}

CCError_t SbrtSwVersionGet(unsigned long hwBaseAddress, CCSbSwVersionId_t id, uint32_t *swVersion)
{
    CCError_t error = CC_OK;

    uint32_t i = 0;
    uint32_t regVal = 0;
    uint32_t tmpVal = 0;
    uint32_t versionBitCount = 0;
    uint32_t cntrWidth = 0;
    uint32_t cntrOffset = 0;
    uint32_t cntrSwVersion = 0;
    CCBool_t isNextWordZero = CC_FALSE;

    /* check swVersion pointer */
    if (swVersion == NULL) {
        return CC_SBRT_ILLEGEL_PARAMETER;
    }

    /* Get the maximum allowed SW version for the defined ID */
    error = SbrtGetSwVersionInfo(id, &cntrWidth, &cntrOffset, NULL);
    if (error != CC_OK) {
        return error;
    }

    /* clear version in case of error */
    *swVersion = 0;

    /* read the SW version from the OTP, and accumulate number of ones */
    cntrSwVersion = 0;
    for (i = 0; i < cntrWidth; i++) {
        CC_BSV_READ_OTP_WORD(hwBaseAddress, cntrOffset + i, regVal, error);
        if (error != CC_OK) {
            return error;
        }

        COUNT_ONE_BITS(regVal, versionBitCount);

        /* verify legality of 1's bits */
        /* once isNextWordZero is TRUE all subsequent words should be 0 */
        if ((isNextWordZero == CC_TRUE) && (regVal != 0)) {
            return CC_SBRT_ILLIGAL_SW_VERSION_ERROR;
        }

        if (versionBitCount < CC_SBRT_U32_ALL_ONES_NUM_BITS) {
            isNextWordZero = CC_TRUE;
        }

        /* convert versionBitCount to base-1 representation and compare to OTP word */
        if (versionBitCount != 0) {
            BITFIELD_U32_SHIFT_R(tmpVal,
                                 CC_SBRT_U32_ALL_ONES_VALUE,
                                 CC_SBRT_U32_ALL_ONES_NUM_BITS - versionBitCount);
        } else {
            tmpVal = 0;
        }

        /* validate that the number is of valid form, meaning not zeros in the middle of the word. */
        if (tmpVal != regVal) {
            /* return error in case of invalid base-1 value */
            return CC_SBRT_ILLIGAL_SW_VERSION_ERROR;
        }

        cntrSwVersion += versionBitCount;
    }

    *swVersion = cntrSwVersion;

    return CC_OK;
}

CCError_t SbrtSwVersionSet(unsigned long hwBaseAddress, CCSbSwVersionId_t id, uint32_t swVersion)
{
    CCError_t error = CC_OK;

    uint32_t i = 0;
    uint32_t regVal = 0;
    uint32_t cntrWidth = 0;
    uint32_t cntrOffset = 0;
    uint32_t cntrMax = 0;
    uint32_t currentSwVersion = 0;

    /* Get the maximum allowed SW version for the defined ID */
    error = SbrtGetSwVersionInfo(id, &cntrWidth, &cntrOffset, &cntrMax);
    if (error != CC_OK) {
        return error;
    }

    /* read current version counter */
    error = SbrtSwVersionGet(hwBaseAddress, id, &currentSwVersion);
    if (error != CC_OK) {
        return error;
    }

    /* verify new version validity */
    if ((swVersion > cntrMax) || (swVersion <= currentSwVersion)) {
        return CC_SBRT_ILLEGEL_PARAMETER;
    }

    /* Write new SW version to otp */
    for (i = 0; i < cntrWidth; i++) {
        /* convert to base-1 representation */
        BITFIELD_U32_SHIFT_R(regVal,
                             CC_SBRT_U32_ALL_ONES_VALUE,
                             CC_SBRT_U32_ALL_ONES_NUM_BITS - min(swVersion, CC_SBRT_U32_ALL_ONES_NUM_BITS));
        swVersion -= min(swVersion, CC_SBRT_U32_ALL_ONES_NUM_BITS);

        CC_BSV_WRITE_OTP_VERIFY_WORD(hwBaseAddress, cntrOffset + i, regVal, error);
        if (error != CC_OK) {
            return error;
        }
    }

    return CC_OK;
}

CCError_t SbrtVerifyNvCounter(unsigned long hwBaseAddress,
                              uint32_t nvCounter,
                              CCSbCertInfo_t *certPkgInfo)
{
    CCError_t error = CC_OK;
    uint32_t otpVersion;
    uint32_t initFlag;
    nvCounter_t currentNvCounter;
    CCSbSwVersionId_t nvCounterId;
    uint32_t nvCounterValue;
    uint32_t activeNvCounter;
    uint32_t maxNvCounterVal = 0;
    CCBool_t isVerify = CC_TRUE;

    /* Validate input parameters */
    if (certPkgInfo == NULL) {
        CC_PAL_LOG_ERR("invalid inputs\n");
        return CC_BOOT_IMG_VERIFIER_INV_INPUT_PARAM;
    }

    initFlag = certPkgInfo->initDataFlag;
    currentNvCounter.nvCounterWord = nvCounter;
    nvCounterId = (CCSbSwVersionId_t) (currentNvCounter.nvCounterBits.nvCounterId);
    nvCounterValue = currentNvCounter.nvCounterBits.nvCounterValue;

    /* Verify that all certificates in the chain have the same revocation number */
    if (initFlag == CC_SB_FIRST_CERT_IN_CHAIN) {
        /* Get sw version from OTP */
        error = SbrtSwVersionGet(hwBaseAddress, nvCounterId, &otpVersion);
        if (CC_OK != error) {
            return error;
        }

        certPkgInfo->otpVersion = otpVersion;
    } else {

        otpVersion = certPkgInfo->otpVersion;
        activeNvCounter = certPkgInfo->nvCounter;

        if (activeNvCounter != nvCounter) {
            CC_PAL_LOG_ERR("active counter version is different from the current version in the chain.\n");
            error = CC_BOOT_IMG_VERIFIER_CERT_SW_VER_ILLEGAL;
            goto end_error;
        }
    }

    /* Get the maximum sw version value */
    error = SbrtGetSwVersionInfo(nvCounterId, NULL, NULL, &maxNvCounterVal);
    if (error != CC_OK) {
        goto end_error;
    }

    if (nvCounterValue > maxNvCounterVal) {
        CC_PAL_LOG_ERR("certificate nvCounter is bigger than maximum.\n");
        error = CC_BOOT_IMG_VERIFIER_CERT_SW_VER_ILLEGAL;
        goto end_error;
    }

    /* Skip NV counter verification against OTP, in case of invalid SB chain that based on HBK index not valid */
    error = SbrtIsHbkVerifyAgainstOtp(hwBaseAddress, certPkgInfo->keyIndex, &isVerify);
    if (error != CC_OK) {
        CC_PAL_LOG_ERR("SbrtIsHbkVerifyAgainstOtp failed err[0x%08x]\n", error);
        goto end_error;
    }

    if (isVerify == CC_FALSE) {
        return CC_OK;
    }

    /* Verify the certificate version against the OTP */
    if (nvCounterValue < otpVersion) {
        CC_PAL_LOG_ERR("certificate nvCounter is smaller than the minimum counter version in the OTP.\n");
        error = CC_BOOT_IMG_VERIFIER_SW_VER_SMALLER_THAN_MIN_VER;
        goto end_error;
    }

    return CC_OK;
end_error:
    /* in case of error clear updated value */
    if (initFlag == CC_SB_FIRST_CERT_IN_CHAIN) {
        certPkgInfo->otpVersion = 0;
    }
    return error;

}

CCError_t SbrtUpdateNvCounter(unsigned long hwBaseAddress, CCSbCertInfo_t *certPkgInfo)
{
    CCError_t error = CC_OK;
    uint32_t otpVer = 0;
    uint32_t lcs;
    nvCounter_t currentNvCounter;
    CCSbSwVersionId_t nvCounterId;
    uint32_t nvCounterValue;
    CCBool_t isVerify = CC_TRUE;

    if (certPkgInfo == NULL) {
        return CC_BOOT_IMG_VERIFIER_INV_INPUT_PARAM;
    }

    /* skip NV counter update in case of invalid SB chain that based on HBK index not valid */
    error = SbrtIsHbkVerifyAgainstOtp(hwBaseAddress, certPkgInfo->keyIndex, &isVerify);
    if (error != CC_OK) {
        CC_PAL_LOG_ERR("SbrtIsHbkVerifyAgainstOtp failed err[0x%08x]\n", error);
        return error;
    }

    if (isVerify == CC_FALSE) {
        return CC_OK;
    }

    otpVer = certPkgInfo->otpVersion;
    currentNvCounter.nvCounterWord = certPkgInfo->nvCounter;
    nvCounterId = (CCSbSwVersionId_t) (currentNvCounter.nvCounterBits.nvCounterId);
    nvCounterValue = currentNvCounter.nvCounterBits.nvCounterValue;

    /* verify the certificate version against the otp */
    if (nvCounterValue < otpVer) {
        CC_PAL_LOG_ERR("certificate nvCounter is smaller than the minimum counter version in the OTP.\n");
        return CC_BOOT_IMG_VERIFIER_SW_VER_SMALLER_THAN_MIN_VER;
    }

    /* if version is bigger, then set the new version in the otp */
    if (nvCounterValue > otpVer) {

        /* Get LCS from register */
        error = SbrtLcsGet(hwBaseAddress, &lcs);
        if (error != CC_OK) {
            return error;
        }

        /* SB should should not update SW version if LCS is RMA */
        if (lcs == CC_BSV_RMA_LCS) {
            return CC_OK;
        }

        /* Set SW version according to counter ID */
        error = SbrtSwVersionSet(hwBaseAddress, nvCounterId, nvCounterValue);
        if (error != CC_OK) {
            return error;
        }

        /* Verify that version was written correctly */
        error = SbrtSwVersionGet(hwBaseAddress, nvCounterId, &otpVer);
        if (error != CC_OK) {
            return error;
        }

        if (otpVer != nvCounterValue) {
            return CC_BOOT_IMG_VERIFIER_OTP_VERSION_FAILURE;
        }
    }

    return CC_OK;
}

CCError_t SbrtLcsGet(unsigned long hwBaseAddress, uint32_t *pLcs)
{
    uint32_t regVal = 0;
    uint32_t isSDEnable = 0;

    CC_UNUSED_PARAM(hwBaseAddress);

    /* boot services are not available in "secure disabled mode" */
    CC_BSV_IS_SD_FLAG_SET(hwBaseAddress, isSDEnable);
    if (isSDEnable == 1) {
        return CC_SBRT_SECURE_DISABLE_ERROR;
    }

    /* check input variables */
    if (pLcs == NULL) {
        return CC_SBRT_ILLEGEL_PARAMETER;
    }

    /* read LCS register */
    regVal = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, LCS_REG));
    regVal = CC_REG_FLD_GET(0, LCS_REG, LCS_REG, regVal);

    /* return the LCS value */
    *pLcs = regVal;

    return CC_OK;
}

CCError_t SbrtPubKeyHashGet(unsigned long hwBaseAddress, CCSbPubKeyIndexType_t keyIndex, uint32_t *hashedPubKey, uint32_t hashResultSizeWords)
{
    CCError_t error = CC_OK;
    uint32_t i;
    uint32_t address;
    uint32_t regVal = 0;
    uint32_t cntZero = 0;
    uint32_t zerosHash = 0;
    uint32_t oemFlag = 0;
    uint32_t icvFlag = 0;
    uint32_t lcs = 0;
    uint32_t isHbkFull = 0;

    /* check hash buffer pointer */
    if (hashedPubKey == NULL) {
        return CC_SBRT_ILLEGEL_PARAMETER;
    }

    /* get lifecycle */
    error = SbrtLcsGet(hwBaseAddress, &lcs);
    if (error != CC_OK) {
        return error;
    }

    /* in case of CM, return error */
    if (lcs == CC_RT_CHIP_MANUFACTURE_LCS) {
        return CC_BSV_HASH_NOT_PROGRAMMED_ERR;
    }

    /* get HBK configuration */
    CC_BSV_IS_HBK_FULL(hwBaseAddress, isHbkFull, error);
    if (error != CC_OK) {
        return error;
    }

    /* read icv flags word */
    CC_BSV_READ_OTP_WORD(hwBaseAddress, CC_OTP_FIRST_MANUFACTURE_FLAG_OFFSET, icvFlag, error);
    if (error != CC_OK) {
        return error;
    }

    /* read OEM programmer flags word */
    CC_BSV_READ_OTP_WORD(hwBaseAddress, CC_OTP_OEM_FLAG_OFFSET, oemFlag, error);
    if (error != CC_OK) {
        return error;
    }

    /* verify validity of key index, key size and mode of operation */
    switch (keyIndex) {
        case CC_SB_HASH_BOOT_KEY_256B:
            /* key size should hold 256b */
            if (hashResultSizeWords != CC_SBRT_256B_HASH_SIZE_IN_WORDS)
            {
                return CC_SBRT_ILLEGEL_PARAMETER;
            }

            /* otp shuld support full HBK */
            if (isHbkFull != CC_TRUE) {
                return CC_SBRT_ILLEGEL_OPERATION;
            }

            /* Hbk0 zero count should be cleared */
            if (CC_REG_FLD_GET(0, OTP_FIRST_MANUFACTURE_FLAG, HBK0_ZERO_BITS, icvFlag) != 0) {
                return CC_SBRT_ILLEGEL_OPERATION;
            }

            /* DM lcs is illegal for Hbk */
            if (lcs == CC_RT_DEVICE_MANUFACTURE_LCS) {
                return CC_BSV_HASH_NOT_PROGRAMMED_ERR;
            }

            zerosHash = CC_REG_FLD_GET(0, OTP_OEM_FLAG, HBK_ZERO_BITS, oemFlag);
            address = CC_OTP_HBK_OFFSET;
            break;

        case CC_SB_HASH_BOOT_KEY_0_128B:
            /* key size should hold 128b */
            if (hashResultSizeWords != CC_SBRT_128B_HASH_SIZE_IN_WORDS) {
                return CC_SBRT_ILLEGEL_PARAMETER;
            }

            /* otp should support 2 HBK's */
            if (isHbkFull == CC_TRUE) {
                return CC_SBRT_ILLEGEL_OPERATION;
            }

            zerosHash = CC_REG_FLD_GET(0, OTP_FIRST_MANUFACTURE_FLAG, HBK0_ZERO_BITS, icvFlag);
            address = CC_OTP_HBK0_OFFSET;
            break;

        case CC_SB_HASH_BOOT_KEY_1_128B:
            /* key size should hold 128b */
            if (hashResultSizeWords != CC_SBRT_128B_HASH_SIZE_IN_WORDS) {
                return CC_SBRT_ILLEGEL_PARAMETER;
            }

            /* otp should support 2 HBK's */
            if (isHbkFull == CC_TRUE) {
                return CC_SBRT_ILLEGEL_OPERATION;
            }

            /* DM lcs is illegal for Hbk1 */
            if (lcs == CC_RT_DEVICE_MANUFACTURE_LCS) {
                return CC_BSV_HASH_NOT_PROGRAMMED_ERR;
            }

            zerosHash = CC_REG_FLD_GET(0, OTP_OEM_FLAG, HBK1_ZERO_BITS, oemFlag);
            address = CC_OTP_HBK1_OFFSET;
            break;

        default:
            return CC_SBRT_ILLEGEL_PARAMETER;
    }

    /* read hash key from OTP */
    for (i = 0; i < hashResultSizeWords; i++) {
        CC_BSV_READ_OTP_WORD(hwBaseAddress, address + i, regVal, error);
        if (error != CC_OK) {
            goto _Err_GetPubKey;
        }
        *(hashedPubKey + i) = regVal;

        /* accumulate number of zeroes */
        CC_SBRT_COUNT_ZEROES(regVal, cntZero);
    }

    /* verify number of "0" bits in the hash key */
    if (zerosHash == cntZero) {
        return CC_OK;
    } else {
        error = CC_SBRT_HBK_ZERO_COUNT_ERR;
    }

    /* case of error, clean hash buffer */
_Err_GetPubKey:

    CC_PalMemSetZero((uint8_t *)hashedPubKey, hashResultSizeWords * CC_32BIT_WORD_SIZE);

    return error;
}

