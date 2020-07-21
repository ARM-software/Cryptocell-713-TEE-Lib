/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */
#include "cc_cpp.h"
#include "cc_regs.h"
#include "cc_hal_plat.h"
#include "cc_pal_mem.h"
#include "cc_error.h"
#include "cc_util_int_defs.h"
#include "cc_hw_queue_defs.h"
#include "cc_lli_defs_int.h"

#define CPP_WD_DISABLE_VALUE   UINT32_MAX
#define CPP_WD_RELOAD_VALUE    0x1

#define CPP_PUB_SRAM_DATA_READY (1<<CC_PUB_SRAM_DATA_READY_VALUE_BIT_SHIFT)

#define CCP_LLI_HADDR_BIT_MASK   (((1 << LLI_HADDR_BIT_SIZE) - 1) \
                                                        << LLI_HADDR_BIT_OFFSET)

CCCppEventFunction pCppEventFunc = NULL;

/*!
@brief This function read one word from PUB (REE) SRAM

@return data word
*/
static uint32_t readPubSram(
        uint32_t addr/*!< [in] sram data offset */)
{
    uint32_t dummy = 0;

    /* set address */
    CC_HAL_WRITE_REGISTER( CC_REG_OFFSET (HOST_RGF,PUB_SRAM_ADDR), (addr) );

    /* wait for data to be ready */
    do {
        dummy = CC_HAL_READ_REGISTER(
                                 CC_REG_OFFSET (HOST_RGF, PUB_SRAM_DATA_READY));
    }while(!(dummy & CPP_PUB_SRAM_DATA_READY));

    /* read and return data */
    /* first read is dummy, drop this value */
    CC_HAL_READ_REGISTER( CC_REG_OFFSET (HOST_RGF,PUB_SRAM_DATA));

    /* read actual value */
    return CC_HAL_READ_REGISTER( CC_REG_OFFSET (HOST_RGF,PUB_SRAM_DATA));

}

/*!
@brief This function parse sram LLI table

@return void
*/
static CCError_t parseSramTable (
                uint32_t        sramAddr,        /*!< [in] sram data offset  */
                uint32_t        numberOfEntries, /*!< [in] number of entries */
                CCCppBufInfo_t* pBuffInfo /*!< [out] buffer to save the data */
                )
{
    uint32_t i;
    uint32_t lliWord0;
    uint32_t lliWord1;

    if (sramAddr & CCP_LLI_HADDR_BIT_MASK){
        return CC_CPP_WRONG_PARAMETERS_ERROR;
    }
    if (pBuffInfo == NULL){
        return CC_CPP_WRONG_PARAMETERS_ERROR;
    }
    if (numberOfEntries >  LLI_MAX_NUM_OF_ENTRIES){
        return CC_CPP_WRONG_PARAMETERS_ERROR;
    }

    pBuffInfo->numberOfEntries = numberOfEntries;

    for (i = 0; i < pBuffInfo->numberOfEntries; i++)
    {
        lliWord0 = readPubSram(sramAddr + i*LLI_ENTRY_BYTE_SIZE);

        lliWord1 = readPubSram(sramAddr + i*LLI_ENTRY_BYTE_SIZE
                                                            + sizeof(uint32_t));
        pBuffInfo->buffers[i].bus_addr =
                (((uint64_t)BITFIELD_GET(lliWord1,
                                         LLI_HADDR_BIT_OFFSET,
                                         LLI_HADDR_BIT_SIZE)) << 32) | lliWord0;
        pBuffInfo->buffers[i].size     =
                            BITFIELD_GET(lliWord1,
                                         LLI_SIZE_BIT_OFFSET,
                                         LLI_SIZE_BIT_SIZE);
    }
    return CC_OK;
}

CCError_t CC_CppStreamIdSet(uint16_t readStreamId,
                            uint16_t writeStreamId)
{
    uint32_t regVal = 0;
    uint32_t isSecureDisableSet = 0;
    uint32_t isFatalErrorSet = 0;

    /* The function should refuse to operate if the secure disable bit is set */
    CC_UTIL_IS_SECURE_DISABLE_FLAG_SET(isSecureDisableSet);
    if (isSecureDisableSet == SECURE_DISABLE_FLAG_SET) {
        return CC_CPP_SD_ENABLED_ERROR;
    }

    /* The function should refuse to operate if the Fatal Error bit is set */
    CC_UTIL_IS_FATAL_ERROR_SET(isFatalErrorSet);
    if (isFatalErrorSet == FATAL_ERROR_FLAG_SET) {
        return CC_CPP_FATAL_ERR_IS_LOCKED_ERR;
    }

    /* set readStreamId to bits 31:16 */
    regVal = readStreamId <<
                  CC_REG_BIT_SHIFT(HOST_STREAM_ID_CPP_VAL, ARSTREAM_ID_CPP_VAL);
    /* set writeStreamId to bits 15:0 */
    regVal = regVal | writeStreamId;

    CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_STREAM_ID_CPP_VAL),
                  regVal);

    return CC_OK;
}


CCError_t CC_CppWatchdogSet(CCBool enable, uint32_t cycles)
{
    uint32_t isSecureDisableSet = 0;
    uint32_t isFatalErrorSet = 0;

    if ((enable != CC_TRUE) && (enable != CC_FALSE))
    {
        return CC_CPP_WRONG_PARAMETERS_ERROR;
    }
    /* The function should refuse to operate if the secure disable bit is set */
    CC_UTIL_IS_SECURE_DISABLE_FLAG_SET(isSecureDisableSet);
    if (isSecureDisableSet == SECURE_DISABLE_FLAG_SET) {
        return CC_CPP_SD_ENABLED_ERROR;
    }
    /* The function should refuse to operate if the Fatal Error bit is set */
    CC_UTIL_IS_FATAL_ERROR_SET(isFatalErrorSet);
    if (isFatalErrorSet == FATAL_ERROR_FLAG_SET) {
        return CC_CPP_FATAL_ERR_IS_LOCKED_ERR;
    }

    /* In case the watchdog is being disabled the watchdog expiry time will be
     * set to a value of ‘all ones’ (0xffffffff).*/
    if (enable == CC_FALSE)
    {
        cycles = CPP_WD_DISABLE_VALUE;
    }
    /* set the WD reload value */
    CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(HOST_RGF,
                          HOST_CPP_WATCHDOG_RELOAD_VALUE), cycles);
    /* in order to activate the new value in the current transaction set the */
    /* WD reload register */
    CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_CPP_WATCHDOG_RELOAD),
                          CPP_WD_RELOAD_VALUE);
    return CC_OK;
}


CCError_t CC_CppKeySet(
        CCCppEngine_t engine, CCCppKeySize_t keySize, uint8_t *pKey)
{
    uint32_t keySizeInWords = 0;
    uint32_t shadowRegOffset;
    uint32_t i = 0;
    uint32_t keyWord = 0;
    uint32_t isSecureDisableSet = 0;
    uint32_t isFatalErrorSet = 0;

    if (pKey == NULL)
    {
        return CC_CPP_WRONG_PARAMETERS_ERROR;
    }

    /* The function should refuse to operate if the secure disable bit is set */
    CC_UTIL_IS_SECURE_DISABLE_FLAG_SET(isSecureDisableSet);
    if (isSecureDisableSet == SECURE_DISABLE_FLAG_SET) {
        return CC_CPP_SD_ENABLED_ERROR;
    }

    /* The function should refuse to operate if the Fatal Error bit is set */
    CC_UTIL_IS_FATAL_ERROR_SET(isFatalErrorSet);
    if (isFatalErrorSet == FATAL_ERROR_FLAG_SET) {
        return CC_CPP_FATAL_ERR_IS_LOCKED_ERR;
    }

    /* parse enum type into words counter
       CC_CPP_KEY_SIZE_128 = 0, CC_CPP_KEY_SIZE_256 = 2 */
    switch (keySize)
    {
    case CC_CPP_KEY_SIZE_128:
        keySizeInWords = CC_128_BIT_KEY_SIZE_IN_WORDS;
        break;
    case CC_CPP_KEY_SIZE_256:
        keySizeInWords = CC_256_BIT_KEY_SIZE_IN_WORDS;
        break;
    default:
        return CC_CPP_WRONG_PARAMETERS_ERROR;
        break;
    }

    switch(engine)
    {
    case CC_CPP_SM4_ENGINE:
        if (keySizeInWords != CC_128_BIT_KEY_SIZE_IN_WORDS)
        {
            return CC_CPP_WRONG_PARAMETERS_ERROR;
        }
        shadowRegOffset = CC_REG_OFFSET(HOST_RGF, HOST_CPP_SM4_KEY);
        break;
#ifdef CC_SUPPORT_FULL_PROJECT
    /* only full version has AES engine (slim version doesn't) */
    case CC_CPP_AES_ENGINE:
        shadowRegOffset = CC_REG_OFFSET(HOST_RGF, HOST_CPP_AES_KEY);
        break;
#endif
    default:
        return CC_CPP_WRONG_PARAMETERS_ERROR;
    }

    /* write key to appropriate cpp shadow register */
    for(i=0; i<keySizeInWords; i++){
        CC_PalMemCopy(&keyWord, pKey+i*4, 4);
        CC_HAL_WRITE_REGISTER(shadowRegOffset, keyWord);
    }
#ifdef CC_SUPPORT_FULL_PROJECT
    /* AES shadow key interface is implemented for 256 bit key
     * for 128 bit key it should be padded by zeros up to 256 bit */
    if ((keySizeInWords == CC_128_BIT_KEY_SIZE_IN_WORDS) &&
            (engine == CC_CPP_AES_ENGINE)){
        for (i=0; i<CC_128_BIT_KEY_SIZE_IN_WORDS; i++ ){
            CC_HAL_WRITE_REGISTER(shadowRegOffset, 0);
        }
    }
#endif
    return CC_OK;
}


CCError_t CC_CppBufInfoGet (CCCppBufInfo_t *bufInfoIn,
                            CCCppBufInfo_t *bufInfoOut)
{
    HwDesc_s desc;
    uint32_t dmaMode = 0;
    uint32_t i = 0;
    uint32_t highAddr = 0;
    uint32_t sramAddr = 0;
    uint32_t numberOfMlliEntries = 0;
    uint32_t isSecureDisableSet = 0;
    uint32_t isFatalErrorSet = 0;
    CCError_t rc = CC_OK;

    /* init with zeros */
    HW_DESC_INIT(&desc);

    /* parameters sanity check*/
    if ((bufInfoIn == NULL) || (bufInfoOut == NULL))
    {
        return CC_CPP_WRONG_PARAMETERS_ERROR;
    }

    /* The function should refuse to operate if the secure disable bit is set */
    CC_UTIL_IS_SECURE_DISABLE_FLAG_SET(isSecureDisableSet);
    if (isSecureDisableSet == SECURE_DISABLE_FLAG_SET) {
        return CC_CPP_SD_ENABLED_ERROR;
    }

    /* The function should refuse to operate if the Fatal Error bit is set */
    CC_UTIL_IS_FATAL_ERROR_SET(isFatalErrorSet);
    if (isFatalErrorSet == FATAL_ERROR_FLAG_SET) {
        return CC_CPP_FATAL_ERR_IS_LOCKED_ERR;
    }

    /* read descriptor */
    for (i=0; i < HW_DESC_SIZE_WORDS; i++)
    {
        desc.word[i] = CC_HAL_READ_REGISTER(
                CC_REG_OFFSET(HOST_RGF, DSCRPTR_CPP_LOADED_FROM_REE_WORD0) +
                                                            i*sizeof(uint32_t));
    }

    /* get the dma mode of descriptor (DLLI/MLLI) */
    dmaMode = BITFIELD_GET(desc.word[1],
                                  CC_DSCRPTR_QUEUE_WORD1_DIN_DMA_MODE_BIT_SHIFT,
                                  CC_DSCRPTR_QUEUE_WORD1_DIN_DMA_MODE_BIT_SIZE);

    /* if Mlli read data from SRAM */
    if (dmaMode == DMA_MLLI)
    {
        /* parse Buff In data */
        sramAddr = desc.word[0];

        numberOfMlliEntries = BITFIELD_GET(desc.word[1],
                CC_DSCRPTR_QUEUE_WORD1_DIN_SIZE_BIT_SHIFT,
                CC_DSCRPTR_QUEUE_WORD1_DIN_SIZE_BIT_SIZE);

        rc = parseSramTable (sramAddr, numberOfMlliEntries, bufInfoIn);
        if (rc != CC_OK){
            goto endOfFunction;
        }

        /* parse Buff Out data */
        sramAddr = desc.word[2];

        numberOfMlliEntries = BITFIELD_GET(desc.word[3],
                CC_DSCRPTR_QUEUE_WORD3_DOUT_SIZE_BIT_SHIFT,
                CC_DSCRPTR_QUEUE_WORD3_DOUT_SIZE_BIT_SIZE);

        rc = parseSramTable (sramAddr, numberOfMlliEntries, bufInfoOut);

        goto endOfFunction;
    }

    /* DLLI */
    bufInfoIn->numberOfEntries = 1;

    /* set buffin low addr */
    bufInfoIn->buffers[0].bus_addr = desc.word[0];

    /* set buffin size */
    bufInfoIn->buffers[0].size = BITFIELD_GET(desc.word[1],
                                     CC_DSCRPTR_QUEUE_WORD1_DIN_SIZE_BIT_SHIFT,
                                     CC_DSCRPTR_QUEUE_WORD1_DIN_SIZE_BIT_SIZE);
    /* buffer Out number of entries*/
    bufInfoOut->numberOfEntries = 1;

    /* set buff out low addr */
    bufInfoOut->buffers[0].bus_addr = desc.word[2];

    /* set buff in size */
    bufInfoOut->buffers[0].size = BITFIELD_GET(desc.word[3],
                                     CC_DSCRPTR_QUEUE_WORD3_DOUT_SIZE_BIT_SHIFT,
                                     CC_DSCRPTR_QUEUE_WORD3_DOUT_SIZE_BIT_SIZE);


    /* set buffin high addr */
    highAddr = BITFIELD_GET(desc.word[5],
                            CC_DSCRPTR_QUEUE_WORD5_DIN_ADDR_HIGH_BIT_SHIFT,
                            CC_DSCRPTR_QUEUE_WORD5_DIN_ADDR_HIGH_BIT_SIZE);
    bufInfoIn->buffers[0].bus_addr  |= ((uint64_t)(highAddr) << 32);

    /* set buffout high addr */
    highAddr = BITFIELD_GET(desc.word[5],
                            CC_DSCRPTR_QUEUE_WORD5_DOUT_ADDR_HIGH_BIT_SHIFT,
                            CC_DSCRPTR_QUEUE_WORD5_DOUT_ADDR_HIGH_BIT_SIZE);
    bufInfoOut->buffers[0].bus_addr |= ((uint64_t)(highAddr) << 32);

endOfFunction:
    return rc;
};


CCError_t CC_CppHandleOp(CCBool accept)
{
    uint32_t isSecureDisableSet = 0;
    uint32_t isFatalErrorSet = 0;

    if ((accept != CC_TRUE) && (accept != CC_FALSE))
    {
        return CC_CPP_WRONG_PARAMETERS_ERROR;
    }

    /* The function should refuse to operate if the secure disable bit is set */
    CC_UTIL_IS_SECURE_DISABLE_FLAG_SET(isSecureDisableSet);
    if (isSecureDisableSet == SECURE_DISABLE_FLAG_SET) {
        CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_ABORT_REE_KS_OPERATION), 1);
        return CC_CPP_SD_ENABLED_ERROR;
    }

    /* The function should refuse to operate if the Fatal Error bit is set */
    CC_UTIL_IS_FATAL_ERROR_SET(isFatalErrorSet);
    if (isFatalErrorSet == FATAL_ERROR_FLAG_SET) {
        return CC_CPP_FATAL_ERR_IS_LOCKED_ERR;
    }

    /* the input parameter is used to choose between
     * accepting the operation by writing to the approve_ree_ks_operation reg
     * or rejecting it by writing to the abort_ree_ks_operation register*/
    if (accept)
    {
        CC_HAL_WRITE_REGISTER(
                CC_REG_OFFSET(HOST_RGF, HOST_APPROVE_REE_KS_OPERATION), 1);
    }else{
        CC_HAL_WRITE_REGISTER(
                 CC_REG_OFFSET(HOST_RGF, HOST_ABORT_REE_KS_OPERATION), 1);

    }
    return CC_OK;
}


CCError_t CC_CppRecvOp(CCCppOpParams_t *opParams)
{
    uint32_t ivRegOffset = 0;
    uint32_t reeParamsRegValue;
    uint32_t i = 0;
    uint32_t isSecureDisableSet = 0;
    uint32_t isFatalErrorSet = 0;

    /* parameter sanity check */
    if (opParams == NULL)
    {
        return CC_CPP_WRONG_PARAMETERS_ERROR;
    }

    /* The function should refuse to operate if the secure disable bit is set */
    CC_UTIL_IS_SECURE_DISABLE_FLAG_SET(isSecureDisableSet);
    if (isSecureDisableSet == SECURE_DISABLE_FLAG_SET) {
        return CC_CPP_SD_ENABLED_ERROR;
    }

    /* The function should refuse to operate if the Fatal Error bit is set */
    CC_UTIL_IS_FATAL_ERROR_SET(isFatalErrorSet);
    if (isFatalErrorSet == FATAL_ERROR_FLAG_SET) {
        return CC_CPP_FATAL_ERR_IS_LOCKED_ERR;
    }

    /* Read the REE_params register, thereby stopping
     * the CPP watchdog if it is active. */
    reeParamsRegValue = CC_HAL_READ_REGISTER(
            CC_REG_OFFSET(HOST_RGF, HOST_REE_PARAMS));

    /* If the value from the REE_params_valid_bit is 0 (Zero), the watchdog
     * has expired and the operation is no longer pending. The function will
     * reload the watchdog counter by writing 1 (one) to the cpp_watchdog_reload
     * address and exist with a return value of false, indicating failure.*/
    if (BITFIELD_GET(reeParamsRegValue,
            CC_HOST_REE_PARAMS_VALID_BIT_SHIFT,
            CC_HOST_REE_PARAMS_VALID_BIT_SIZE) == 0)
    {
        CC_HAL_WRITE_REGISTER(CC_REG_OFFSET
                                        (HOST_RGF, HOST_CPP_WATCHDOG_RELOAD),
                                        CPP_WD_RELOAD_VALUE);
        return CC_CPP_EXPIRED_WATCHDOG_ERROR;
    }

    /* parse the fields of the REE_params register */
    opParams->keySlot  = BITFIELD_GET(reeParamsRegValue,
            CC_HOST_REE_PARAMS_KEY_SLOT_SEL_BIT_SHIFT,
            CC_HOST_REE_PARAMS_KEY_SLOT_SEL_BIT_SIZE);

    opParams->mode     = BITFIELD_GET(reeParamsRegValue,
            CC_HOST_REE_PARAMS_MODE_BIT_SHIFT,
            CC_HOST_REE_PARAMS_MODE_BIT_SIZE);

    opParams->direction = BITFIELD_GET(reeParamsRegValue,
            CC_HOST_REE_PARAMS_DIRECTION_BIT_SHIFT,
            CC_HOST_REE_PARAMS_DIRECTION_BIT_SIZE);

    opParams->engine   = BITFIELD_GET(reeParamsRegValue,
            CC_HOST_REE_PARAMS_TARGET_ENGINE_BIT_SHIFT,
            CC_HOST_REE_PARAMS_TARGET_ENGINE_BIT_SIZE);

    opParams->keySize  = BITFIELD_GET(reeParamsRegValue,
            CC_HOST_REE_PARAMS_KEY_SIZE_BIT_SHIFT,
            CC_HOST_REE_PARAMS_KEY_SIZE_BIT_SIZE);

    opParams->dataSize = CC_HAL_READ_REGISTER(
            CC_REG_OFFSET(HOST_RGF, HOST_REE_DATA_SIZE));

    /* If the operation mode is CTR, the REE_CTR register should be read
     * into the iv_data field of the CPP operation parameter struct.
     */
    if (opParams->mode == CC_CPP_CTR_MODE)
    {
#ifdef CC_SUPPORT_FULL_PROJECT
        /* only full version has AES engine (slim version doesn't) */
        if (opParams->engine == CC_CPP_AES_ENGINE)
        {
            ivRegOffset = CC_REG_OFFSET(HOST_RGF, CPP_AES_CTR_0_0);
        }
#endif
        if (opParams->engine == CC_CPP_SM4_ENGINE)
        {
            ivRegOffset = CC_REG_OFFSET(HOST_RGF, CPP_SM4_CTR_0_0);
        }
    }
    if (opParams->mode == CC_CPP_CBC_MODE)
    {
#ifdef CC_SUPPORT_FULL_PROJECT
        /* only full version has AES engine (slim version doesn't) */
        if (opParams->engine == CC_CPP_AES_ENGINE)
        {
            ivRegOffset = CC_REG_OFFSET(HOST_RGF, CPP_AES_IV_0_0);
        }
#endif
        if (opParams->engine == CC_CPP_SM4_ENGINE)
        {
            ivRegOffset = CC_REG_OFFSET(HOST_RGF, CPP_SM4_IV_0_0);
        }

    }
    /* if the operation is on a none supported algorithm (i.e. AES on a
     * Eris 703 system), the operation will be rejected by writing to the
     * abort_ree_ks_operation register and a return value of false should be
     * returned.
     */
    if (ivRegOffset == 0)
    {
        return CC_CPP_NOT_SUPPORTED_OP_ERROR;

    }else{
        for (i = 0; i < CC_128_BIT_KEY_SIZE_IN_WORDS; i++)
        {
            opParams->ivData.iv_data[i] =
                    CC_HAL_READ_REGISTER(ivRegOffset + i*4);
        }
    }

    return CC_OK;
}


/*!
@brief This function is called from ISR function to handle CPP event.
       It call to external function ("policy") if it was registered by
       CC_CppRegisterEventRoutine

@return void
*/
void CC_CppEventHandler(void)
{
    if (pCppEventFunc != NULL)
        pCppEventFunc(NULL);

    return;
}

void CC_CppRegisterEventRoutine (CCCppEventFunction pFunc)
{
    pCppEventFunc = pFunc;
}

