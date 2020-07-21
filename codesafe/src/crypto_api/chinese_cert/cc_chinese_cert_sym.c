/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include "cc_chinese_cert.h"
#include "cc_chinese_cert_defs.h"
#include "cc_chinese_cert_sym_data.h"
#include "cc_pal_types.h"
#include "cc_pal_mem.h"
#include "cc_sm4.h"
#include "cc_sm4_defs.h"
#include "cc_sm3.h"
#include "cc_sm3_defs.h"

/*********************** Definitions ***********************/

#define CH_CERT_PUT_SYM_MAX_TEST_DATA_SIZE      64

/************************* Structs *************************/

typedef struct _ChCertSm4Data {
    CCSm4OperationMode_t  oprMode;
    CCSm4EncryptMode_t    encMode;
    CCSm4Key_t            key;
    CCSm4Iv_t             iv;
    uint8_t               dataIn[CH_CERT_PUT_SYM_MAX_TEST_DATA_SIZE];
    uint8_t               dataOut[CH_CERT_PUT_SYM_MAX_TEST_DATA_SIZE];
    size_t                dataInSize;
    size_t                dataOutSize;
    CCChCertError_t       error;
} ChCertSm4Data;

typedef struct _ChCertSm3Data {
    uint8_t         dataIn[CH_CERT_PUT_SYM_MAX_TEST_DATA_SIZE];
    uint32_t        dataInSize;
    uint8_t         Sm3ResultBuff[CC_SM3_RESULT_SIZE_IN_BYTES];
    CCChCertError_t error;
} ChCertSm3Data;


/*** Test data tables ***/
/*********************** SM4 ***********************/
static const ChCertSm4Data ChCertSm4DataTable[] = {
/* 0 A.1.1*/   { CC_SM4_MODE_ECB, CC_SM4_ENCRYPT, CH_CERT_SM4_128_KEY1, CH_CERT_SM4_128_DUMMY_IV, CH_CERT_SM4_PLAIN1, CH_CERT_SM4_CIPHER1,  CH_CERT_SM4_IN_OUT_SIZE_16, CH_CERT_SM4_IN_OUT_SIZE_16, CC_TEE_CH_CERT_ERROR_SM4_ECB_PUT },
/* 1 A.1.2*/   { CC_SM4_MODE_ECB, CC_SM4_DECRYPT, CH_CERT_SM4_128_KEY1, CH_CERT_SM4_128_DUMMY_IV, CH_CERT_SM4_PLAIN2, CH_CERT_SM4_CIPHER2,  CH_CERT_SM4_IN_OUT_SIZE_16, CH_CERT_SM4_IN_OUT_SIZE_16, CC_TEE_CH_CERT_ERROR_SM4_ECB_PUT },
/* 2 A.1.4*/   { CC_SM4_MODE_ECB, CC_SM4_ENCRYPT, CH_CERT_SM4_128_KEY2, CH_CERT_SM4_128_DUMMY_IV, CH_CERT_SM4_PLAIN3, CH_CERT_SM4_CIPHER3,  CH_CERT_SM4_IN_OUT_SIZE_16, CH_CERT_SM4_IN_OUT_SIZE_16, CC_TEE_CH_CERT_ERROR_SM4_ECB_PUT },
/* 3 A.1.5*/   { CC_SM4_MODE_ECB, CC_SM4_DECRYPT, CH_CERT_SM4_128_KEY2, CH_CERT_SM4_128_DUMMY_IV, CH_CERT_SM4_PLAIN4, CH_CERT_SM4_CIPHER4,  CH_CERT_SM4_IN_OUT_SIZE_16, CH_CERT_SM4_IN_OUT_SIZE_16, CC_TEE_CH_CERT_ERROR_SM4_ECB_PUT },
/* 4 A.2.1.1*/ { CC_SM4_MODE_ECB, CC_SM4_ENCRYPT, CH_CERT_SM4_128_KEY1, CH_CERT_SM4_128_DUMMY_IV, CH_CERT_SM4_PLAIN5, CH_CERT_SM4_CIPHER5,  CH_CERT_SM4_IN_OUT_SIZE_32, CH_CERT_SM4_IN_OUT_SIZE_32, CC_TEE_CH_CERT_ERROR_SM4_ECB_PUT },
/* 5 A.2.1.2*/ { CC_SM4_MODE_ECB, CC_SM4_ENCRYPT, CH_CERT_SM4_128_KEY2, CH_CERT_SM4_128_DUMMY_IV, CH_CERT_SM4_PLAIN5, CH_CERT_SM4_CIPHER6,  CH_CERT_SM4_IN_OUT_SIZE_32, CH_CERT_SM4_IN_OUT_SIZE_32, CC_TEE_CH_CERT_ERROR_SM4_ECB_PUT },
/* 6 A.2.2.1*/ { CC_SM4_MODE_CBC, CC_SM4_ENCRYPT, CH_CERT_SM4_128_KEY1, CH_CERT_SM4_128_ASC_IV,   CH_CERT_SM4_PLAIN5, CH_CERT_SM4_CIPHER7,  CH_CERT_SM4_IN_OUT_SIZE_32, CH_CERT_SM4_IN_OUT_SIZE_32, CC_TEE_CH_CERT_ERROR_SM4_ECB_PUT },
/* 7 A.2.2.2*/ { CC_SM4_MODE_CBC, CC_SM4_ENCRYPT, CH_CERT_SM4_128_KEY2, CH_CERT_SM4_128_ASC_IV,   CH_CERT_SM4_PLAIN5, CH_CERT_SM4_CIPHER8,  CH_CERT_SM4_IN_OUT_SIZE_32, CH_CERT_SM4_IN_OUT_SIZE_32, CC_TEE_CH_CERT_ERROR_SM4_ECB_PUT },
/* 8 A.2.5.1*/ { CC_SM4_MODE_CTR, CC_SM4_ENCRYPT, CH_CERT_SM4_128_KEY1, CH_CERT_SM4_128_ASC_IV,   CH_CERT_SM4_PLAIN9, CH_CERT_SM4_CIPHER9,  CH_CERT_SM4_IN_OUT_SIZE_64, CH_CERT_SM4_IN_OUT_SIZE_64, CC_TEE_CH_CERT_ERROR_SM4_ECB_PUT },
/* 9 A.2.5.2*/ { CC_SM4_MODE_CTR, CC_SM4_ENCRYPT, CH_CERT_SM4_128_KEY2, CH_CERT_SM4_128_ASC_IV,   CH_CERT_SM4_PLAIN9, CH_CERT_SM4_CIPHER10, CH_CERT_SM4_IN_OUT_SIZE_64, CH_CERT_SM4_IN_OUT_SIZE_64, CC_TEE_CH_CERT_ERROR_SM4_ECB_PUT },
/* 6 A.2.3.1*/ { CC_SM4_MODE_OFB, CC_SM4_ENCRYPT, CH_CERT_SM4_128_KEY1, CH_CERT_SM4_128_ASC_IV,   CH_CERT_SM4_PLAIN5, CH_CERT_SM4_CIPHER11,  CH_CERT_SM4_IN_OUT_SIZE_32, CH_CERT_SM4_IN_OUT_SIZE_32, CC_TEE_CH_CERT_ERROR_SM4_ECB_PUT },
/* 7 A.2.3.2*/ { CC_SM4_MODE_OFB, CC_SM4_ENCRYPT, CH_CERT_SM4_128_KEY2, CH_CERT_SM4_128_ASC_IV,   CH_CERT_SM4_PLAIN5, CH_CERT_SM4_CIPHER12,  CH_CERT_SM4_IN_OUT_SIZE_32, CH_CERT_SM4_IN_OUT_SIZE_32, CC_TEE_CH_CERT_ERROR_SM4_ECB_PUT },
};
#define CH_CERT_SM4_NUM_OF_TESTS        (sizeof(ChCertSm4DataTable) / sizeof(ChCertSm4Data))

/*********************** SM3 ***********************/
static const ChCertSm3Data ChCertSm3DataTable[] = {
    { CH_CERT_SM3_INPUT1, CH_CERT_SM3_INPUT1_SIZE, CH_CERT_SM3_OUTPUT1, CC_TEE_CH_CERT_ERROR_SM3_PUT },
    { CH_CERT_SM3_INPUT2, CH_CERT_SM3_INPUT2_SIZE, CH_CERT_SM3_OUTPUT2, CC_TEE_CH_CERT_ERROR_SM3_PUT },

};
#define CH_CERT_SM3_NUM_OF_TESTS        (sizeof(ChCertSm3DataTable) / sizeof(ChCertSm3Data))


/*********************** SM4 ***********************/
CCChCertError_t CC_ChCertSm4RunTests(void)
{
    CCError_t error = CC_OK;
    ChCertSm4Data *sm4Data = NULL;
    uint32_t i;
    uint8_t dataOutActual[CH_CERT_PUT_SYM_MAX_TEST_DATA_SIZE];

    for (i = 0; i < CH_CERT_SM4_NUM_OF_TESTS; ++i) {
        sm4Data = (ChCertSm4Data*)&ChCertSm4DataTable[i];
        error = CC_Sm4(sm4Data->iv, sm4Data->key, sm4Data->encMode, sm4Data->oprMode, sm4Data->dataIn, sm4Data->dataInSize, dataOutActual);
        if (error != CC_OK) {
            return sm4Data->error;
        }
        if (CC_PalMemCmp(dataOutActual, sm4Data->dataOut, sm4Data->dataOutSize) != 0) {
            return sm4Data->error;
        }
    }

    ChCertSetTrace(CC_CH_CERT_TRACE_SM4_PUT);

    return CC_TEE_CH_CERT_ERROR_OK;
}

/*********************** SM3 ***********************/
CCChCertError_t CC_ChCertSm3RunTests(void)
{
    CCError_t error = CC_OK;
    ChCertSm3Data* sm3Data = NULL;
    uint32_t i;
    CCSm3ResultBuf_t sm3ResultBuffActual;

    for (i = 0; i < CH_CERT_SM3_NUM_OF_TESTS; ++i) {
        sm3Data = (ChCertSm3Data*)&ChCertSm3DataTable[i];
        error = CC_Sm3(sm3Data->dataIn, sm3Data->dataInSize, sm3ResultBuffActual);
        if (error != CC_OK) {
            return sm3Data->error;
        }
        if (CC_PalMemCmp(sm3ResultBuffActual, sm3Data->Sm3ResultBuff, CC_SM3_RESULT_SIZE_IN_BYTES) != 0) {
            return sm3Data->error;
        }
    }

    ChCertSetTrace(CC_CH_CERT_TRACE_SM3_PUT);

    return CC_TEE_CH_CERT_ERROR_OK;
}
