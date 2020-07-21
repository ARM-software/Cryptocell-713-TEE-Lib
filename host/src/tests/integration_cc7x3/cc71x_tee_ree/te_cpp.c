/****************************************************************************
* The confidential and proprietary information contained in this file may   *
* only be used by a person authorised under and to the extent permitted     *
* by a subsisting licensing agreement from Arm Limited (or its affiliates). *
*     (C) COPYRIGHT [2018-2020] Arm Limited (or its affiliates).                 *
*         ALL RIGHTS RESERVED                                               *
* This entire notice must be reproduced on all copies of this file          *
* and copies of this file may only be made by a person if such person is    *
* permitted to do so under the terms of a subsisting license agreement      *
* from Arm Limited (or its affiliates).                                     *
*****************************************************************************/

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include "test_engine.h"
#include "cc_cpp.h"
#include "test_proj.h"
#include "cc_regs.h"
#include "kcapi.h"
#include "test_pal_thread.h"
#include "test_pal_time.h"
#include <errno.h>

/******************************************************************
 * Defines
 ******************************************************************/
#define MAX_BUF_SIZE    (5 * 4096)
#define MAX_KEY_SIZE    32
#define MAX_ALG_NAME    16
#define CPP_SLOT_OFFSET 0x10

/******************************************************************
 * Types
 ******************************************************************/
struct cc_hkey_info {
    uint16_t keylen;
    uint8_t hw_key1;
    uint8_t hw_key2;
} __packed;

struct ctr_iv {
    uint64_t nonce;
    uint64_t ctr;
};

enum cipher_op {
    CIPHER_OP_DEC,
    CIPHER_OP_ENC
};

typedef struct teCppVector_t {
    uint8_t slot;
    const char *cipher;
    const char *mode;
    uint32_t key_size;
    enum cipher_op op;
    uint32_t data_size;
    uint64_t ctr;
    int32_t expected;
} teCppVector_t;

/******************************************************************
 * Externs
 ******************************************************************/

/******************************************************************
 * Globals
 ******************************************************************/
static unsigned char in_buf[MAX_BUF_SIZE];
static unsigned char out_buf[MAX_BUF_SIZE];
static unsigned char real_key[MAX_KEY_SIZE];

static teCppVector_t cpp_vector[] = {
    {
        .slot = 1,
        .cipher = "sm4",
        .mode = "ctr",
        .key_size = 16,
        .op = CIPHER_OP_DEC,
        .data_size = 256,
        .ctr = 0x42,
        .expected = 0
    },
#ifdef CC_SUPPORT_FULL_PROJECT
    {
        .slot = 0,
        .cipher = "aes",
        .mode = "ctr",
        .key_size = 32,
        .op = CIPHER_OP_DEC,
        .data_size = 256,
        .ctr = 0x42,
        .expected = 0
    },
#endif
    {
        .slot = 1,
        .cipher = "sm4",
        .mode = "ctr",
        .key_size = 16,
        .op = CIPHER_OP_ENC,
        .data_size = 256,
        .ctr = 0x42,
        .expected = -1
    },
    {
        .slot = 1,
        .cipher = "sm4",
        .mode = "cbc",
        .key_size = 16,
        .op = CIPHER_OP_DEC,
        .data_size = 256,
        .ctr = 0x42,
        .expected = -1
    },
    {
        .slot = 2,
        .cipher = "sm4",
        .mode = "ctr",
        .key_size = 16,
        .op = CIPHER_OP_DEC,
        .data_size = 256,
        .ctr = 0x42,
        .expected = -1
    },
    {
        .slot = 0,
        .cipher = "sm4",
        .mode = "ctr",
        .key_size = 16,
        .op = CIPHER_OP_DEC,
        .data_size = 256,
        .ctr = 0x42,
        .expected = -1
    },
    {
        .slot = 1,
        .cipher = "sm4",
        .mode = "ctr",
        .key_size = 16,
        .op = CIPHER_OP_DEC,
        .data_size = 0x2000,
        .ctr = 0x42,
        .expected = -1
    },
    {
        .slot = 1,
        .cipher = "sm4",
        .mode = "ctr",
        .key_size = 16,
        .op = CIPHER_OP_DEC,
        .data_size = 256,
        .ctr = 0xBAD,
        .expected = -1
    },
};


/******************************************************************
 * Static Prototypes
 ******************************************************************/
static TE_rc_t cpp_prepare(void *pContext);
static TE_rc_t cpp_execute(void *pContext);
static TE_rc_t cpp_verify(void *pContext);
static TE_rc_t cpp_clean(void *pContext);

/******************************************************************
 * Static functions
 ******************************************************************/

/* cppPolicyExample - example function to TEE CPP handler function.
 * The function called when TEE received CPP interrupt
 * The function checks the validity of the operation. In case of approval,
 * the function set the Stream ID and CPP key into the shadow registers.
 */
static void cppPolicyExample(void* params)
{
    CCError_t rc = 0;
    CCCppOpParams_t opParams;
    CCCppBufInfo_t bufIn = {0};
    CCCppBufInfo_t bufOut = {0};

    uint8_t key[CC_256_BIT_KEY_SIZE_IN_BYTES] = {
            0xFF ,0xFF ,0xFF ,0xFF ,0xFF ,0xFF ,0xFF ,0xFF ,
            0xFF ,0xFF ,0xFF ,0xFF ,0xFF ,0xFF ,0xFF ,0xFF ,
            0xFF ,0xFF ,0xFF ,0xFF ,0xFF ,0xFF ,0xFF ,0xFF ,
            0xFF ,0xFF ,0xFF ,0xFF ,0xFF ,0xFF ,0xFF ,0xFF ,
    };

    TE_UNUSED(params);

    rc =  CC_CppRecvOp(&opParams);
    if (rc != 0)
    {
        goto returnWithReject;
    }

    rc = CC_CppBufInfoGet(&bufIn, &bufOut);
    if (rc != 0)
    {
        goto returnWithReject;
    }

    // check policy
    // key slot 0 | AES | CTR | 256 bit | Decrypt | <  4KB | Nonce 0x42
    // key slot 1 | SM4 | CTR | 128 bit | Decrypt | <  4KB | Nonce 0x42
    //
    if (opParams.keySlot == 0)
    {
        if ((opParams.engine        == CC_CPP_AES_ENGINE)        &&
            (opParams.mode          == CC_CPP_CTR_MODE   )       &&
            (opParams.keySize       == CC_CPP_KEY_SIZE_256)      &&
            (opParams.direction     == CC_CPP_DECRYPT_OP)        &&
            (opParams.dataSize      <= 0x1000)                   &&
            (opParams.ivData.iv_data[2] == 0x42))
        {
            goto returnWithApprove;
        }
    }

    if (opParams.keySlot == 1)
    {
        if ((opParams.engine        == CC_CPP_SM4_ENGINE)        &&
            (opParams.mode          == CC_CPP_CTR_MODE   )       &&
            (opParams.keySize       == CC_CPP_KEY_SIZE_128)      &&
            (opParams.direction     == CC_CPP_DECRYPT_OP)        &&
            (opParams.dataSize      <= 0x1000)                   &&
            (opParams.ivData.iv_data[2] == 0x42))
        {
            goto returnWithApprove;
        }
    }

returnWithReject:
    TE_LOG_INFO ("Reject transaction\n");
    CC_CppHandleOp(CC_FALSE);
    return;

returnWithApprove:
    rc = CC_CppKeySet(opParams.engine, opParams.keySize, key);
    TE_LOG_INFO ("CC_CppKeySet %d\n", rc);
    rc = CC_CppStreamIdSet(0,1);
    TE_LOG_INFO ("CC_CppStreamIdSet %d\n", rc);
    TE_LOG_INFO ("Approve transaction\n");
    CC_CppHandleOp(CC_TRUE);
    return;
}

static void* test_tee_runtime_cpp(void *params)
{
    uint32_t imrValue = 0;

    TE_UNUSED(params);
    TE_LOG_INFO("CPP Test sign of life\n");

    imrValue = TEST_READ_TEE_CC_REG(CC_REG_OFFSET(HOST_RGF, HOST_RGF_IMR));
    TE_LOG_INFO ("CC_InterruptHandler imrValue = 0x%x\n", imrValue);

    /* disable watchdog */
    CC_CppWatchdogSet (CC_FALSE, 0xFFFF0000);

    /* register TEE CPP handler */
    CC_CppRegisterEventRoutine(cppPolicyExample);

    while(1)
    {
        // wait for transaction
    }

    return NULL;
}

/*
 * The test creates two handles - one for CPP op and one for a regular op.
 * It will than run the requested CPP op from the in buffers to out buffer,
 * Than follow up by running the regular op inplace in the in buffer and
 * finishes by comparing the results.
 */
static int cpp_ree_test(uint8_t slot, const char *cipher,
            const char *mode, uint32_t key_size, enum cipher_op op,
            uint32_t data_size, uint64_t ctr, int32_t expected)
{
    int32_t ret;
    struct kcapi_handle *handle;
    struct cc_hkey_info key = { .hw_key2 = 0xFFUL };
    struct ctr_iv iv = { .nonce = 0x42UL };
    char alg[MAX_ALG_NAME];
    const char *op_name = (op == CIPHER_OP_DEC ? "Decrypt" : "Encrypt");

    memset(in_buf, 0x42UL, data_size);
    memset(out_buf, 0x0UL, data_size);
    memset(real_key, 0xFFUL, key_size);

    iv.ctr = ctr;

    /*
     * We create the protected key token:
     * Set the real key size (the one which the TEE feeds the HW)
     * Set the slot by adding the CPP slot offset to the slot number requested
     */
    key.keylen = key_size;
    key.hw_key1 = slot + CPP_SLOT_OFFSET;

    snprintf(alg, MAX_ALG_NAME, "%s(p%s)", mode, cipher);

    TE_LOG_INFO("Running test: slot: %d, alg: %s, key size %d, op: %s, data size: %d, counter: %ju, expected: %d... ",
            slot, alg, key_size, op_name, data_size, ctr,
        expected);
    fflush(NULL);

    ret = kcapi_cipher_init(&handle, alg, 0);
    if (ret)
        goto out_no_cipher;
    ret = kcapi_cipher_setkey(handle, (unsigned char *)&key, sizeof(key));
    if (ret)
        goto out;
   if (op == CIPHER_OP_DEC) {
        ret = kcapi_cipher_decrypt(handle, in_buf, data_size,
                       (uint8_t *)&iv, out_buf, data_size,
                       KCAPI_ACCESS_HEURISTIC);
    } else {
        ret = kcapi_cipher_encrypt(handle, in_buf, data_size,
                       (uint8_t *)&iv, out_buf, data_size,
                       KCAPI_ACCESS_HEURISTIC);
    }

    if (ret < 0)
        goto out;

    kcapi_cipher_destroy(handle);

    snprintf(alg, MAX_ALG_NAME, "%s(%s)", mode, cipher);

    iv.ctr = ctr;

    ret = kcapi_cipher_init(&handle, alg, 0);
    if (ret)
        goto out_no_cipher;

    ret = kcapi_cipher_setkey(handle, real_key, key_size);
    if (ret)
        goto out;

    if (op == CIPHER_OP_DEC) {
        ret = kcapi_cipher_decrypt(handle, in_buf, data_size,
                       (uint8_t *)&iv, in_buf, data_size,
                       KCAPI_ACCESS_HEURISTIC);
    } else {
        ret = kcapi_cipher_encrypt(handle, in_buf, data_size,
                       (uint8_t *)&iv, in_buf, data_size,
                       KCAPI_ACCESS_HEURISTIC);
    }

    if (ret < 0)
        goto out;

    ret = memcmp(&in_buf, &out_buf, data_size);
    if(ret)
        ret = -EINVAL;

out:
    kcapi_cipher_destroy(handle);

out_no_cipher:
    if (ret != expected) {
        TE_LOG_ERROR("FAILED! Got %d, expected %d.\n\n", ret, expected);
        return 1;
    } else {
        TE_LOG_INFO("SUCCESS!\n\n");
        return 0;
    }
}

static TE_rc_t cpp_prepare(void *pContext)
{
    TE_rc_t res = TE_RC_SUCCESS;
    TE_UNUSED(pContext);

    goto bail;
bail:
    return res;
}

static TE_rc_t cpp_execute(void *pContext)
{
    TE_rc_t res = TE_RC_SUCCESS;
    TE_perfIndex_t cookie;
    TE_UNUSED(pContext);
    ThreadHandle threadHandle = NULL;
    const char* THREAD_TASK_NAME = "cpp_tee_execute";
    teCppVector_t *cppParams = (teCppVector_t *)pContext;

    /* create TEE thread */
    threadHandle = Test_PalThreadCreate(Test_PalGetMinimalStackSize(),
                                        test_tee_runtime_cpp,
                                        Test_PalGetDefaultPriority(),
                                        NULL,
                                        (char*)THREAD_TASK_NAME,
                                        sizeof(THREAD_TASK_NAME),
                                        true);
    /* wait to enable test_tee_runtime_cpp to run */
    Test_PalDelay(1000000);

    cookie = TE_perfOpenNewEntry("cpp", "cpp test");
    /* run REE test */
    res = cpp_ree_test(cppParams->slot, cppParams->cipher, cppParams->mode,
            cppParams->key_size, cppParams->op, cppParams->data_size,
            cppParams->ctr, cppParams->expected);

    TE_perfCloseEntry(cookie);

    /* Finalize task's resources */
    Test_PalThreadDestroy(threadHandle);


    goto bail;

bail:
    return res;
}

static TE_rc_t cpp_verify(void *pContext)
{
    TE_rc_t res = TE_RC_SUCCESS;
    TE_UNUSED(pContext);
    goto bail;
bail:
    return res;
}

static TE_rc_t cpp_clean(void *pContext)
{
    TE_rc_t res = TE_RC_SUCCESS;
    TE_UNUSED(pContext);

    goto bail;
bail:
    return res;
}

/******************************************************************
 * Public
 ******************************************************************/
int TE_init_cpp_test(void)
{
    uint32_t test_counter = 0;

    TE_rc_t res = TE_RC_SUCCESS;

    TE_perfEntryInit("cpp", "cpp test");

    TE_ASSERT(TE_registerFlow("cpp",
                               "sm4",
                               "success",
                               cpp_prepare,
                               cpp_execute,
                               cpp_verify,
                               cpp_clean,
                               &cpp_vector[test_counter++]) == TE_RC_SUCCESS);

#ifdef CC_SUPPORT_FULL_PROJECT
    TE_ASSERT(TE_registerFlow("cpp",
                               "aes",
                               "success",
                               cpp_prepare,
                               cpp_execute,
                               cpp_verify,
                               cpp_clean,
                               &cpp_vector[test_counter++]) == TE_RC_SUCCESS);
#endif
    TE_ASSERT(TE_registerFlow("cpp",
                               "sm4",
                               "bad case - enc operation",
                               cpp_prepare,
                               cpp_execute,
                               cpp_verify,
                               cpp_clean,
                               &cpp_vector[test_counter++]) == TE_RC_SUCCESS);

    TE_ASSERT(TE_registerFlow("cpp",
                               "sm4",
                               "bad case - cbc mode",
                               cpp_prepare,
                               cpp_execute,
                               cpp_verify,
                               cpp_clean,
                               &cpp_vector[test_counter++]) == TE_RC_SUCCESS);

    TE_ASSERT(TE_registerFlow("cpp",
                               "sm4",
                               "bad case - slot",
                               cpp_prepare,
                               cpp_execute,
                               cpp_verify,
                               cpp_clean,
                               &cpp_vector[test_counter++]) == TE_RC_SUCCESS);

    TE_ASSERT(TE_registerFlow("cpp",
                               "sm4",
                               "bad case - slot alg",
                               cpp_prepare,
                               cpp_execute,
                               cpp_verify,
                               cpp_clean,
                               &cpp_vector[test_counter++]) == TE_RC_SUCCESS);

    TE_ASSERT(TE_registerFlow("cpp",
                               "sm4",
                               "bad case - data size",
                               cpp_prepare,
                               cpp_execute,
                               cpp_verify,
                               cpp_clean,
                               &cpp_vector[test_counter++]) == TE_RC_SUCCESS);

    TE_ASSERT(TE_registerFlow("cpp",
                               "sm4",
                               "bad case - nonce",
                               cpp_prepare,
                               cpp_execute,
                               cpp_verify,
                               cpp_clean,
                               &cpp_vector[test_counter++]) == TE_RC_SUCCESS);
    goto bail;

bail:
	return res;
}

