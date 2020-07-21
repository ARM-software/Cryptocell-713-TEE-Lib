/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include "cc_pal_types.h"
#include "cc_pal_mem.h"
#include "cc_aes.h"
#include "cc_aes_defs.h"
#include "cc_aesccm.h"
#include "cc_aesgcm.h"
#include "cc_des.h"
#include "cc_hash_defs.h"
#include "cc_hmac.h"
#include "cc_fips_defs.h"
#include "cc_fips_sym_data.h"

#define FIPS_SYM_PUT_MAX_TEST_DATA_SIZE         32
#define FIPS_SYM_PUT_MAX_TEST_GCM_DATA_SIZE     64
#define FIPS_SYM_PUT_MAX_HMAC_TEST_DATA_SIZE    128
#define FIPS_SYM_COND_MAX_BLOCK_SIZE            0x100000

typedef struct _FipsAesData {
        CCAesKeyBuffer_t      key;
        uint32_t              keySize;
        CCAesIv_t             iv;
        CCAesEncryptMode_t    encMode;
        CCAesOperationMode_t  oprMode;
        uint8_t               dataIn[FIPS_SYM_PUT_MAX_TEST_DATA_SIZE];
        uint8_t               dataOut[FIPS_SYM_PUT_MAX_TEST_DATA_SIZE];
        size_t                dataInSize;
        size_t                dataOutSize;
        CCFipsError_t         error;
} FipsAesData;

typedef struct _FipsAesCcmData {
        CCAesCcmKey_t           key;
        uint32_t                keySize;
        uint8_t                 nonce[FIPS_SYM_PUT_MAX_TEST_DATA_SIZE];
        uint8_t                 nonceSize;
        CCAesEncryptMode_t      encMode;
        uint8_t                 AData[FIPS_SYM_PUT_MAX_TEST_DATA_SIZE];
        size_t                  ADataSize;
        uint8_t                 textData[FIPS_SYM_PUT_MAX_TEST_DATA_SIZE];
        size_t                  textDataSize;
        uint8_t                 textDataOut[FIPS_SYM_PUT_MAX_TEST_DATA_SIZE];
        uint8_t                 tagSize;
        CCAesCcmMacRes_t        macResOut;
        CCFipsError_t           error;
} FipsAesCcmData;

typedef struct _FipsAesGcmData {
        CCAesGcmKey_t           key;
        uint32_t                keySize;
        uint8_t                 iv[FIPS_SYM_PUT_MAX_TEST_DATA_SIZE];
        uint8_t                 ivSize;
        CCAesEncryptMode_t      encMode;
        uint8_t                 AData[FIPS_SYM_PUT_MAX_TEST_DATA_SIZE];
        size_t                  ADataSize;
        uint8_t                 textData[FIPS_SYM_PUT_MAX_TEST_GCM_DATA_SIZE];
        size_t                  textDataSize;
        uint8_t                 textDataOut[FIPS_SYM_PUT_MAX_TEST_GCM_DATA_SIZE];
        uint8_t                 tagSize;
        CCAesGcmTagRes_t        macResOut;
        CCFipsError_t           error;
} FipsAesGcmData;

typedef struct _FipsDesData {
        CCDesKey_t                  key;
        CCDesNumOfKeys_t            numOfKeys;
        CCDesIv_t                   iv;
        CCDesEncryptMode_t          encMode;
        CCDesOperationMode_t        oprMode;
        uint8_t                         dataIn[FIPS_SYM_PUT_MAX_TEST_DATA_SIZE];
        uint8_t                         dataOut[FIPS_SYM_PUT_MAX_TEST_DATA_SIZE];
        uint32_t                        dataInSize;
        CCFipsError_t                  error;
} FipsDesData;

typedef struct _FipsHashData {
        CCHashOperationMode_t       oprMode;
        uint8_t                         dataIn[FIPS_SYM_PUT_MAX_TEST_DATA_SIZE];
        uint32_t                        dataInSize;
        uint8_t                         HashResultBuff[CC_HASH_SHA512_DIGEST_SIZE_IN_BYTES];  /* maximum required size */
        uint32_t                        HmacResultSize;
        CCFipsError_t                  error;
} FipsHashData;

typedef struct _FipsHmacData {
        CCHashOperationMode_t       oprMode;
        uint8_t                         key[CC_HMAC_KEY_SIZE_IN_BYTES];       /* maximum required size */
        uint32_t                        keySize;
        uint8_t                         dataIn[FIPS_SYM_PUT_MAX_HMAC_TEST_DATA_SIZE];
        uint32_t                        dataInSize;
        uint8_t                         HmacResultBuff[CC_HASH_SHA512_DIGEST_SIZE_IN_BYTES];  /* maximum required size */
        uint32_t                        HmacResultSize;
        CCFipsError_t                  error;
} FipsHmacData;

/* test data tables */
static const FipsAesData FipsAesDataTable[] = {
        { NIST_AES_128_KEY, AES_128_BIT_KEY_SIZE, NIST_AES_DUMMY_IV, CC_AES_ENCRYPT, CC_AES_MODE_ECB, NIST_AES_PLAIN_DATA, NIST_AES_128_ECB_CIPHER, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE, CC_TEE_FIPS_ERROR_AES_ECB_PUT },
        { NIST_AES_128_KEY, AES_128_BIT_KEY_SIZE, NIST_AES_DUMMY_IV, CC_AES_DECRYPT, CC_AES_MODE_ECB, NIST_AES_128_ECB_CIPHER, NIST_AES_PLAIN_DATA, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE, CC_TEE_FIPS_ERROR_AES_ECB_PUT },
        { NIST_AES_192_KEY, AES_192_BIT_KEY_SIZE, NIST_AES_DUMMY_IV, CC_AES_ENCRYPT, CC_AES_MODE_ECB, NIST_AES_PLAIN_DATA, NIST_AES_192_ECB_CIPHER, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE, CC_TEE_FIPS_ERROR_AES_ECB_PUT },
        { NIST_AES_192_KEY, AES_192_BIT_KEY_SIZE, NIST_AES_DUMMY_IV, CC_AES_DECRYPT, CC_AES_MODE_ECB, NIST_AES_192_ECB_CIPHER, NIST_AES_PLAIN_DATA, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE, CC_TEE_FIPS_ERROR_AES_ECB_PUT },
        { NIST_AES_256_KEY, AES_256_BIT_KEY_SIZE, NIST_AES_DUMMY_IV, CC_AES_ENCRYPT, CC_AES_MODE_ECB, NIST_AES_PLAIN_DATA, NIST_AES_256_ECB_CIPHER, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE, CC_TEE_FIPS_ERROR_AES_ECB_PUT },
        { NIST_AES_256_KEY, AES_256_BIT_KEY_SIZE, NIST_AES_DUMMY_IV, CC_AES_DECRYPT, CC_AES_MODE_ECB, NIST_AES_256_ECB_CIPHER, NIST_AES_PLAIN_DATA, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE, CC_TEE_FIPS_ERROR_AES_ECB_PUT },
        { NIST_AES_128_KEY, AES_128_BIT_KEY_SIZE, NIST_AES_CBC_IV, CC_AES_ENCRYPT, CC_AES_MODE_CBC, NIST_AES_PLAIN_DATA, NIST_AES_128_CBC_CIPHER, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE, CC_TEE_FIPS_ERROR_AES_CBC_PUT },
        { NIST_AES_128_KEY, AES_128_BIT_KEY_SIZE, NIST_AES_CBC_IV, CC_AES_DECRYPT, CC_AES_MODE_CBC, NIST_AES_128_CBC_CIPHER, NIST_AES_PLAIN_DATA, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE, CC_TEE_FIPS_ERROR_AES_CBC_PUT },
        { NIST_AES_192_KEY, AES_192_BIT_KEY_SIZE, NIST_AES_CBC_IV, CC_AES_ENCRYPT, CC_AES_MODE_CBC, NIST_AES_PLAIN_DATA, NIST_AES_192_CBC_CIPHER, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE, CC_TEE_FIPS_ERROR_AES_CBC_PUT },
        { NIST_AES_192_KEY, AES_192_BIT_KEY_SIZE, NIST_AES_CBC_IV, CC_AES_DECRYPT, CC_AES_MODE_CBC, NIST_AES_192_CBC_CIPHER, NIST_AES_PLAIN_DATA, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE, CC_TEE_FIPS_ERROR_AES_CBC_PUT },
        { NIST_AES_256_KEY, AES_256_BIT_KEY_SIZE, NIST_AES_CBC_IV, CC_AES_ENCRYPT, CC_AES_MODE_CBC, NIST_AES_PLAIN_DATA, NIST_AES_256_CBC_CIPHER, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE, CC_TEE_FIPS_ERROR_AES_CBC_PUT },
        { NIST_AES_256_KEY, AES_256_BIT_KEY_SIZE, NIST_AES_CBC_IV, CC_AES_DECRYPT, CC_AES_MODE_CBC, NIST_AES_256_CBC_CIPHER, NIST_AES_PLAIN_DATA, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE, CC_TEE_FIPS_ERROR_AES_CBC_PUT },
        { NIST_AES_128_KEY, AES_128_BIT_KEY_SIZE, NIST_AES_OFB_IV, CC_AES_ENCRYPT, CC_AES_MODE_OFB, NIST_AES_PLAIN_DATA, NIST_AES_128_OFB_CIPHER, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE, CC_TEE_FIPS_ERROR_AES_OFB_PUT },
        { NIST_AES_128_KEY, AES_128_BIT_KEY_SIZE, NIST_AES_OFB_IV, CC_AES_DECRYPT, CC_AES_MODE_OFB, NIST_AES_128_OFB_CIPHER, NIST_AES_PLAIN_DATA, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE, CC_TEE_FIPS_ERROR_AES_OFB_PUT },
        { NIST_AES_192_KEY, AES_192_BIT_KEY_SIZE, NIST_AES_OFB_IV, CC_AES_ENCRYPT, CC_AES_MODE_OFB, NIST_AES_PLAIN_DATA, NIST_AES_192_OFB_CIPHER, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE, CC_TEE_FIPS_ERROR_AES_OFB_PUT },
        { NIST_AES_192_KEY, AES_192_BIT_KEY_SIZE, NIST_AES_OFB_IV, CC_AES_DECRYPT, CC_AES_MODE_OFB, NIST_AES_192_OFB_CIPHER, NIST_AES_PLAIN_DATA, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE, CC_TEE_FIPS_ERROR_AES_OFB_PUT },
        { NIST_AES_256_KEY, AES_256_BIT_KEY_SIZE, NIST_AES_OFB_IV, CC_AES_ENCRYPT, CC_AES_MODE_OFB, NIST_AES_PLAIN_DATA, NIST_AES_256_OFB_CIPHER, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE, CC_TEE_FIPS_ERROR_AES_OFB_PUT },
        { NIST_AES_256_KEY, AES_256_BIT_KEY_SIZE, NIST_AES_OFB_IV, CC_AES_DECRYPT, CC_AES_MODE_OFB, NIST_AES_256_OFB_CIPHER, NIST_AES_PLAIN_DATA, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE, CC_TEE_FIPS_ERROR_AES_OFB_PUT },
        { NIST_AES_128_KEY, AES_128_BIT_KEY_SIZE, NIST_AES_CTR_IV, CC_AES_ENCRYPT, CC_AES_MODE_CTR, NIST_AES_PLAIN_DATA, NIST_AES_128_CTR_CIPHER, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE, CC_TEE_FIPS_ERROR_AES_CTR_PUT },
        { NIST_AES_128_KEY, AES_128_BIT_KEY_SIZE, NIST_AES_CTR_IV, CC_AES_DECRYPT, CC_AES_MODE_CTR, NIST_AES_128_CTR_CIPHER, NIST_AES_PLAIN_DATA, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE, CC_TEE_FIPS_ERROR_AES_CTR_PUT },
        { NIST_AES_192_KEY, AES_192_BIT_KEY_SIZE, NIST_AES_CTR_IV, CC_AES_ENCRYPT, CC_AES_MODE_CTR, NIST_AES_PLAIN_DATA, NIST_AES_192_CTR_CIPHER, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE, CC_TEE_FIPS_ERROR_AES_CTR_PUT },
        { NIST_AES_192_KEY, AES_192_BIT_KEY_SIZE, NIST_AES_CTR_IV, CC_AES_DECRYPT, CC_AES_MODE_CTR, NIST_AES_192_CTR_CIPHER, NIST_AES_PLAIN_DATA, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE, CC_TEE_FIPS_ERROR_AES_CTR_PUT },
        { NIST_AES_256_KEY, AES_256_BIT_KEY_SIZE, NIST_AES_CTR_IV, CC_AES_ENCRYPT, CC_AES_MODE_CTR, NIST_AES_PLAIN_DATA, NIST_AES_256_CTR_CIPHER, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE, CC_TEE_FIPS_ERROR_AES_CTR_PUT },
        { NIST_AES_256_KEY, AES_256_BIT_KEY_SIZE, NIST_AES_CTR_IV, CC_AES_DECRYPT, CC_AES_MODE_CTR, NIST_AES_256_CTR_CIPHER, NIST_AES_PLAIN_DATA, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE, CC_TEE_FIPS_ERROR_AES_CTR_PUT },
        { RFC3962_AES_128_KEY, AES_128_BIT_KEY_SIZE, NIST_AES_DUMMY_IV, CC_AES_ENCRYPT, CC_AES_MODE_CBC_CTS, RFC3962_AES_PLAIN_DATA, RFC3962_AES_128_CBC_CTS_CIPHER, RFC3962_AES_VECTOR_SIZE, RFC3962_AES_VECTOR_SIZE, CC_TEE_FIPS_ERROR_AES_CBC_CTS_PUT },
        { RFC3962_AES_128_KEY, AES_128_BIT_KEY_SIZE, NIST_AES_DUMMY_IV, CC_AES_DECRYPT, CC_AES_MODE_CBC_CTS, RFC3962_AES_128_CBC_CTS_CIPHER, RFC3962_AES_PLAIN_DATA, RFC3962_AES_VECTOR_SIZE, RFC3962_AES_VECTOR_SIZE, CC_TEE_FIPS_ERROR_AES_CBC_CTS_PUT },
        { NIST_AES_128_CBC_MAC_KEY, AES_128_BIT_KEY_SIZE, NIST_AES_CBC_MAC_IV, CC_AES_ENCRYPT, CC_AES_MODE_CBC_MAC, NIST_AES_128_CBC_MAC_ONE_BLOCK_PLAIN_DATA, NIST_AES_128_CBC_MAC_ONE_BLOCK_OUTPUT, NIST_AES_128_CBC_MAC_ONE_BLOCK_VECTOR_SIZE, NIST_AES_128_CBC_MAC_OUTPUT_SIZE, CC_TEE_FIPS_ERROR_AES_CBC_MAC_PUT },
        { NIST_AES_128_CBC_MAC_KEY, AES_128_BIT_KEY_SIZE, NIST_AES_CBC_MAC_IV, CC_AES_ENCRYPT, CC_AES_MODE_CBC_MAC, NIST_AES_128_CBC_MAC_TWO_BLOCKS_PLAIN_DATA, NIST_AES_128_CBC_MAC_TWO_BLOCKS_OUTPUT, NIST_AES_128_CBC_MAC_TWO_BLOCKS_VECTOR_SIZE, NIST_AES_128_CBC_MAC_OUTPUT_SIZE, CC_TEE_FIPS_ERROR_AES_CBC_MAC_PUT },
        { NIST_AES_256_KEY, AES_256_BIT_KEY_SIZE, NIST_AES_CBC_IV, CC_AES_ENCRYPT, CC_AES_MODE_CBC_MAC, NIST_AES_PLAIN_DATA, NIST_AES_256_CBC_CIPHER, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE, CC_TEE_FIPS_ERROR_AES_CBC_MAC_PUT },
        { NIST_AES_256_XTS_KEY, AES_256_BIT_KEY_SIZE, NIST_AES_256_XTS_IV, CC_AES_ENCRYPT, CC_AES_MODE_XTS, NIST_AES_256_XTS_PLAIN, NIST_AES_256_XTS_CIPHER, NIST_AES_256_XTS_VECTOR_SIZE, NIST_AES_256_XTS_VECTOR_SIZE, CC_TEE_FIPS_ERROR_AES_XTS_PUT },
        { NIST_AES_256_XTS_KEY, AES_256_BIT_KEY_SIZE, NIST_AES_256_XTS_IV, CC_AES_DECRYPT, CC_AES_MODE_XTS, NIST_AES_256_XTS_CIPHER, NIST_AES_256_XTS_PLAIN, NIST_AES_256_XTS_VECTOR_SIZE, NIST_AES_256_XTS_VECTOR_SIZE, CC_TEE_FIPS_ERROR_AES_XTS_PUT },
        { NIST_AES_512_XTS_KEY, AES_512_BIT_KEY_SIZE, NIST_AES_512_XTS_IV, CC_AES_ENCRYPT, CC_AES_MODE_XTS, NIST_AES_512_XTS_PLAIN, NIST_AES_512_XTS_CIPHER, NIST_AES_512_XTS_VECTOR_SIZE, NIST_AES_256_XTS_VECTOR_SIZE, CC_TEE_FIPS_ERROR_AES_XTS_PUT },
        { NIST_AES_512_XTS_KEY, AES_512_BIT_KEY_SIZE, NIST_AES_512_XTS_IV, CC_AES_DECRYPT, CC_AES_MODE_XTS, NIST_AES_512_XTS_CIPHER, NIST_AES_512_XTS_PLAIN, NIST_AES_512_XTS_VECTOR_SIZE, NIST_AES_256_XTS_VECTOR_SIZE, CC_TEE_FIPS_ERROR_AES_XTS_PUT },
        { NIST_AES_128_CMAC_KEY, AES_128_BIT_KEY_SIZE, NIST_AES_DUMMY_IV, CC_AES_ENCRYPT, CC_AES_MODE_CMAC, NIST_AES_128_CMAC_PLAIN_DATA, NIST_AES_128_CMAC_MAC, NIST_AES_128_CMAC_VECTOR_SIZE, NIST_AES_128_CMAC_OUTPUT_SIZE, CC_TEE_FIPS_ERROR_AES_CMAC_PUT },
        { NIST_AES_192_CMAC_KEY, AES_192_BIT_KEY_SIZE, NIST_AES_DUMMY_IV, CC_AES_ENCRYPT, CC_AES_MODE_CMAC, NIST_AES_192_CMAC_PLAIN_DATA, NIST_AES_192_CMAC_MAC, NIST_AES_192_CMAC_VECTOR_SIZE, NIST_AES_192_CMAC_OUTPUT_SIZE, CC_TEE_FIPS_ERROR_AES_CMAC_PUT },
        { NIST_AES_256_CMAC_KEY, AES_256_BIT_KEY_SIZE, NIST_AES_DUMMY_IV, CC_AES_ENCRYPT, CC_AES_MODE_CMAC, NIST_AES_256_CMAC_PLAIN_DATA, NIST_AES_256_CMAC_MAC, NIST_AES_256_CMAC_VECTOR_SIZE, NIST_AES_256_CMAC_OUTPUT_SIZE, CC_TEE_FIPS_ERROR_AES_CMAC_PUT },
};
#define FIPS_AES_NUM_OF_TESTS        (sizeof(FipsAesDataTable) / sizeof(FipsAesData))

static const FipsAesCcmData FipsAesCcmDataTable[] = {
        { NIST_AESCCM_128_KEY, NIST_AESCCM_128_BIT_KEY_SIZE, NIST_AESCCM_128_NONCE, NIST_AESCCM_NONCE_SIZE, CC_AES_ENCRYPT, NIST_AESCCM_128_ADATA, NIST_AESCCM_ADATA_SIZE, NIST_AESCCM_128_TEXT_DATA, NIST_AESCCM_TEXT_DATA_SIZE, NIST_AESCCM_128_CIPHER, NIST_AESCCM_TAG_SIZE, NIST_AESCCM_128_MAC, CC_TEE_FIPS_ERROR_AESCCM_PUT },
        { NIST_AESCCM_128_KEY, NIST_AESCCM_128_BIT_KEY_SIZE, NIST_AESCCM_128_NONCE, NIST_AESCCM_NONCE_SIZE, CC_AES_DECRYPT, NIST_AESCCM_128_ADATA, NIST_AESCCM_ADATA_SIZE, NIST_AESCCM_128_CIPHER, NIST_AESCCM_TEXT_DATA_SIZE, NIST_AESCCM_128_TEXT_DATA, NIST_AESCCM_TAG_SIZE, NIST_AESCCM_128_MAC, CC_TEE_FIPS_ERROR_AESCCM_PUT },
        { NIST_AESCCM_192_KEY, NIST_AESCCM_192_BIT_KEY_SIZE, NIST_AESCCM_192_NONCE, NIST_AESCCM_NONCE_SIZE, CC_AES_ENCRYPT, NIST_AESCCM_192_ADATA, NIST_AESCCM_ADATA_SIZE, NIST_AESCCM_192_TEXT_DATA, NIST_AESCCM_TEXT_DATA_SIZE, NIST_AESCCM_192_CIPHER, NIST_AESCCM_TAG_SIZE, NIST_AESCCM_192_MAC, CC_TEE_FIPS_ERROR_AESCCM_PUT },
        { NIST_AESCCM_192_KEY, NIST_AESCCM_192_BIT_KEY_SIZE, NIST_AESCCM_192_NONCE, NIST_AESCCM_NONCE_SIZE, CC_AES_DECRYPT, NIST_AESCCM_192_ADATA, NIST_AESCCM_ADATA_SIZE, NIST_AESCCM_192_CIPHER, NIST_AESCCM_TEXT_DATA_SIZE, NIST_AESCCM_192_TEXT_DATA, NIST_AESCCM_TAG_SIZE, NIST_AESCCM_192_MAC, CC_TEE_FIPS_ERROR_AESCCM_PUT },
        { NIST_AESCCM_256_KEY, NIST_AESCCM_256_BIT_KEY_SIZE, NIST_AESCCM_256_NONCE, NIST_AESCCM_NONCE_SIZE, CC_AES_ENCRYPT, NIST_AESCCM_256_ADATA, NIST_AESCCM_ADATA_SIZE, NIST_AESCCM_256_TEXT_DATA, NIST_AESCCM_TEXT_DATA_SIZE, NIST_AESCCM_256_CIPHER, NIST_AESCCM_TAG_SIZE, NIST_AESCCM_256_MAC, CC_TEE_FIPS_ERROR_AESCCM_PUT },
        { NIST_AESCCM_256_KEY, NIST_AESCCM_256_BIT_KEY_SIZE, NIST_AESCCM_256_NONCE, NIST_AESCCM_NONCE_SIZE, CC_AES_DECRYPT, NIST_AESCCM_256_ADATA, NIST_AESCCM_ADATA_SIZE, NIST_AESCCM_256_CIPHER, NIST_AESCCM_TEXT_DATA_SIZE, NIST_AESCCM_256_TEXT_DATA, NIST_AESCCM_TAG_SIZE, NIST_AESCCM_256_MAC, CC_TEE_FIPS_ERROR_AESCCM_PUT },
};
#define FIPS_AESCCM_NUM_OF_TESTS        (sizeof(FipsAesCcmDataTable) / sizeof(FipsAesCcmData))

static const FipsAesGcmData FipsAesGcmDataTable[] = {
        { NIST_AESGCM_128_ZERO_DATA, NIST_AESGCM_128_BIT_KEY_SIZE, NIST_AESGCM_96_ZERO_IV, NIST_AESGCM_96_BIT_IV_SIZE, CC_AES_ENCRYPT, NIST_AESGCM_EMPTY_DATA, NIST_AESGCM_EMPTY_DATA_SIZE, NIST_AESGCM_EMPTY_DATA, NIST_AESGCM_EMPTY_DATA_SIZE, NIST_AESGCM_EMPTY_DATA, NIST_AESGCM_TAG_SIZE, NIST_AESGCM_128_MAC_1, CC_TEE_FIPS_ERROR_AESGCM_PUT },
        { NIST_AESGCM_128_ZERO_DATA, NIST_AESGCM_128_BIT_KEY_SIZE, NIST_AESGCM_96_ZERO_IV, NIST_AESGCM_96_BIT_IV_SIZE, CC_AES_DECRYPT, NIST_AESGCM_EMPTY_DATA, NIST_AESGCM_EMPTY_DATA_SIZE, NIST_AESGCM_EMPTY_DATA, NIST_AESGCM_EMPTY_DATA_SIZE, NIST_AESGCM_EMPTY_DATA, NIST_AESGCM_TAG_SIZE, NIST_AESGCM_128_MAC_1, CC_TEE_FIPS_ERROR_AESGCM_PUT },
        { NIST_AESGCM_128_ZERO_DATA, NIST_AESGCM_128_BIT_KEY_SIZE, NIST_AESGCM_96_ZERO_IV, NIST_AESGCM_96_BIT_IV_SIZE, CC_AES_ENCRYPT, NIST_AESGCM_EMPTY_DATA, NIST_AESGCM_EMPTY_DATA_SIZE, NIST_AESGCM_128_ZERO_DATA, NIST_AESGCM_128_TEXT_DATA_SIZE, NIST_AESGCM_128_CIPHER_1, NIST_AESGCM_TAG_SIZE, NIST_AESGCM_128_MAC_2, CC_TEE_FIPS_ERROR_AESGCM_PUT },
        { NIST_AESGCM_128_ZERO_DATA, NIST_AESGCM_128_BIT_KEY_SIZE, NIST_AESGCM_96_ZERO_IV, NIST_AESGCM_96_BIT_IV_SIZE, CC_AES_DECRYPT, NIST_AESGCM_EMPTY_DATA, NIST_AESGCM_EMPTY_DATA_SIZE, NIST_AESGCM_128_CIPHER_1, NIST_AESGCM_128_TEXT_DATA_SIZE, NIST_AESGCM_128_ZERO_DATA, NIST_AESGCM_TAG_SIZE, NIST_AESGCM_128_MAC_2, CC_TEE_FIPS_ERROR_AESGCM_PUT },
        { NIST_AESGCM_128_KEY, NIST_AESGCM_128_BIT_KEY_SIZE, NIST_AESGCM_96_IV, NIST_AESGCM_96_BIT_IV_SIZE, CC_AES_ENCRYPT, NIST_AESGCM_EMPTY_DATA, NIST_AESGCM_EMPTY_DATA_SIZE, NIST_AESGCM_512_TEXT_DATA, NIST_AESGCM_512_TEXT_DATA_SIZE, NIST_AESGCM_512_CIPHER_1, NIST_AESGCM_TAG_SIZE, NIST_AESGCM_128_MAC_3, CC_TEE_FIPS_ERROR_AESGCM_PUT },
        { NIST_AESGCM_128_KEY, NIST_AESGCM_128_BIT_KEY_SIZE, NIST_AESGCM_96_IV, NIST_AESGCM_96_BIT_IV_SIZE, CC_AES_DECRYPT, NIST_AESGCM_EMPTY_DATA, NIST_AESGCM_EMPTY_DATA_SIZE, NIST_AESGCM_512_CIPHER_1, NIST_AESGCM_512_TEXT_DATA_SIZE, NIST_AESGCM_512_TEXT_DATA, NIST_AESGCM_TAG_SIZE, NIST_AESGCM_128_MAC_3, CC_TEE_FIPS_ERROR_AESGCM_PUT },
        { NIST_AESGCM_128_KEY, NIST_AESGCM_128_BIT_KEY_SIZE, NIST_AESGCM_96_IV, NIST_AESGCM_96_BIT_IV_SIZE, CC_AES_ENCRYPT, NIST_AESGCM_160_ADATA, NIST_AESGCM_160_ADATA_SIZE, NIST_AESGCM_512_TEXT_DATA, NIST_AESGCM_480_TEXT_DATA_SIZE, NIST_AESGCM_512_CIPHER_1, NIST_AESGCM_TAG_SIZE, NIST_AESGCM_128_MAC_4, CC_TEE_FIPS_ERROR_AESGCM_PUT },
        { NIST_AESGCM_128_KEY, NIST_AESGCM_128_BIT_KEY_SIZE, NIST_AESGCM_96_IV, NIST_AESGCM_96_BIT_IV_SIZE, CC_AES_DECRYPT, NIST_AESGCM_160_ADATA, NIST_AESGCM_160_ADATA_SIZE, NIST_AESGCM_512_CIPHER_1, NIST_AESGCM_480_TEXT_DATA_SIZE, NIST_AESGCM_512_TEXT_DATA, NIST_AESGCM_TAG_SIZE, NIST_AESGCM_128_MAC_4, CC_TEE_FIPS_ERROR_AESGCM_PUT },
        { NIST_AESGCM_192_ZERO_DATA, NIST_AESGCM_192_BIT_KEY_SIZE, NIST_AESGCM_96_ZERO_IV, NIST_AESGCM_96_BIT_IV_SIZE, CC_AES_ENCRYPT, NIST_AESGCM_EMPTY_DATA, NIST_AESGCM_EMPTY_DATA_SIZE, NIST_AESGCM_EMPTY_DATA, NIST_AESGCM_EMPTY_DATA_SIZE, NIST_AESGCM_EMPTY_DATA, NIST_AESGCM_TAG_SIZE, NIST_AESGCM_128_MAC_5, CC_TEE_FIPS_ERROR_AESGCM_PUT },
        { NIST_AESGCM_192_ZERO_DATA, NIST_AESGCM_192_BIT_KEY_SIZE, NIST_AESGCM_96_ZERO_IV, NIST_AESGCM_96_BIT_IV_SIZE, CC_AES_DECRYPT, NIST_AESGCM_EMPTY_DATA, NIST_AESGCM_EMPTY_DATA_SIZE, NIST_AESGCM_EMPTY_DATA, NIST_AESGCM_EMPTY_DATA_SIZE, NIST_AESGCM_EMPTY_DATA, NIST_AESGCM_TAG_SIZE, NIST_AESGCM_128_MAC_5, CC_TEE_FIPS_ERROR_AESGCM_PUT },
        { NIST_AESGCM_192_ZERO_DATA, NIST_AESGCM_192_BIT_KEY_SIZE, NIST_AESGCM_96_ZERO_IV, NIST_AESGCM_96_BIT_IV_SIZE, CC_AES_ENCRYPT, NIST_AESGCM_EMPTY_DATA, NIST_AESGCM_EMPTY_DATA_SIZE, NIST_AESGCM_128_ZERO_DATA, NIST_AESGCM_128_TEXT_DATA_SIZE, NIST_AESGCM_128_CIPHER_2, NIST_AESGCM_TAG_SIZE, NIST_AESGCM_128_MAC_6, CC_TEE_FIPS_ERROR_AESGCM_PUT },
        { NIST_AESGCM_192_ZERO_DATA, NIST_AESGCM_192_BIT_KEY_SIZE, NIST_AESGCM_96_ZERO_IV, NIST_AESGCM_96_BIT_IV_SIZE, CC_AES_DECRYPT, NIST_AESGCM_EMPTY_DATA, NIST_AESGCM_EMPTY_DATA_SIZE, NIST_AESGCM_128_CIPHER_2, NIST_AESGCM_128_TEXT_DATA_SIZE, NIST_AESGCM_128_ZERO_DATA, NIST_AESGCM_TAG_SIZE, NIST_AESGCM_128_MAC_6, CC_TEE_FIPS_ERROR_AESGCM_PUT },
        { NIST_AESGCM_192_KEY, NIST_AESGCM_192_BIT_KEY_SIZE, NIST_AESGCM_96_IV, NIST_AESGCM_96_BIT_IV_SIZE, CC_AES_ENCRYPT, NIST_AESGCM_EMPTY_DATA, NIST_AESGCM_EMPTY_DATA_SIZE, NIST_AESGCM_512_TEXT_DATA, NIST_AESGCM_512_TEXT_DATA_SIZE, NIST_AESGCM_512_CIPHER_2, NIST_AESGCM_TAG_SIZE, NIST_AESGCM_128_MAC_7, CC_TEE_FIPS_ERROR_AESGCM_PUT },
        { NIST_AESGCM_192_KEY, NIST_AESGCM_192_BIT_KEY_SIZE, NIST_AESGCM_96_IV, NIST_AESGCM_96_BIT_IV_SIZE, CC_AES_DECRYPT, NIST_AESGCM_EMPTY_DATA, NIST_AESGCM_EMPTY_DATA_SIZE, NIST_AESGCM_512_CIPHER_2, NIST_AESGCM_512_TEXT_DATA_SIZE, NIST_AESGCM_512_TEXT_DATA, NIST_AESGCM_TAG_SIZE, NIST_AESGCM_128_MAC_7, CC_TEE_FIPS_ERROR_AESGCM_PUT },
        { NIST_AESGCM_256_ZERO_DATA, NIST_AESGCM_256_BIT_KEY_SIZE, NIST_AESGCM_96_ZERO_IV, NIST_AESGCM_96_BIT_IV_SIZE, CC_AES_ENCRYPT, NIST_AESGCM_EMPTY_DATA, NIST_AESGCM_EMPTY_DATA_SIZE, NIST_AESGCM_EMPTY_DATA, NIST_AESGCM_EMPTY_DATA_SIZE, NIST_AESGCM_EMPTY_DATA, NIST_AESGCM_TAG_SIZE, NIST_AESGCM_128_MAC_8, CC_TEE_FIPS_ERROR_AESGCM_PUT },
        { NIST_AESGCM_256_ZERO_DATA, NIST_AESGCM_256_BIT_KEY_SIZE, NIST_AESGCM_96_ZERO_IV, NIST_AESGCM_96_BIT_IV_SIZE, CC_AES_DECRYPT, NIST_AESGCM_EMPTY_DATA, NIST_AESGCM_EMPTY_DATA_SIZE, NIST_AESGCM_EMPTY_DATA, NIST_AESGCM_EMPTY_DATA_SIZE, NIST_AESGCM_EMPTY_DATA, NIST_AESGCM_TAG_SIZE, NIST_AESGCM_128_MAC_8, CC_TEE_FIPS_ERROR_AESGCM_PUT },
        { NIST_AESGCM_256_ZERO_DATA, NIST_AESGCM_256_BIT_KEY_SIZE, NIST_AESGCM_96_ZERO_IV, NIST_AESGCM_96_BIT_IV_SIZE, CC_AES_ENCRYPT, NIST_AESGCM_EMPTY_DATA, NIST_AESGCM_EMPTY_DATA_SIZE, NIST_AESGCM_128_ZERO_DATA, NIST_AESGCM_128_TEXT_DATA_SIZE, NIST_AESGCM_128_CIPHER_3, NIST_AESGCM_TAG_SIZE, NIST_AESGCM_128_MAC_9, CC_TEE_FIPS_ERROR_AESGCM_PUT },
        { NIST_AESGCM_256_ZERO_DATA, NIST_AESGCM_256_BIT_KEY_SIZE, NIST_AESGCM_96_ZERO_IV, NIST_AESGCM_96_BIT_IV_SIZE, CC_AES_DECRYPT, NIST_AESGCM_EMPTY_DATA, NIST_AESGCM_EMPTY_DATA_SIZE, NIST_AESGCM_128_CIPHER_3, NIST_AESGCM_128_TEXT_DATA_SIZE, NIST_AESGCM_128_ZERO_DATA, NIST_AESGCM_TAG_SIZE, NIST_AESGCM_128_MAC_9, CC_TEE_FIPS_ERROR_AESGCM_PUT },
        { NIST_AESGCM_256_KEY, NIST_AESGCM_256_BIT_KEY_SIZE, NIST_AESGCM_96_IV, NIST_AESGCM_96_BIT_IV_SIZE, CC_AES_ENCRYPT, NIST_AESGCM_EMPTY_DATA, NIST_AESGCM_EMPTY_DATA_SIZE, NIST_AESGCM_512_TEXT_DATA, NIST_AESGCM_512_TEXT_DATA_SIZE, NIST_AESGCM_512_CIPHER_3, NIST_AESGCM_TAG_SIZE, NIST_AESGCM_128_MAC_10, CC_TEE_FIPS_ERROR_AESGCM_PUT },
        { NIST_AESGCM_256_KEY, NIST_AESGCM_256_BIT_KEY_SIZE, NIST_AESGCM_96_IV, NIST_AESGCM_96_BIT_IV_SIZE, CC_AES_DECRYPT, NIST_AESGCM_EMPTY_DATA, NIST_AESGCM_EMPTY_DATA_SIZE, NIST_AESGCM_512_CIPHER_3, NIST_AESGCM_512_TEXT_DATA_SIZE, NIST_AESGCM_512_TEXT_DATA, NIST_AESGCM_TAG_SIZE, NIST_AESGCM_128_MAC_10, CC_TEE_FIPS_ERROR_AESGCM_PUT },
        { NIST_AESGCM_256_KEY, NIST_AESGCM_256_BIT_KEY_SIZE, NIST_AESGCM_96_IV, NIST_AESGCM_96_BIT_IV_SIZE, CC_AES_ENCRYPT, NIST_AESGCM_160_ADATA, NIST_AESGCM_160_ADATA_SIZE, NIST_AESGCM_512_TEXT_DATA, NIST_AESGCM_480_TEXT_DATA_SIZE, NIST_AESGCM_512_CIPHER_3, NIST_AESGCM_TAG_SIZE, NIST_AESGCM_128_MAC_11, CC_TEE_FIPS_ERROR_AESGCM_PUT },
        { NIST_AESGCM_256_KEY, NIST_AESGCM_256_BIT_KEY_SIZE, NIST_AESGCM_96_IV, NIST_AESGCM_96_BIT_IV_SIZE, CC_AES_DECRYPT, NIST_AESGCM_160_ADATA, NIST_AESGCM_160_ADATA_SIZE, NIST_AESGCM_512_CIPHER_3, NIST_AESGCM_480_TEXT_DATA_SIZE, NIST_AESGCM_512_TEXT_DATA, NIST_AESGCM_TAG_SIZE, NIST_AESGCM_128_MAC_11, CC_TEE_FIPS_ERROR_AESGCM_PUT },
        { NIST_AESGCM_192_KEY, NIST_AESGCM_192_BIT_KEY_SIZE, NIST_AESGCM_96_IV, NIST_AESGCM_96_BIT_IV_SIZE, CC_AES_ENCRYPT, NIST_AESGCM_160_ADATA, NIST_AESGCM_160_ADATA_SIZE, NIST_AESGCM_512_TEXT_DATA, NIST_AESGCM_480_TEXT_DATA_SIZE, NIST_AESGCM_512_CIPHER_2, NIST_AESGCM_TAG_SIZE, NIST_AESGCM_128_MAC_12, CC_TEE_FIPS_ERROR_AESGCM_PUT },
        { NIST_AESGCM_192_KEY, NIST_AESGCM_192_BIT_KEY_SIZE, NIST_AESGCM_96_IV, NIST_AESGCM_96_BIT_IV_SIZE, CC_AES_DECRYPT, NIST_AESGCM_160_ADATA, NIST_AESGCM_160_ADATA_SIZE, NIST_AESGCM_512_CIPHER_2, NIST_AESGCM_480_TEXT_DATA_SIZE, NIST_AESGCM_512_TEXT_DATA, NIST_AESGCM_TAG_SIZE, NIST_AESGCM_128_MAC_12, CC_TEE_FIPS_ERROR_AESGCM_PUT },
};
#define FIPS_AESGCM_NUM_OF_TESTS        (sizeof(FipsAesGcmDataTable) / sizeof(FipsAesGcmData))

static const FipsDesData FipsDesDataTable[] = {
        { { NIST_TDES_ECB3_KEY_1, NIST_TDES_ECB3_KEY_2, NIST_TDES_ECB3_KEY_3 }, CC_DES_3_KeysInUse, NIST_TDES_ECB_IV, CC_DES_Encrypt, CC_DES_ECB_mode, NIST_TDES_ECB3_PLAIN_DATA, NIST_TDES_ECB3_CIPHER, NIST_TDES_VECTOR_SIZE, CC_TEE_FIPS_ERROR_DES_ECB_PUT },
        { { NIST_TDES_ECB3_KEY_1, NIST_TDES_ECB3_KEY_2, NIST_TDES_ECB3_KEY_3 }, CC_DES_3_KeysInUse, NIST_TDES_ECB_IV, CC_DES_Decrypt, CC_DES_ECB_mode, NIST_TDES_ECB3_CIPHER, NIST_TDES_ECB3_PLAIN_DATA, NIST_TDES_VECTOR_SIZE, CC_TEE_FIPS_ERROR_DES_ECB_PUT },
        { { NIST_TDES_ECB2_KEY_1, NIST_TDES_ECB2_KEY_2, NIST_TDES_ECB2_KEY_1 }, CC_DES_3_KeysInUse, NIST_TDES_ECB_IV, CC_DES_Encrypt, CC_DES_ECB_mode, NIST_TDES_ECB2_PLAIN_DATA, NIST_TDES_ECB2_CIPHER, NIST_TDES_VECTOR_SIZE, CC_TEE_FIPS_ERROR_DES_ECB_PUT },
        { { NIST_TDES_ECB2_KEY_1, NIST_TDES_ECB2_KEY_2, NIST_TDES_ECB2_KEY_1 }, CC_DES_3_KeysInUse, NIST_TDES_ECB_IV, CC_DES_Decrypt, CC_DES_ECB_mode, NIST_TDES_ECB2_CIPHER, NIST_TDES_ECB2_PLAIN_DATA, NIST_TDES_VECTOR_SIZE, CC_TEE_FIPS_ERROR_DES_ECB_PUT },
        { { NIST_TDES_CBC3_KEY_1, NIST_TDES_CBC3_KEY_2, NIST_TDES_CBC3_KEY_3 }, CC_DES_3_KeysInUse, NIST_TDES_CBC3_IV, CC_DES_Encrypt, CC_DES_CBC_mode, NIST_TDES_CBC3_PLAIN_DATA, NIST_TDES_CBC3_CIPHER, NIST_TDES_VECTOR_SIZE, CC_TEE_FIPS_ERROR_DES_CBC_PUT },
        { { NIST_TDES_CBC3_KEY_1, NIST_TDES_CBC3_KEY_2, NIST_TDES_CBC3_KEY_3 }, CC_DES_3_KeysInUse, NIST_TDES_CBC3_IV, CC_DES_Decrypt, CC_DES_CBC_mode, NIST_TDES_CBC3_CIPHER, NIST_TDES_CBC3_PLAIN_DATA, NIST_TDES_VECTOR_SIZE, CC_TEE_FIPS_ERROR_DES_CBC_PUT },
        { { NIST_TDES_CBC2_KEY_1, NIST_TDES_CBC2_KEY_2, NIST_TDES_CBC2_KEY_1 }, CC_DES_3_KeysInUse, NIST_TDES_CBC2_IV, CC_DES_Encrypt, CC_DES_CBC_mode, NIST_TDES_CBC2_PLAIN_DATA, NIST_TDES_CBC2_CIPHER, NIST_TDES_VECTOR_SIZE, CC_TEE_FIPS_ERROR_DES_CBC_PUT },
        { { NIST_TDES_CBC2_KEY_1, NIST_TDES_CBC2_KEY_2, NIST_TDES_CBC2_KEY_1 }, CC_DES_3_KeysInUse, NIST_TDES_CBC2_IV, CC_DES_Decrypt, CC_DES_CBC_mode, NIST_TDES_CBC2_CIPHER, NIST_TDES_CBC2_PLAIN_DATA, NIST_TDES_VECTOR_SIZE, CC_TEE_FIPS_ERROR_DES_CBC_PUT },
};
#define FIPS_DES_NUM_OF_TESTS        (sizeof(FipsDesDataTable) / sizeof(FipsDesData))

static const FipsHashData FipsHashDataTable[] = {
        { CC_HASH_SHA1_mode, NIST_SHA_1_MSG, NIST_SHA_MSG_SIZE, NIST_SHA_1_MD, CC_HASH_SHA1_DIGEST_SIZE_IN_BYTES, CC_TEE_FIPS_ERROR_SHA1_PUT },
        { CC_HASH_SHA256_mode, NIST_SHA_256_MSG, NIST_SHA_MSG_SIZE, NIST_SHA_256_MD, CC_HASH_SHA256_DIGEST_SIZE_IN_BYTES, CC_TEE_FIPS_ERROR_SHA256_PUT },
        { CC_HASH_SHA512_mode, NIST_SHA_512_MSG, NIST_SHA_MSG_SIZE, NIST_SHA_512_MD, CC_HASH_SHA512_DIGEST_SIZE_IN_BYTES, CC_TEE_FIPS_ERROR_SHA512_PUT },
};
#define FIPS_HASH_NUM_OF_TESTS        (sizeof(FipsHashDataTable) / sizeof(FipsHashData))

static const FipsHmacData FipsHmacDataTable[] = {
        { CC_HASH_SHA256_mode, NIST_HMAC_SHA256_KEY, NIST_HMAC_SHA256_KEY_SIZE, NIST_HMAC_SHA256_PLAIN_DATA, NIST_HMAC_SHA256_VECTOR_SIZE, NIST_HMAC_SHA256_MAC, NIST_HMAC_SHA256_OUTPUT_SIZE, CC_TEE_FIPS_ERROR_HMAC_SHA256_PUT },
};
#define FIPS_HMAC_NUM_OF_TESTS        (sizeof(FipsHmacDataTable) / sizeof(FipsHmacData))

/* internal function prototypes */
static CCError_t FipsRunAes(uint8_t* pKey,
        uint32_t keySize,
        uint8_t* pIv,
        CCAesEncryptMode_t encMode,
        CCAesOperationMode_t oprMode,
        uint8_t* dataIn,
        size_t dataInSize,
        uint8_t* dataOut);

static CCAesCcmKeySize_t FIPS_AesCcmToEnumKeySize(uint32_t keySize);
static CCAesGcmKeySize_t FIPS_AesGcmToEnumKeySize(uint32_t keySize);

/***** AES **************/
CCFipsError_t CC_FipsAesRunTests(void)
{
        CCError_t error = CC_OK;
        FipsAesData *aesData = NULL;
        uint32_t i;
        uint8_t dataOutActual[FIPS_SYM_PUT_MAX_TEST_DATA_SIZE];

        for (i = 0; i < FIPS_AES_NUM_OF_TESTS; ++i) {
                aesData = (FipsAesData*)&FipsAesDataTable[i];
                error = FipsRunAes(aesData->key, aesData->keySize, aesData->iv, aesData->encMode, aesData->oprMode, aesData->dataIn, aesData->dataInSize, dataOutActual);
                if (error != CC_OK) {
                        return aesData->error;
                }
                if (CC_PalMemCmp(dataOutActual, aesData->dataOut, aesData->dataOutSize) != 0) {
                        return aesData->error;
                }
        }

        FipsSetTrace(CC_FIPS_TRACE_AES_PUT);

        return CC_TEE_FIPS_ERROR_OK;
}

static CCError_t FipsRunAes(uint8_t* pKey,
        uint32_t keySize,
        CCAesIv_t pIv,
        CCAesEncryptMode_t encMode,
        CCAesOperationMode_t oprMode,
        uint8_t* dataIn,
        size_t dataInSize,
        uint8_t* dataOut)
{
        CCError_t error = CC_OK;

        CCAesUserContext_t aesContext;
        CCAesUserKeyData_t keyData;
        size_t dataOutSize = dataInSize;

        /* Encrypt (K,IV) by AES-CBC using output buff */
        error = CC_AesInit(&aesContext, encMode, oprMode, CC_AES_PADDING_NONE);
        if (error != CC_OK) {
                return error;
        }

        keyData.pKey = pKey;
        keyData.keySize = keySize;
        error = CC_AesSetKey(&aesContext, CC_AES_USER_KEY, &keyData, sizeof(keyData));
        if (error != CC_OK) {
                return error;
        }

        if (oprMode != CC_AES_MODE_ECB && oprMode != CC_AES_MODE_CMAC) {
                error = CC_AesSetIv(&aesContext, pIv);
                if (error != CC_OK) {
                        return error;
                }
        }

        error = CC_AesFinish(&aesContext,
                dataInSize,
                dataIn/*in*/,
                dataInSize,
                dataOut,/*out*/
                (size_t *)&dataOutSize);

        return error;
}


/***** AES-CCM **************/
CCFipsError_t CC_FipsAesCcmRunTests(void)
{
        CCError_t error = CC_OK;
        FipsAesCcmData *aesCcmData = NULL;
        uint32_t i;
        uint8_t dataOutActual[FIPS_SYM_PUT_MAX_TEST_DATA_SIZE];
        CCAesCcmMacRes_t macResActual;

        for (i = 0; i < FIPS_AESCCM_NUM_OF_TESTS; ++i) {
                aesCcmData = (FipsAesCcmData*)&FipsAesCcmDataTable[i];
                if (aesCcmData->encMode == CC_AES_DECRYPT) {
                        CC_PalMemCopy(macResActual, aesCcmData->macResOut, sizeof(CCAesCcmMacRes_t));
                }
                error = CC_AesCcm(aesCcmData->encMode,
                                        aesCcmData->key,
                                        FIPS_AesCcmToEnumKeySize(aesCcmData->keySize),
                                        aesCcmData->nonce,
                                        aesCcmData->nonceSize,
                                        aesCcmData->AData,
                                        aesCcmData->ADataSize,
                                        aesCcmData->textData,
                                        aesCcmData->textDataSize,
                                        dataOutActual,
                                        aesCcmData->tagSize,
                                        macResActual,
                                        CC_AES_MODE_CCM);
                if (error != CC_OK) {
                        return aesCcmData->error;
                }
                if (CC_PalMemCmp(dataOutActual, aesCcmData->textDataOut, aesCcmData->textDataSize) != 0) {
                        return aesCcmData->error;
                }
                if (aesCcmData->encMode == CC_AES_ENCRYPT && CC_PalMemCmp(macResActual, aesCcmData->macResOut, sizeof(CCAesCcmMacRes_t)) != 0) {
                        return aesCcmData->error;
                }
        }

        FipsSetTrace(CC_FIPS_TRACE_AESCCM_PUT);

        return CC_TEE_FIPS_ERROR_OK;
}

static CCAesCcmKeySize_t FIPS_AesCcmToEnumKeySize(uint32_t keySize)
{
        CCAesCcmKeySize_t AesCcmKeySize = CC_AES_KeySizeNumOfOptions;
        switch (keySize)
        {
        case NIST_AESCCM_128_BIT_KEY_SIZE:
                AesCcmKeySize = CC_AES_Key128BitSize;
                break;
        case NIST_AESCCM_192_BIT_KEY_SIZE:
                AesCcmKeySize = CC_AES_Key192BitSize;
                break;
        case NIST_AESCCM_256_BIT_KEY_SIZE:
                AesCcmKeySize = CC_AES_Key256BitSize;
                break;
        default:
                AesCcmKeySize = CC_AES_KeySizeNumOfOptions;
                break;
        }
        return AesCcmKeySize;
}

/***** AES-GCM **************/
CCFipsError_t CC_FipsAesGcmRunTests(void)
{
        CCError_t error = CC_OK;
        FipsAesGcmData *aesGcmData = NULL;
        uint32_t i;
        uint8_t dataOutActual[FIPS_SYM_PUT_MAX_TEST_GCM_DATA_SIZE];
        CCAesGcmTagRes_t macResActual;

        for (i = 0; i < FIPS_AESGCM_NUM_OF_TESTS; ++i) {
                aesGcmData = (FipsAesGcmData*)&FipsAesGcmDataTable[i];
                if (aesGcmData->encMode == CC_AES_DECRYPT) {
                        CC_PalMemCopy(macResActual, aesGcmData->macResOut, sizeof(CCAesGcmTagRes_t));
                }
                error = CC_AesGcm(aesGcmData->encMode,
                                        aesGcmData->key,
                                        FIPS_AesGcmToEnumKeySize(aesGcmData->keySize),
                                        aesGcmData->iv,
                                        aesGcmData->ivSize,
                                        aesGcmData->AData,
                                        aesGcmData->ADataSize,
                                        aesGcmData->textData,
                                        aesGcmData->textDataSize,
                                        dataOutActual,
                                        aesGcmData->tagSize,
                                        macResActual);
                if (error != CC_OK) {
                    return aesGcmData->error;
                }
                if (CC_PalMemCmp(dataOutActual, aesGcmData->textDataOut, aesGcmData->textDataSize) != 0) {
                    return aesGcmData->error;
                }
                if (aesGcmData->encMode == CC_AES_ENCRYPT && CC_PalMemCmp(macResActual, aesGcmData->macResOut, sizeof(CCAesGcmTagRes_t)) != 0) {
                    return aesGcmData->error;
                }
        }

        FipsSetTrace(CC_FIPS_TRACE_AESGCM_PUT);

        return CC_TEE_FIPS_ERROR_OK;
}

static CCAesGcmKeySize_t FIPS_AesGcmToEnumKeySize(uint32_t keySize)
{
        CCAesGcmKeySize_t AesGcmKeySize = CC_AES_KeySizeNumOfOptions;
        switch (keySize)
        {
        case NIST_AESGCM_128_BIT_KEY_SIZE:
                AesGcmKeySize = CC_AES_Key128BitSize;
                break;
        case NIST_AESGCM_192_BIT_KEY_SIZE:
                AesGcmKeySize = CC_AES_Key192BitSize;
                break;
        case NIST_AESGCM_256_BIT_KEY_SIZE:
                AesGcmKeySize = CC_AES_Key256BitSize;
                break;
        default:
                AesGcmKeySize = CC_AES_KeySizeNumOfOptions;
                break;
        }
        return AesGcmKeySize;
}


/***** TDES **************/
CCFipsError_t CC_FipsDesRunTests(void)
{
        CCError_t error = CC_OK;
        FipsDesData* desData = NULL;
        uint32_t i;
        uint8_t dataOutActual[FIPS_SYM_PUT_MAX_TEST_DATA_SIZE];

        for (i = 0; i < FIPS_DES_NUM_OF_TESTS; ++i)
        {
                desData = (FipsDesData*)&FipsDesDataTable[i];
                error = CC_Des(desData->iv, &(desData->key), desData->numOfKeys, desData->encMode, desData->oprMode, desData->dataIn, desData->dataInSize, dataOutActual);
                if (error != CC_OK) {
                        return desData->error;
                }
                if (CC_PalMemCmp(dataOutActual, desData->dataOut, desData->dataInSize) != 0) {
                        return desData->error;
                }
        }

        FipsSetTrace(CC_FIPS_TRACE_DES_PUT);

        return CC_TEE_FIPS_ERROR_OK;
}


/***** HASH **************/
CCFipsError_t CC_FipsHashRunTests(void)
{
        CCError_t error = CC_OK;
        FipsHashData* hashData = NULL;
        uint32_t i;
        CCHashResultBuf_t hashResultBuffActual;

        for (i = 0; i < FIPS_HASH_NUM_OF_TESTS; ++i)
        {
                hashData = (FipsHashData*)&FipsHashDataTable[i];
                error = CC_Hash(hashData->oprMode, hashData->dataIn, hashData->dataInSize, hashResultBuffActual);
                if (error != CC_OK) {
                        return hashData->error;
                }
                if (CC_PalMemCmp(hashResultBuffActual, hashData->HashResultBuff, hashData->HmacResultSize) != 0) {
                        return hashData->error;
                }
        }

        FipsSetTrace(CC_FIPS_TRACE_HASH_PUT);

        return CC_TEE_FIPS_ERROR_OK;
}


/***** HMAC **************/
CCFipsError_t CC_FipsHmacRunTests(void)
{
        CCError_t error = CC_OK;
        FipsHmacData* hmacData = NULL;
        uint32_t i;
        CCHashResultBuf_t hmacResultBuffActual;

        for (i = 0; i < FIPS_HMAC_NUM_OF_TESTS; ++i)
        {
                hmacData = (FipsHmacData*)&FipsHmacDataTable[i];
                error = CC_Hmac(hmacData->oprMode, hmacData->key, hmacData->keySize, hmacData->dataIn, hmacData->dataInSize, hmacResultBuffActual);
                if (error != CC_OK) {
                        return hmacData->error;
                }
                if (CC_PalMemCmp((uint8_t*)hmacResultBuffActual, hmacData->HmacResultBuff, hmacData->HmacResultSize) != 0) {
                        return hmacData->error;
                }
        }

        FipsSetTrace(CC_FIPS_TRACE_HMAC_PUT);

        return CC_TEE_FIPS_ERROR_OK;
}

