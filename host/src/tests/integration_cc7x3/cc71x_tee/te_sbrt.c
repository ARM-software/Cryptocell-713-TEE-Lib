/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include <stdio.h>
#include <stdint.h>

/* Test engine and testAL headers*/
#include "test_engine.h"
#include "test_pal_mem.h"
#include "test_proj_otp.h"
#include "test_proj_defs.h"
#include "test_proj_cclib.h"
#include "te_flash.h"
#include "te_sbrt_defs.h"
#include "te_sbrt.h"

/* CryptoCell headers*/
#include "cc_otp_defs.h"
#include "cc_boot_defs.h"
#include "secureboot_defs.h"
#include "cc_sbrt_api.h"
#ifdef CC_SB_X509_CERT_SUPPORTED
#include "cc_pal_x509_defs.h"
#endif

/******************************************************************
 * Defines
 ******************************************************************/
#define NUM_OF_BOOT_IMAGES  2

/******************************************************************
 * Enums
 ******************************************************************/

/******************************************************************
 * Types
 ******************************************************************/

typedef struct SbrtVector_t{
    uint32_t isHbkFull;
    CCSbPubKeyIndexType_t  certRot;
}SbrtVector_t;

/*! Definition for secure boot certificates chain.*/
typedef struct {
    uint8_t *pKey1; /*!< A pointer to the first key certificate in a secure boot certificate chain. */
    uint32_t key1_size;  /*!< The key certificate size. */
    unsigned long pKey1_flash_addr; /*!< Flash address of the first key certificate.*/
    uint8_t *pKey2; /*!< A pointer to the second key certificate in a secure boot certificate chain. */
    uint32_t key2_size; /*!< The key certificate size. */
    unsigned long pKey2_flash_addr; /*!< Flash address of the second key certificate.*/
    uint8_t *pContent; /*!< A pointer to the content certificate. */
    uint32_t content_size; /*!< Content certificate size. */
    unsigned long pContent_flash_addr; /*!< Flash address of the content certificate. */
}TE_secure_boot_chain_t;

/*! Test structure that includes all the required SW image information. */
typedef struct {
    CCSbImageMemoryType_t   image_memory_type; /*!< SW image location (Flash or RAM). */
    uint32_t image_size; /*!< SW Image size. */
    uint32_t image_is_encrypted; /*!< A flag defining if the SW image is encrypted or not. */
    CCAddr_t image_src_addr; /*!< SW image source address. */
    CCAddr_t image_dest_addr; /*!< SW image destination address. */
    uint8_t *pImage; /*!< SW image data. */
    uint8_t *pImage_to_load; /*!< Pointer to the SW image to load to memory (for the test usage) */
}TE_secure_boot_image_t;

/******************************************************************
 * Externs
 ******************************************************************/
extern CCError_t SbrtSwVersionGet(unsigned long hwBaseAddress, CCSbSwVersionId_t id, uint32_t *swVersion);


/* OEM HALF ROT */
extern uint8_t boot_se_trusted_key1[];
extern uint32_t boot_se_trusted_key1_size;
extern uint8_t boot_se_trusted_key2[];
extern uint32_t boot_se_trusted_key2_size;
extern uint8_t boot_se_trusted_content[];
extern uint32_t boot_se_trusted_content_size;
/* OEM FULL ROT */
extern uint8_t boot_se_non_trusted_key1[];
extern uint32_t boot_se_non_trusted_key1_size;
extern uint8_t boot_se_non_trusted_key2[];
extern uint32_t boot_se_non_trusted_key2_size;
extern uint8_t boot_se_non_trusted_content[];
extern uint32_t boot_se_non_trusted_content_size;

/* images */
extern uint32_t image1_size;
extern uint32_t image1_is_encrypted;
extern CCAddr_t image1_src_addr;
extern CCAddr_t image1_dest_addr;
extern uint8_t image1[];
extern uint8_t image1_to_load[];

extern uint32_t image2_size;
extern uint32_t image2_is_encrypted;
extern CCAddr_t image2_src_addr;
extern CCAddr_t image2_dest_addr;
extern uint8_t image2[];
extern uint8_t image2_to_load[];

extern uint32_t image3_size;
extern uint32_t image3_is_encrypted;
extern CCAddr_t image3_src_addr;
extern CCAddr_t image3_dest_addr;
extern uint8_t image3[];
extern uint8_t image3_to_load[];

extern uint32_t image4_size;
extern uint32_t image4_is_encrypted;
extern CCAddr_t image4_src_addr;
extern CCAddr_t image4_dest_addr;
extern uint8_t image4[];
extern uint8_t image4_to_load[];

/******************************************************************
 * Globals
 ******************************************************************/
TE_secure_boot_image_t boot_images[NUM_OF_BOOT_IMAGES];

SbrtVector_t sbrt_vector[] ={ { .isHbkFull =        FULL_HBK,
                                    .certRot =          CC_SB_HASH_BOOT_KEY_256B },
                                  { .isHbkFull =        NOT_FULL_HBK,
                                    .certRot =          CC_SB_HASH_BOOT_KEY_0_128B },
                                  { .isHbkFull =        NOT_FULL_HBK,
                                    .certRot =          CC_SB_HASH_BOOT_KEY_1_128B }};

uint32_t otpKceBuff[CC_OTP_KCE_SIZE_IN_WORDS] =  KCE_BUFF;
uint32_t otpHbk256Buff[CC_OTP_HBK_SIZE_IN_WORDS] = HBK256_BUFF;
uint32_t otpHbk0Buff[CC_OTP_HBK0_SIZE_IN_WORDS] =  HBK0_BUFF;
uint32_t otpHbk1Buff[CC_OTP_HBK1_SIZE_IN_WORDS] =  HBK1_BUFF;

/******************************************************************
 * Static Prototypes
 ******************************************************************/
static TE_rc_t sbrt_prepare(void *pContext);
static TE_rc_t sbrt_execute(void *pContext);

/******************************************************************
 * Static functions
 ******************************************************************/
static int setTestFieldsInOtp(uint32_t *otpBuff, uint32_t isFullHbk)
{
    int res = 0;

    TE_ASSERT_ERR(Test_ProjSetOtpField(otpBuff, otpKceBuff, PROJ_OTP_KCE_FIELD, KEY_IN_USE), 0, 1);
    if (isFullHbk == 1) {
        TE_ASSERT_ERR(Test_ProjSetHbkInOtpBuff(otpBuff,
                (uint8_t *)otpHbk256Buff, CC_OTP_HBK_SIZE_IN_WORDS,
                PROJ_OTP_HBK_FIELD,
                TEST_PROJ_LCS_SECURE), 0, 1);
     } else {
         TE_ASSERT_ERR(Test_ProjSetHbkInOtpBuff(otpBuff,
                (uint8_t *)otpHbk0Buff, CC_OTP_HBK0_SIZE_IN_WORDS,
                PROJ_OTP_HBK0_FIELD,
                TEST_PROJ_LCS_SECURE), 0, 1);
         TE_ASSERT_ERR(Test_ProjSetHbkInOtpBuff(otpBuff,
                (uint8_t *)otpHbk1Buff, CC_OTP_HBK1_SIZE_IN_WORDS,
                PROJ_OTP_HBK1_FIELD,
                TEST_PROJ_LCS_SECURE), 0, 1);
    }

bail:
    return res;
}

static uint32_t init_test_data(uint32_t         hbk_type,
                               TE_secure_boot_chain_t *boot_cert_chain,
                               uint32_t *nvCounter_id)
{
    int res = 0;

    TE_ASSERT(boot_cert_chain != NULL);
    TE_ASSERT(nvCounter_id != NULL);

    memset((uint8_t *)boot_cert_chain, 0, sizeof(TE_secure_boot_chain_t));
    memset((uint8_t *)boot_images, 0, sizeof(TE_secure_boot_image_t));
    /* get the certificate chain pointer according to the test */
    switch(hbk_type) {
    case CC_SB_HASH_BOOT_KEY_1_128B:
        boot_cert_chain->pKey1 = boot_se_trusted_key1;
        boot_cert_chain->key1_size = boot_se_trusted_key1_size;
        boot_cert_chain->pKey2 = boot_se_trusted_key2;
        boot_cert_chain->key2_size = boot_se_trusted_key2_size;
        boot_cert_chain->pContent = boot_se_trusted_content;
        boot_cert_chain->content_size = boot_se_trusted_content_size;
        boot_images[0].pImage = image3;
        boot_images[0].pImage_to_load = image3_to_load;
        boot_images[0].image_size = image3_size;
        boot_images[0].image_memory_type = CC_SB_IMAGE_IN_FLASH;
        boot_images[0].image_dest_addr = image3_dest_addr;
        boot_images[0].image_src_addr = image3_src_addr;
        boot_images[0].image_is_encrypted = image3_is_encrypted;
        boot_images[1].pImage = image4;
        boot_images[1].pImage_to_load = image4_to_load;
        boot_images[1].image_size = image4_size;
        boot_images[1].image_memory_type = CC_SB_IMAGE_IN_FLASH;
        boot_images[1].image_dest_addr = image4_dest_addr;
        boot_images[1].image_src_addr = image4_src_addr;
        boot_images[1].image_is_encrypted = image4_is_encrypted;
        *nvCounter_id = CC_SW_VERSION_TRUSTED;
        break;
    case CC_SB_HASH_BOOT_KEY_256B:
        boot_cert_chain->pKey1 = boot_se_non_trusted_key1;
        boot_cert_chain->key1_size = boot_se_non_trusted_key1_size;
        boot_cert_chain->pKey2 = boot_se_non_trusted_key2;
        boot_cert_chain->key2_size = boot_se_non_trusted_key2_size;
        boot_cert_chain->pContent = boot_se_non_trusted_content;
        boot_cert_chain->content_size = boot_se_non_trusted_content_size;
        boot_images[0].pImage = image1;
        boot_images[0].pImage_to_load = image1_to_load;
        boot_images[0].image_size = image1_size;
        boot_images[0].image_memory_type = CC_SB_IMAGE_IN_RAM;
        boot_images[0].image_dest_addr = image1_dest_addr;
        boot_images[0].image_src_addr = image1_src_addr;
        boot_images[0].image_is_encrypted = image1_is_encrypted;
        boot_images[1].pImage = image2;
        boot_images[1].pImage_to_load = image2_to_load;
        boot_images[1].image_size = image2_size;
        boot_images[1].image_memory_type = CC_SB_IMAGE_IN_RAM;
        boot_images[1].image_dest_addr = image2_dest_addr;
        boot_images[1].image_src_addr = image2_src_addr;
        boot_images[1].image_is_encrypted = image2_is_encrypted;
        *nvCounter_id = CC_SW_VERSION_NON_TRUSTED;
        break;
    case CC_SB_HASH_BOOT_KEY_0_128B:

    default:
        return 1;
    }

bail:
    return res;
}

static uint32_t TE_verify_loaded_images(CCSbImagesInfo_t *image_info)
{
    int res = 0;
    uint32_t i = 0;

    TE_ASSERT(image_info != NULL);
    TE_ASSERT(image_info->numOfImages == NUM_OF_BOOT_IMAGES);

    for (i = 0; i < image_info->numOfImages; i++) {
        TE_ASSERT(image_info->imagesList[i].imageSize == boot_images[i].image_size);
        TE_ASSERT(image_info->imagesList[i].imageMemoryType == boot_images[i].image_memory_type);
        switch(boot_images[i].image_memory_type) {
        case CC_SB_IMAGE_IN_FLASH:
            TE_ASSERT(image_info->imagesList[i].imageAddr == boot_images[i].image_src_addr);
            TE_ASSERT_ERR(TE_flash_memCmp(image_info->imagesList[i].imageAddr,
                                 (uint8_t *)boot_images[i].pImage,
                                 image_info->imagesList[i].imageSize, NULL), 0, 1);
            break;
        case CC_SB_IMAGE_IN_RAM:
            TE_ASSERT(image_info->imagesList[i].imageAddr == boot_images[i].image_dest_addr);
            TE_LOG_TRACE("printing image_info->imagesList[i].imageAddr 0x%lx\n", (unsigned long)image_info->imagesList[i].imageAddr);
            TE_LOG_BUFF(trace, (uint8_t *)((unsigned long)image_info->imagesList[i].imageAddr), image_info->imagesList[i].imageSize);
            TE_ASSERT_ERR(memcmp((uint8_t *)((unsigned long)image_info->imagesList[i].imageAddr),
                                 (uint8_t *)boot_images[i].pImage,
                                 image_info->imagesList[i].imageSize), 0, 1);
            break;
        default:
            TE_ASSERT(1 == 0);
        }

    }
bail:
    return res;
}

static int load_certificate_chain(TE_secure_boot_chain_t *pBootCertChain)
{
    int res = 0;

    TE_ASSERT(pBootCertChain != NULL);

    pBootCertChain->pKey1_flash_addr = (unsigned long)TE_FLASH_MAP_KEY1_CERT_ADDR;
    TE_ASSERT(pBootCertChain->pKey1_flash_addr != 0);
    pBootCertChain->pKey2_flash_addr = (unsigned long)TE_FLASH_MAP_KEY2_CERT_ADDR;
    TE_ASSERT(pBootCertChain->pKey2_flash_addr != 0);
    pBootCertChain->pContent_flash_addr = (unsigned long)TE_FLASH_MAP_CONTENT_CERT_ADDR;
    TE_ASSERT(pBootCertChain->pContent_flash_addr != 0);

    TE_flash_write((CCAddr_t)pBootCertChain->pKey1_flash_addr, (uint8_t *)pBootCertChain->pKey1, pBootCertChain->key1_size);
    TE_LOG_INFO("writing key1 cert to flash 0x%lx\n", (unsigned long)pBootCertChain->pKey1_flash_addr);
    TE_flash_write((CCAddr_t)pBootCertChain->pKey2_flash_addr, (uint8_t *)pBootCertChain->pKey2, pBootCertChain->key2_size);
    TE_LOG_INFO("writing key2 cert to flash 0x%lx\n", (unsigned long)pBootCertChain->pKey2_flash_addr);
    TE_flash_write((CCAddr_t)pBootCertChain->pContent_flash_addr, (uint8_t *)pBootCertChain->pContent, pBootCertChain->content_size);
    TE_LOG_INFO("writing content cert to flash 0x%lx\n", (unsigned long)pBootCertChain->pContent_flash_addr);
bail:
    return res;
}

static int load_images(TE_secure_boot_image_t *pBootImages, uint32_t num_of_images)
{
    int res = 0;
    uint32_t i;

    TE_ASSERT(pBootImages != NULL);
    TE_ASSERT(num_of_images == TE_FLASH_MAP_MAX_IMAGES);

    for (i = 0; i < num_of_images; i++) {
        TE_ASSERT(pBootImages[i].image_size < TE_FLASH_MAP_IMAGE_MAX_SIZE);
        if (pBootImages[i].image_src_addr != CC_SW_COMP_NO_MEM_LOAD_INDICATION) {
            TE_flash_write(pBootImages[i].image_src_addr, pBootImages[i].pImage_to_load, pBootImages[i].image_size);
            TE_LOG_INFO("writing image %d to flash 0x%lx\n", i, (unsigned long)pBootImages[i].image_src_addr);
        } else {
            memcpy((uint8_t *)(unsigned long)(pBootImages[i].image_dest_addr), pBootImages[i].pImage_to_load, pBootImages[i].image_size);
            TE_LOG_INFO("writing image %d to ram 0x%lx\n", i, (unsigned long)pBootImages[i].image_dest_addr);
        }
   }
bail:
    return res;
}

static TE_rc_t sbrt_prepare(void *pContext)
{
    uint32_t otpBuff[TEST_OTP_SIZE_IN_WORDS] = { 0 };

    uint32_t isHbkFull;
    SbrtVector_t *sbrtTestVec;
    TE_rc_t res = TE_RC_SUCCESS;

    TE_ASSERT(pContext != NULL);
    sbrtTestVec = (SbrtVector_t *) pContext;

    isHbkFull = sbrtTestVec->isHbkFull;

    /* Finalise CC TEE runtime library */
    Test_Proj_CC_LibFini_Wrap();
    /* Burn OTP */
    TE_ASSERT_ERR(Test_ProjBuildDefaultOtp(otpBuff,
                                           sizeof(otpBuff)/CC_32BIT_WORD_SIZE,
                                           TEST_PROJ_LCS_SECURE,
                                           PROJ_OTP_CHIP_STATE_PRODUCTION,
                                           PROJ_OTP_RMA_NO,
                                           NOT_SD_ENABLE,
                                           isHbkFull), 0 , 1);

    TE_ASSERT_ERR(setTestFieldsInOtp(otpBuff, isHbkFull), 0 , 1);

    TE_ASSERT_ERR(Test_ProjBurnOtp(otpBuff, TEST_PROJ_LCS_SECURE), 0, 1);

    TE_ASSERT(Test_Proj_CC_LibInit_Wrap() == CC_OK);
bail:
    return res;
}

static TE_rc_t sbrt_execute(void *pContext)
{
    TE_perfIndex_t cookie;
    SbrtVector_t *sbrtTestVec;
    int res = 0;
    TE_secure_boot_chain_t bootCertChain;
    CCSbCertInfo_t sbCertInfo;
    uint32_t hbkRotType;
    unsigned long hwBaseAddress = processMap.processTeeHwRegBaseAddr;
    CCSbImagesInfo_t imageInfo;
    CCSbX509TBSHeader_t x509HeaderInfo;
    uint32_t nvCounter_trusted_value = 0;
    uint32_t nvCounter_non_trusted_value = 0;
    uint32_t nvCounter_val;
    CCSbSwVersionId_t nvCounter_id = CC_SW_VERSION_TRUSTED;
    uint32_t *pWorkspace = NULL;

#ifdef CC_SB_X509_CERT_SUPPORTED
    CCX509CertHeaderInfo_t x509_info;
    x509HeaderInfo.pBuffer = (uint32_t *)&x509_info;
    x509HeaderInfo.bufferSize = sizeof(CCX509CertHeaderInfo_t);
#else
    x509HeaderInfo.pBuffer = NULL;
    x509HeaderInfo.bufferSize = 0;
#endif

    TE_ASSERT(pContext != NULL);
    sbrtTestVec = (SbrtVector_t *) pContext;

    hbkRotType = sbrtTestVec->certRot;

    if (hbkRotType == CC_SB_HASH_BOOT_KEY_0_128B) {
        /* The existing test doesn't include certificate chain for that case */
        return 0;
    }
    TE_ASSERT_ERR(init_test_data(hbkRotType, &bootCertChain, &nvCounter_id), 0, 1);
    TE_ASSERT_ERR(TE_flash_init(), 0, 1);

    pWorkspace = (uint32_t *)Test_PalDMAContigBufferAlloc(CC_SB_MIN_WORKSPACE_SIZE_IN_BYTES);
    TE_ASSERT(pWorkspace != 0);

    TE_ASSERT_ERR(SbrtSwVersionGet(hwBaseAddress, CC_SW_VERSION_TRUSTED, &nvCounter_trusted_value), CC_OK, 1);
    TE_ASSERT_ERR(SbrtSwVersionGet(hwBaseAddress, CC_SW_VERSION_NON_TRUSTED, &nvCounter_non_trusted_value), CC_OK, 1);

    /* Load the certificate chain to Flash */
    TE_ASSERT_ERR(load_certificate_chain(&bootCertChain), 0, 1);
    TE_LOG_INFO("certificate chain was loaded to Flash\n");

    /* Load SW components to Flash file */
    TE_ASSERT_ERR(load_images(boot_images, NUM_OF_BOOT_IMAGES), 0, 1);
    TE_LOG_INFO("%d SW images were loaded\n", NUM_OF_BOOT_IMAGES);

    /* Start of verification process */
    memset((uint8_t*)&sbCertInfo ,0x0, sizeof(sbCertInfo));
    TE_ASSERT_ERR(CC_SbrtCertChainVerificationInit(&sbCertInfo), CC_OK, 1);
    TE_LOG_INFO("Function CC_SbCertChainVerificationInit succeeded!!\n");

    /* Start performance measurement */
    cookie = TE_perfOpenNewEntry("sbrt", "sbrt_key_certificate");

    /* Verify key1 certificate */
    TE_ASSERT_ERR(CC_SbrtCertVerifySingle((CCSbFlashReadFunc)TE_flash_read,
                                        NULL,
                                        bootCertChain.pKey1_flash_addr,
                                        &sbCertInfo,
                                        &x509HeaderInfo,
                                        pWorkspace,
                                        CC_SB_MIN_WORKSPACE_SIZE_IN_BYTES,
                                        NULL,
                                        NULL), CC_OK, 1);
    TE_LOG_INFO("CC_SbCertVerifySingle for key1 succeeded\n");

    /* Finish performance measurement */
    TE_perfCloseEntry(cookie);

    /* Verify key2 certificate */

    /* Start performance measurement */
    cookie = TE_perfOpenNewEntry("sbrt", "sbrt_key2_certificate");

    TE_ASSERT_ERR(CC_SbrtCertVerifySingle((CCSbFlashReadFunc)TE_flash_read,
                                        NULL,
                                        bootCertChain.pKey2_flash_addr,
                                        &sbCertInfo,
                                        &x509HeaderInfo,
                                        pWorkspace,
                                        CC_SB_MIN_WORKSPACE_SIZE_IN_BYTES,
                                        NULL,
                                        NULL), CC_OK, 1);
    TE_LOG_INFO("CC_SbCertVerifySingle for key2 succeeded\n");

    /* Finish performance measurement */
    TE_perfCloseEntry(cookie);

    /* Start performance measurement */
    cookie = TE_perfOpenNewEntry("sbrt", "sbrt_content_certificate");

    /* Verify content certificate  */
    res = CC_SbrtCertVerifySingle((CCSbFlashReadFunc)TE_flash_read,
                                        NULL,
                                        bootCertChain.pContent_flash_addr,
                                        &sbCertInfo,
                                        &x509HeaderInfo,
                                        pWorkspace,
                                        CC_SB_MIN_WORKSPACE_SIZE_IN_BYTES,
                                        &imageInfo,
                                        NULL);
    /* Finish performance measurement */
    TE_perfCloseEntry(cookie);

    TE_LOG_INFO("CC_SbCertVerifySingle for content 0x%x\n", res);
    if (res != CC_OK) {
        goto bail;
    }

    /* Verify nvcounter in the OTP was set correctly */
    TE_ASSERT_ERR(SbrtSwVersionGet(hwBaseAddress, CC_SW_VERSION_TRUSTED, &nvCounter_val), CC_OK, 1);
    if (nvCounter_id == CC_SW_VERSION_TRUSTED) {
        TE_ASSERT(nvCounter_val != nvCounter_trusted_value);
    } else {
        TE_ASSERT(nvCounter_val == nvCounter_trusted_value);
    }
    TE_ASSERT_ERR(SbrtSwVersionGet(hwBaseAddress, CC_SW_VERSION_NON_TRUSTED, &nvCounter_val), CC_OK, 1);
    if (nvCounter_id == CC_SW_VERSION_NON_TRUSTED) {
        TE_ASSERT(nvCounter_val != nvCounter_non_trusted_value);
    } else {
        TE_ASSERT(nvCounter_val == nvCounter_non_trusted_value);
    }

    /* Check loaded images */
    TE_ASSERT_ERR(TE_verify_loaded_images(&imageInfo), 0, 1);

bail:
    TE_LOG_INFO("Exit secure boot test with 0x%08X !!\n\n", res);
    if( pWorkspace != NULL) {
        Test_PalDMAContigBufferFree(pWorkspace);
    }
    TE_flash_finish();

    return res;
}

/******************************************************************
 * Public
 ******************************************************************/
int TE_init_sbrt_test(void)
{
    TE_rc_t res = TE_RC_SUCCESS;

    TE_perfEntryInit("sbrt", "sbrt_key_certificate");
    TE_perfEntryInit("sbrt", "sbrt_key2_certificate");
    TE_perfEntryInit("sbrt", "sbrt_content_certificate");


    TE_ASSERT(TE_registerFlow("sbrt",
                              "SE FULL HBK",
                              "",
                              sbrt_prepare,
                              sbrt_execute,
                              NULL,
                              NULL,
                              &sbrt_vector[0]) == TE_RC_SUCCESS);


    TE_ASSERT(TE_registerFlow("sbrt",
                              "SE ICV ROT",
                              "",
                              sbrt_prepare,
                              sbrt_execute,
                              NULL,
                              NULL,
                              &sbrt_vector[1]) == TE_RC_SUCCESS);

    TE_ASSERT(TE_registerFlow("sbrt",
                              "SE OEM ROT",
                              "",
                              sbrt_prepare,
                              sbrt_execute,
                              NULL,
                              NULL,
                              &sbrt_vector[2]) == TE_RC_SUCCESS);

    goto bail;

bail:
    return res;
}

