/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */
#include "util_asn1_parser.h"
#include "x509_error.h"
#include "x509_cert_parser.h"
#include "x509_extensions_parser.h"
#include "bootimagesverifier_error.h"
#include "cc_pal_x509_defs.h"
#include "bsv_error.h"
#include "cc_bitops.h"
#include "cc_pal_log.h"
#include "cc_certificate_defs.h"
#include "cc_pka_hw_plat_defs.h"
#include "secureboot_stage_defs.h"


/**
   @brief This function load sizeof(CCSbCertAsn1Data_t ) from flash and get the
   certificate size from it. Make sure size is within range
   (smaller than workspace size not including the required space for N, Np and signature).
   read the certificate according to size from header and copy the certificate content from Flash to RAM.
 */
uint32_t CCCertLoadCertificate(CCSbFlashReadFunc flashRead_func,
                               void *userContext,
                               CCAddr_t certAddress,
                               uint32_t *pCert,
                               uint32_t *pCertBufferWordSize)
{
        uint32_t rc = 0;
        CCSbCertAsn1Data_t asn1DataCert1;
        uint8_t *plCert = (uint8_t *)pCert;
        uint32_t certSizeFullWords;

        /* Verify that the certificate buffer size is big enough to contain the header */
        if (*pCertBufferWordSize < (SIZE_OF_CERT_ASN1_HEADER / CC_32BIT_WORD_SIZE)) {
                CC_PAL_LOG_ERR("certificate buff size too small to contain certificate header\n");
                return CC_BOOT_IMG_VERIFIER_WORKSPACE_SIZE_TOO_SMALL;
        }

        /* Read the certificate header from the Flash */
        rc = flashRead_func(certAddress,
                            plCert,
                            SIZE_OF_CERT_ASN1_HEADER,
                            userContext);
        if (rc != CC_OK) {
                CC_PAL_LOG_ERR("failed flashRead_func for certificate header\n");
                return rc;
        }

        /* Note: although we only loaded the certificate header to the workspace,
         * the UTIL_Asn1ReadItemVerifyTagFW function verifies that the whole certificate is within the workspace range */
        rc = UTIL_Asn1ReadItemVerifyTagFW((uint8_t **)&plCert,
                                          &asn1DataCert1,
                                          CC_X509_CERT_SEQ_TAG_ID,
                                          (unsigned long)plCert + ((*pCertBufferWordSize) * CC_32BIT_WORD_SIZE) /* endAddress */
                                          );
        if (rc != CC_OK) {
                CC_PAL_LOG_ERR("Failed to UTIL_Asn1ReadItemVerifyTagFW 0x%x for cert header\n", rc);
                return rc;
        }

        certSizeFullWords = ALIGN_TO_4BYTES(asn1DataCert1.itemSize);

        /* Verify no wrap around */
        if ((*pCertBufferWordSize) * CC_32BIT_WORD_SIZE - SIZE_OF_CERT_ASN1_HEADER > (*pCertBufferWordSize) * CC_32BIT_WORD_SIZE) {
                CC_PAL_LOG_ERR("Certificate size too big\n");
                return CC_BOOT_IMG_VERIFIER_INV_INPUT_PARAM;
        }
        /* Make sure certificate size is within range */
        if (certSizeFullWords > ((*pCertBufferWordSize) * CC_32BIT_WORD_SIZE - SIZE_OF_CERT_ASN1_HEADER)) {
                CC_PAL_LOG_ERR("Certificate size too big\n");
                return CC_BOOT_IMG_VERIFIER_INV_INPUT_PARAM;
        }

        /* according to the header read the additional certificate buffer -
          * not including the non-signed part in case of content certificate */
        rc = flashRead_func(certAddress + SIZE_OF_CERT_ASN1_HEADER,
                            (uint8_t *)plCert,
                            asn1DataCert1.itemSize,
                            userContext);
        if (rc != CC_OK) {
                CC_PAL_LOG_ERR("failed flashRead_func for certificate\n");
                return rc;
        }

        *pCertBufferWordSize = ((certSizeFullWords + SIZE_OF_CERT_ASN1_HEADER) / CC_32BIT_WORD_SIZE);

        return CC_OK;

}


