/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include "secureboot_stage_defs.h"
#include "bootimagesverifier_error.h"
#include "cc_pal_log.h"
#include "cc_certificate_defs.h"


/**
   @brief This function copy N, Np (CCSbNParams_t) and signature
   (certificate start address + sizeof certificate in certificate header) from the certificate to workspace.
   Return pointer to certificate header CCSbCertHeader_t, and pointer to cert body sizeof()

 */
CCError_t CCCertFieldsParse(BufferInfo32_t  *pCertInfo,
                            BufferInfo32_t  *pWorkspaceInfo,
                            CertFieldsInfo_t  *pCertFields,
                            uint32_t	**ppCertStartSign,
                            uint32_t	*pCertSignedSize,
                            BufferInfo32_t  *pX509HeaderInfo)
{
        uint8_t *pPubKey = NULL;
        uint8_t *pSignature = NULL;
        uint32_t  certSignedSize = 0;
        BsvRsaExponentWorkspace_t *lpWorkspaceInt;

        /* Fields used only for X509 */
        CC_UNUSED_PARAM(pX509HeaderInfo);

        if ((pWorkspaceInfo == NULL) ||
            (pWorkspaceInfo->pBuffer == NULL) ||
            (pWorkspaceInfo->bufferSize < sizeof(BsvRsaExponentWorkspace_t))) {
                CC_PAL_LOG_ERR("workspace and or sizes illegal\n");
                return CC_BSV_ILLEGAL_INPUT_PARAM_ERR;
        }

        lpWorkspaceInt = (BsvRsaExponentWorkspace_t *)pWorkspaceInfo->pBuffer;

        /* Verify the cert size (from the header), certSize is constant according to MAX certificate size. */
        UTIL_MemCopy((uint8_t *)&pCertFields->certHeader, (uint8_t *)pCertInfo->pBuffer, sizeof(CCSbCertHeader_t));
        certSignedSize = pCertFields->certHeader.certSize * CC_32BIT_WORD_SIZE;
        if (certSignedSize > pCertInfo->bufferSize - sizeof(CCSbSignature_t)) {
                CC_PAL_LOG_ERR("certSignedSize illegal 0x%x, certSize  0x%x, sizeof(CCSbSignature_t) 0x%x,\n", (unsigned int)certSignedSize, (unsigned int)(pCertInfo->bufferSize), (unsigned int)sizeof(CCSbSignature_t));
                UTIL_MemSet((uint8_t *)&pCertFields->certHeader, 0, sizeof(CCSbCertHeader_t));
                return CC_BSV_ILLEGAL_INPUT_PARAM_ERR;
        }

        /* Parse and set the pointers */
        pCertFields->pCertBody = (uint8_t *)((unsigned long)pCertInfo->pBuffer + sizeof(CCSbCertHeader_t) + sizeof(CCSbNParams_t));
        pCertFields->certBodySize = pCertInfo->bufferSize - (sizeof(CCSbCertHeader_t) + sizeof(CCSbNParams_t) + sizeof(CCSbSignature_t));
        pPubKey = (uint8_t *)((unsigned long)pCertInfo->pBuffer + sizeof(CCSbCertHeader_t));
        pSignature = (uint8_t *)((unsigned long)pCertInfo->pBuffer + certSignedSize);
        /* copy N and Np into workspace */
        UTIL_MemCopy((uint8_t *)&lpWorkspaceInt->pNparams, pPubKey, sizeof(CCSbNParams_t));
        /* copy signature into workspace */
        UTIL_MemCopy((uint8_t *)&lpWorkspaceInt->pDataIn , pSignature, sizeof(CCSbSignature_t));
        *ppCertStartSign = pCertInfo->pBuffer;
        *pCertSignedSize = certSignedSize;


        return CC_OK;
}
