/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */
#include "secureboot_stage_defs.h"
#include "util_asn1_parser.h"
#include "x509_error.h"
#include "x509_cert_parser.h"
#include "x509_extensions_parser.h"
#include "bootimagesverifier_error.h"
#include "cc_pal_x509_defs.h"
#include "cc_bitops.h"
#include "cc_pal_log.h"
#include "cc_certificate_defs.h"
#include "cc_pka_hw_plat_defs.h"


/**
   @brief This function
   call SB_X509_VerifyCertTbsHeader() to verify the X509 header and get the user Data and public key.
   Copy the public key into workspace
   Call SB_X509_ParseCertExtensions() to get pointers for:
      Proprietary header pointer
      Copy Np into workspace following N
      Proprietary Certificate body pointer
   Call UTIL_X509GetSignature(), and copy the signature into workspace, after Np.
 */
/* Trust in Soft annotations - __TRUSTINSOFT_ANALYZER__ */
/*@
	ensures ((\result != 0) || ((\result == 0) && \initialized(pCertFields->pCertBody)));
*/
uint32_t CCCertFieldsParse(BufferInfo32_t  *pCertInfo,
                           BufferInfo32_t  *pWorkspaceInfo,
                           CertFieldsInfo_t  *pCertFields,
                           uint32_t	**ppCertStartSign,
                           uint32_t	*pCertSignedSize,
                           CCSbX509TBSHeader_t  *pX509HeaderInfo)
{
        uint32_t rc = 0;
        uint32_t  certSignedSize = 0;
        uint32_t	certStartOffest;
        CCSbCertHeader_t *lpCertHeader;
        uint8_t *lpNp;
        CCSbSignature_t *lpSignature;
        unsigned long startAddr = (unsigned long)pCertInfo->pBuffer;
        unsigned long endAddr = (unsigned long)pCertInfo->pBuffer + pCertInfo->bufferSize + SIZE_OF_CERT_ASN1_HEADER;
        CCX509CertHeaderInfo_t   *pX509UserData = NULL;
        uint8_t		*pX509Cert = (uint8_t *)pCertInfo->pBuffer;
        BsvRsaExponentWorkspace_t  *lpWorkspaceInt;

        if ((pWorkspaceInfo == NULL) ||
            (pWorkspaceInfo->pBuffer == NULL) ||
            (pWorkspaceInfo->bufferSize < sizeof(BsvRsaExponentWorkspace_t))) {
                CC_PAL_LOG_ERR("workspace and or sizes illegal\n");
                return CC_BSV_ILLEGAL_INPUT_PARAM_ERR;
        }

        /* Trust in Soft assert - __TRUSTINSOFT_ANALYZER__ */
        /*@ assert Value: ptr_comparison: \pointer_comparable((void *)startAddr, (void *)endAddr); */
        if (startAddr > endAddr) {  /* Verify no overlap */
                CC_PAL_LOG_ERR("buffer overlap detected \n");
                return CC_BSV_ILLEGAL_INPUT_PARAM_ERR;
        }
        lpWorkspaceInt = (BsvRsaExponentWorkspace_t  *)(pWorkspaceInfo->pBuffer);

        if (pX509HeaderInfo != NULL) {
                if (((pX509HeaderInfo->pBuffer == NULL) && (pX509HeaderInfo->bufferSize != 0)) ||
                    ((pX509HeaderInfo->pBuffer != NULL) && (pX509HeaderInfo->bufferSize < sizeof(CCX509CertHeaderInfo_t)))) {
                        CC_PAL_LOG_ERR("workspace and or sizes illegal\n");
                        return CC_BSV_ILLEGAL_INPUT_PARAM_ERR;
                }
                pX509UserData = (CCX509CertHeaderInfo_t *)pX509HeaderInfo->pBuffer;
        }

        rc = SB_X509_VerifyCertTbsHeader(&pX509Cert,
                                         pCertInfo->bufferSize,
                                         &certSignedSize,
                                         &certStartOffest,
                                         (CCSbNParams_t *)&(lpWorkspaceInt->pNparams),
                                         pX509UserData,
                                         endAddr);

        if ((rc != CC_OK) ||
            (certSignedSize > pCertInfo->bufferSize - BSV_CERT_RSA_KEY_SIZE_IN_BYTES)) {
                CC_PAL_LOG_ERR("Failed SB_X509_VerifyCertTbsHeader 0x%x\n", rc);
                goto error;
        }

        *ppCertStartSign = pCertInfo->pBuffer + 1;
        *pCertSignedSize = certSignedSize;

        /* Copy the proprietary header from the extension,
           copy Np from the extension,
           get the pointer to the certificate main */
        rc = SB_X509_ParseCertExtensions(&pX509Cert,
                                         certSignedSize,
                                         &lpCertHeader,
                                         &lpNp,
                                         (uint8_t **)&pCertFields->pCertBody,
                                         &pCertFields->certBodySize,
                                         endAddr);
        if ((rc != CC_OK) ||
            (pCertFields->certBodySize > certSignedSize)) {
                CC_PAL_LOG_ERR("Failed SB_X509_ParseCertExtensions 0x%x, or bodySize 0x%x too big 0x%x\n", rc, pCertFields->certBodySize, certSignedSize);
                goto error;
        }

        /* Trust in Soft assert - __TRUSTINSOFT_ANALYZER__ */
        /*@ assert \initialized(&lpCertHeader); */
        UTIL_MemCopy((uint8_t *)&pCertFields->certHeader, (uint8_t *)lpCertHeader, sizeof(CCSbCertHeader_t));
        UTIL_MemCopy((uint8_t *)&(lpWorkspaceInt->pNparams.Np), lpNp, RSA_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_BYTES);


        lpSignature = (CCSbSignature_t *)&(lpWorkspaceInt->pDataIn);
        rc = UTIL_X509GetSignature(&pX509Cert, lpSignature, endAddr);
        if (rc != CC_OK) {
                CC_PAL_LOG_ERR("Failed UTIL_X509GetSignature 0x%x\n", rc);
                goto error;
        }

        return CC_OK;
error:
        UTIL_MemSet((uint8_t *)pCertFields, 0, sizeof(CertFieldsInfo_t));
        if (pX509UserData != NULL) {
            UTIL_MemSet((uint8_t *)pX509UserData, 0, sizeof(CCX509CertHeaderInfo_t));
        }
        *pCertSignedSize = 0;

        return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
}
