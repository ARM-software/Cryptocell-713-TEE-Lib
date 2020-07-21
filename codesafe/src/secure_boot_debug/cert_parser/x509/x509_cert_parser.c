/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#define CC_PAL_LOG_CUR_COMPONENT CC_LOG_MASK_SECURE_BOOT

/************* Include Files ****************/

#include "secureboot_stage_defs.h"
#include "secureboot_defs.h"
#include "cc_crypto_x509_defs.h"
#include "secureboot_base_func.h"
#include "util_asn1_parser.h"
#include "x509_error.h"
#include "x509_cert_parser.h"
#include "x509_extensions_parser.h"
#include "cc_pal_log.h"
#include "cc_crypto_boot_defs.h"

const uint8_t *certType2SubjectNames[CC_X509_CERT_TYPE_MAX] = {
  /*CC_X509_CERT_TYPE_MIN      */   (uint8_t *)NULL,
  /*CC_X509_CERT_TYPE_KEY      */   (uint8_t *)CC_X509_CERT_KEY_CERT,
  /*CC_X509_CERT_TYPE_CONTENT  */   (uint8_t *)CC_X509_CERT_CNT_CERT,
  /*CC_X509_CERT_TYPE_ENABLER_DBG */    (uint8_t *)CC_X509_CERT_ENABLER_CERT,
  /*CC_X509_CERT_TYPE_DEVELOPER_DBG */  (uint8_t *)CC_X509_CERT_DEVELOPER_CERT
};



/************************ Private Functions ******************************/
/* the following function verify the ASN1 tags sequences in case of strings (Issuer name and subject name) */
CCError_t UTIL_X509VerifyStr(uint8_t **pCert, uint32_t *dataSize, unsigned long endAddress)
{
    CCError_t error = CC_OK;
    CCSbCertAsn1Data_t asn1Data;

    /* read SEQ */
    error = UTIL_Asn1ReadItemVerifyTagFW(pCert, &asn1Data, CC_X509_CERT_SEQ_TAG_ID, endAddress);
    if (error != CC_OK) {
        return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
    }
    /* read SET */
    error = UTIL_Asn1ReadItemVerifyTagFW(pCert, &asn1Data, CC_X509_CERT_SET_OF_TAG_ID, endAddress);
    if (error != CC_OK) {
        return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
    }
    /* read SEQ */
    error = UTIL_Asn1ReadItemVerifyTagFW(pCert, &asn1Data, CC_X509_CERT_SEQ_TAG_ID, endAddress);
    if (error != CC_OK) {
        return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
    }
    /* OBJ ID */
    error = UTIL_Asn1ReadItemVerifyTagFW(pCert, &asn1Data, CC_X509_CERT_OBJ_IDENTIFIER_TAG_ID, endAddress);
    if (error != CC_OK) {
        return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
    }

    UTIL_ASN1_GET_NEXT_ITEM_RET(*pCert, asn1Data.itemSize, endAddress)

    /* PRINT STR ID */
    error = UTIL_Asn1ReadItemVerifyTagFW(pCert, &asn1Data, CC_X509_CERT_PRNT_STR_TAG_ID, endAddress);
    if (error != CC_OK) {
        error = UTIL_Asn1ReadItemVerifyTagFW(pCert, &asn1Data, CC_X509_CERT_UTF8_TAG_ID, endAddress);
        if (error != CC_OK) {
            return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
        }
    }
    *dataSize = asn1Data.itemSize;

    return error;
}

/* the following function verify the ASN1 tags sequences in case of strings (Issuer name and subject name) */
CCError_t UTIL_X509VerifyPubKey(uint8_t **pCert, CCSbNParams_t *pParamsN, unsigned long endAddress)
{
    CCError_t error = CC_OK;
    CCSbCertAsn1Data_t asn1Data;
    uint8_t objId[] = CC_X509_CERT_RSASSAENC_ID;
    uint8_t eVal[] = X509_RSA_E_VAL_IN_BYTES;

    /* read SEQ */
    error = UTIL_Asn1ReadItemVerifyTagFW(pCert, &asn1Data, CC_X509_CERT_SEQ_TAG_ID, endAddress);
    if (error != CC_OK)
        return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
    /* read SEQ */
    error = UTIL_Asn1ReadItemVerifyTagFW(pCert, &asn1Data, CC_X509_CERT_SEQ_TAG_ID, endAddress);
    if (error != CC_OK)
        return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
    /* OBJ ID */
    error = UTIL_Asn1ReadItemVerifyTagFW(pCert, &asn1Data, CC_X509_CERT_OBJ_IDENTIFIER_TAG_ID, endAddress);
    if ((error != CC_OK) || (asn1Data.itemSize != sizeof(objId))) {
        return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
    }
    /* verify ID */
    if ((error = UTIL_MemCmp(*pCert, objId, sizeof(objId))) != CC_TRUE){
        return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
    }
    UTIL_ASN1_GET_NEXT_ITEM_RET(*pCert, asn1Data.itemSize, endAddress);

    /* read NULL */
    error = UTIL_Asn1ReadItemVerifyTagFW(pCert, &asn1Data, CC_X509_CERT_NULL_TAG_ID, endAddress);
    if (error != CC_OK)
        return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
    UTIL_ASN1_GET_NEXT_ITEM_RET(*pCert, asn1Data.itemSize, endAddress);
    /* BIT Str */
    error = UTIL_Asn1ReadItemVerifyTag(*pCert, &asn1Data, CC_X509_CERT_BIT_STR_TAG_ID);
    if (error != CC_OK)
        return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
    UTIL_ASN1_GET_NEXT_ITEM_RET(*pCert, asn1Data.index+1, endAddress);//add 1 for unused bits
    /* SEQ */
    error = UTIL_Asn1ReadItemVerifyTagFW(pCert, &asn1Data, CC_X509_CERT_SEQ_TAG_ID, endAddress);
    if (error != CC_OK)
        return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
    /* read INT and copy the N into buffer */

    error = UTIL_Asn1ReadItemVerifyTag(*pCert, &asn1Data, CC_X509_CERT_INT_TAG_ID);
    if (error != CC_OK)
        return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
    if (asn1Data.itemSize != BSV_CERT_RSA_KEY_SIZE_IN_BYTES){
        if (asn1Data.itemSize != (BSV_CERT_RSA_KEY_SIZE_IN_BYTES + 1)){
            return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
        }
        asn1Data.index ++;
    }
    UTIL_ASN1_GET_NEXT_ITEM_RET(*pCert, asn1Data.index, endAddress);
    UTIL_MemCopy((uint8_t*)pParamsN->N, *pCert, BSV_CERT_RSA_KEY_SIZE_IN_BYTES);
    UTIL_ASN1_GET_NEXT_ITEM_RET(*pCert, BSV_CERT_RSA_KEY_SIZE_IN_BYTES, endAddress);

    /* Verify E is the expected constant */
    error = UTIL_Asn1ReadItemVerifyTagFW(pCert, &asn1Data, CC_X509_CERT_INT_TAG_ID, endAddress);
    if (error != CC_OK)
        return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;

    if (asn1Data.itemSize != sizeof(eVal)) /* verify the size of E is correct */
        return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;

    if ((error = UTIL_MemCmp(*pCert, eVal, sizeof(eVal))) != CC_TRUE){
        return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
    }
    UTIL_ASN1_GET_NEXT_ITEM_RET(*pCert, asn1Data.itemSize, endAddress);


    return CC_OK;
}

/* the following function retrieves the signature */
CCError_t UTIL_X509GetSignature(uint8_t **pCert, CCSbSignature_t *signatureP, unsigned long endAddress)
{
    CCError_t error = CC_OK;
    CCSbCertAsn1Data_t asn1Data;
    uint8_t objId[] = CC_X509_CERT_SHA256RSAPSS_ID;
    uint8_t objSha256Id[] = CC_X509_CERT_SHA256_ID;
    uint8_t objMgf1Id[] = CC_X509_CERT_MGF1_ID;

    /* read SEQ */
    error = UTIL_Asn1ReadItemVerifyTagFW(pCert, &asn1Data, CC_X509_CERT_SEQ_TAG_ID, endAddress);
    if (error != CC_OK) {
        return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
    }
    /* OBJ ID */
    error = UTIL_Asn1ReadItemVerifyTagFW(pCert, &asn1Data, CC_X509_CERT_OBJ_IDENTIFIER_TAG_ID, endAddress);
    if (error != CC_OK) {
        return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
    }
    if (asn1Data.itemSize != sizeof(objId)) {
        return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
    }
    /* verify ID */
    if ((error = UTIL_MemCmp(*pCert, objId, sizeof(objId))) != CC_TRUE){
        return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
    }
    UTIL_ASN1_GET_NEXT_ITEM_RET(*pCert, asn1Data.itemSize, endAddress);

    /* verify sha256 + PSS + mgf1 attributes signature */
    error = UTIL_Asn1ReadItemVerifyTagFW(pCert, &asn1Data, CC_X509_CERT_SEQ_TAG_ID, endAddress);
    if (error != CC_OK) {
        return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
    }
    error = UTIL_Asn1ReadItemVerifyTagFW(pCert, &asn1Data, CC_X509_CERT_CTX_SPEC_TAG_ID, endAddress);
    if (error != CC_OK) {
        return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
    }
    error = UTIL_Asn1ReadItemVerifyTagFW(pCert, &asn1Data, CC_X509_CERT_SEQ_TAG_ID, endAddress);
    if (error != CC_OK) {
        return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
    }
    /* verify sha256 */
    error = UTIL_Asn1ReadItemVerifyTagFW(pCert, &asn1Data, CC_X509_CERT_OBJ_IDENTIFIER_TAG_ID, endAddress);
    if (error != CC_OK) {
        return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
    }
    if (asn1Data.itemSize != sizeof(objSha256Id)) {
        return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
    }
    if ((error = UTIL_MemCmp(*pCert, objSha256Id, sizeof(objSha256Id))) != CC_TRUE){
        return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
    }
    UTIL_ASN1_GET_NEXT_ITEM_RET(*pCert, asn1Data.itemSize, endAddress);
    /* verify mgf1 + sha256 */
    error = UTIL_Asn1ReadItemVerifyTagFW(pCert, &asn1Data, CC_X509_CERT_CTX_SPEC_TAG1_ID, endAddress);
    if (error != CC_OK) {
        return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
    }
    error = UTIL_Asn1ReadItemVerifyTagFW(pCert, &asn1Data, CC_X509_CERT_SEQ_TAG_ID, endAddress);
    if (error != CC_OK) {
        return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
    }
    /* verify mgf1 */
    error = UTIL_Asn1ReadItemVerifyTagFW(pCert, &asn1Data, CC_X509_CERT_OBJ_IDENTIFIER_TAG_ID, endAddress);
    if (error != CC_OK) {
        return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
    }
    if (asn1Data.itemSize != sizeof(objMgf1Id)) {
        return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
    }
    if ((error = UTIL_MemCmp(*pCert, objMgf1Id, sizeof(objMgf1Id))) != CC_TRUE){
        return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
    }

    UTIL_ASN1_GET_NEXT_ITEM_RET(*pCert, asn1Data.itemSize, endAddress);
    error = UTIL_Asn1ReadItemVerifyTagFW(pCert, &asn1Data, CC_X509_CERT_SEQ_TAG_ID, endAddress);
    if (error != CC_OK) {
        return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
    }
    /* verify sha256 */
    error = UTIL_Asn1ReadItemVerifyTagFW(pCert, &asn1Data, CC_X509_CERT_OBJ_IDENTIFIER_TAG_ID, endAddress);
    if (error != CC_OK) {
        return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
    }
    if (asn1Data.itemSize != sizeof(objSha256Id)) {
        return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
    }
    if ((error = UTIL_MemCmp(*pCert, objSha256Id, sizeof(objSha256Id))) != CC_TRUE){
        return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
    }
    UTIL_ASN1_GET_NEXT_ITEM_RET(*pCert, asn1Data.itemSize, endAddress);

    /* verify last special tag size */
    error = UTIL_Asn1ReadItemVerifyTagFW(pCert, &asn1Data, CC_X509_CERT_CTX_SPEC_TAG2_ID, endAddress);
    if (error != CC_OK) {
        return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
    }
    if (asn1Data.itemSize != CC_X509_CERT_CTX_SPEC_TAG2_SIZE){
        return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
    }
    UTIL_ASN1_GET_NEXT_ITEM_RET(*pCert, asn1Data.itemSize, endAddress);
    /* BIT Str */
    error = UTIL_Asn1ReadItemVerifyTag(*pCert, &asn1Data, CC_X509_CERT_BIT_STR_TAG_ID);
    if (error != CC_OK) {
        return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
    }
    if (asn1Data.itemSize != (BSV_CERT_RSA_KEY_SIZE_IN_BYTES + 1)){
        return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
    }
    UTIL_ASN1_GET_NEXT_ITEM_RET(*pCert, asn1Data.index + 1, endAddress);//add 1 for unused bits
    // copy the signature as reversed buffer
    UTIL_ReverseMemCopy((uint8_t*)signatureP->sig, *pCert, BSV_CERT_RSA_KEY_SIZE_IN_BYTES);
    UTIL_ASN1_GET_NEXT_ITEM_RET(*pCert, asn1Data.itemSize-1, endAddress);//add 1 for unused bits

    return error;
}


/*!
 * @brief Parse and validate TBS header certificate
 *
 * @param[in] ppAsn1Cert	- pointer to X509 certificate as ASN.1 byte array
 * @param[in] certMaxSize	- certificate max size (according to certificate type)
 * @param[out] pSignCertSize 	- certificate TBS size, used for signature
 * @param[out] pTbsStartOffset - certificate TBS start offset, used for signature
 * @param[out] pOutPubKey   	- certificate public key modulus (exponent is constant)
 *
 * @return uint32_t 		- On success: the value CC_OK is returned,
 *         			  On failure: a value from x509_error.h
 */
CCError_t SB_X509_VerifyCertTbsHeader(uint8_t    **ppAsn1Cert,
				      uint32_t 		certMaxSize,
				      uint32_t   	*pSignCertSize,
				      uint32_t   	*pTbsStartOffset,
				      CCSbNParams_t  	*pOutPubKey,
				      CCX509CertHeaderInfo_t *pOutCertHeaderInfo,
				      unsigned long endAddress)
{
	uint32_t	rc = 0;
	uint32_t	strSize = 0;
	CCSbCertAsn1Data_t asn1Data;
	uint8_t 	algId[] = CC_X509_CERT_SHA256RSAPSS_ID;
	uint8_t objSha256Id[] = CC_X509_CERT_SHA256_ID;
	uint8_t objMgf1Id[] = CC_X509_CERT_MGF1_ID;
	uint32_t         notBeforeStrSize = 0;
	uint32_t         notAfterStrSize  = 0;

	/* validate inputs */
	if ((NULL == ppAsn1Cert) ||
	    (NULL == pOutPubKey) ||
	    (NULL == pSignCertSize) ||
	    (NULL == pTbsStartOffset) ||
	    (certMaxSize == 0)) {
		CC_PAL_LOG_ERR("Invalid inputs\n");
		return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
	}

	/* set default output values */
	*pSignCertSize = 0;
	*pTbsStartOffset = 0;
	UTIL_MemSet((uint8_t *)pOutPubKey, 0, sizeof(CCSbNParams_t));

	/* 1. get certificate size , validate tag + size */
	rc = UTIL_Asn1ReadItemVerifyTagFW(ppAsn1Cert, &asn1Data, CC_X509_CERT_SEQ_TAG_ID, endAddress);
	if (rc != CC_OK) {
		CC_PAL_LOG_ERR("Failed to UTIL_Asn1ReadItemVerifyTagFW 0x%x for CC_X509_CERT_SEQ_TAG_ID\n", rc);
		return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
	}

	if (asn1Data.itemSize > certMaxSize){
		CC_PAL_LOG_ERR("asn1Data.itemSize > certTypeMaxSize[certType]\n");
		return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
	}

	/* certificate signature is on all TBS */
	*pTbsStartOffset = asn1Data.index;

	/* 2. get TBS size - no need to verify size */
	rc = UTIL_Asn1ReadItemVerifyTagFW(ppAsn1Cert, &asn1Data, CC_X509_CERT_SEQ_TAG_ID, endAddress);
	if (rc != CC_OK) {
		CC_PAL_LOG_ERR("Failed to UTIL_Asn1ReadItemVerifyTagFW 0x%x for CC_X509_CERT_SEQ_TAG_ID\n", rc);
		return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
	}

	/* certificate signature is on all TBS */
	*pSignCertSize = asn1Data.itemSize + asn1Data.index;
	if (*pSignCertSize > certMaxSize ){ /* the size of the certificate to be verified cannot be bigger than certMaxSize*/
		CC_PAL_LOG_ERR("asn1Data.itemSize > certTypeMaxSize\n");
		return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
	}

	/* 3. get version and verify it is v3 */
	rc = UTIL_Asn1ReadItemVerifyTagFW(ppAsn1Cert, &asn1Data, CC_X509_CERT_CTX_SPEC_TAG_ID, endAddress);
	if (rc != CC_OK) {
		CC_PAL_LOG_ERR("Failed to UTIL_Asn1ReadItemVerifyTagFW 0x%x for CC_X509_CERT_CTX_SPEC_TAG_ID\n", rc);
		return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
	}
	rc = UTIL_Asn1ReadItemVerifyTagFW(ppAsn1Cert, &asn1Data, CC_X509_CERT_INT_TAG_ID, endAddress);
	if (rc != CC_OK) {
		CC_PAL_LOG_ERR("Failed to UTIL_Asn1ReadItemVerifyTagFW 0x%x for CC_X509_CERT_INT_TAG_ID\n", rc);
		return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
	}

	if (**ppAsn1Cert != CC_X509_CERT_VERSION ){
		CC_PAL_LOG_ERR("Ilegal certificate version 0x%x\n", **ppAsn1Cert);
		return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
	}

	UTIL_ASN1_GET_NEXT_ITEM_RET(*ppAsn1Cert, asn1Data.itemSize, endAddress);

	/* 4. get the serial number */
    rc = UTIL_Asn1ReadItemVerifyTagFW(ppAsn1Cert, &asn1Data, CC_X509_CERT_INT_TAG_ID, endAddress);
    if (rc != CC_OK) {
        CC_PAL_LOG_ERR("Failed to CC_X509_CERT_INT_TAG_ID for serial number\n");
        return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
    }
    /* ASN.1 data encoding may use a NULL byte prefix. Verify serial number item size is no longer than 5 Bytes */
    /* Note, item size may be saved in asn1Data format less then 4 bytes! */
    if (asn1Data.itemSize > (sizeof(uint32_t) + 1)){
            CC_PAL_LOG_ERR("Ilegal serial number item size\n");
            return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
    }
    /* skip NULL byte in case of prefix */
    if (asn1Data.itemSize == (sizeof(uint32_t) + 1)){
            UTIL_ASN1_GET_NEXT_ITEM_RET(*ppAsn1Cert, 1, endAddress);
            asn1Data.itemSize = asn1Data.itemSize-1;
    }
    if (pOutCertHeaderInfo != NULL){
        UTIL_MemCopy((uint8_t*)&(pOutCertHeaderInfo->serialNum), (uint8_t*)*ppAsn1Cert, asn1Data.itemSize);
#ifndef BIG__ENDIAN
        UTIL_ReverseBuff((uint8_t*)&(pOutCertHeaderInfo->serialNum),asn1Data.itemSize);
#endif
        pOutCertHeaderInfo->setSerialNum = 1;
    }
    /* skip ASN1 Data element */
    UTIL_ASN1_GET_NEXT_ITEM_RET(*ppAsn1Cert,asn1Data.itemSize, endAddress);

	/* 5. get the alg id and verify it */
	rc = UTIL_Asn1ReadItemVerifyTagFW(ppAsn1Cert, &asn1Data, CC_X509_CERT_SEQ_TAG_ID, endAddress);
	if (rc != CC_OK) {
		CC_PAL_LOG_ERR("Failed to CC_X509_CERT_SEQ_TAG_ID for algId\n");
		return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
	}
	rc = UTIL_Asn1ReadItemVerifyTagFW(ppAsn1Cert, &asn1Data, CC_X509_CERT_OBJ_IDENTIFIER_TAG_ID, endAddress);
	if (rc != CC_OK || asn1Data.itemSize != sizeof(algId)) {
		CC_PAL_LOG_ERR("Failed to CC_X509_CERT_OBJ_IDENTIFIER_TAG_ID for algId\n");
		return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
	}
	if ((rc = UTIL_MemCmp(*ppAsn1Cert, algId, sizeof(algId))) != CC_TRUE) {
		CC_PAL_LOG_ERR("Failed to UTIL_MemCmp algId\n");
		return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
	}
	UTIL_ASN1_GET_NEXT_ITEM_RET(*ppAsn1Cert, asn1Data.itemSize, endAddress);

	/* verify sha256 + PSS + mgf1 attributes signature */
	rc = UTIL_Asn1ReadItemVerifyTagFW(ppAsn1Cert, &asn1Data, CC_X509_CERT_SEQ_TAG_ID, endAddress);
	if (rc != CC_OK) {
		CC_PAL_LOG_ERR("Failed to CC_X509_CERT_SEQ_TAG_ID for PSS\n");
		return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
	}
	rc = UTIL_Asn1ReadItemVerifyTagFW(ppAsn1Cert, &asn1Data, CC_X509_CERT_CTX_SPEC_TAG_ID, endAddress);
	if (rc != CC_OK) {
		return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
	}
	rc = UTIL_Asn1ReadItemVerifyTagFW(ppAsn1Cert, &asn1Data, CC_X509_CERT_SEQ_TAG_ID, endAddress);
	if (rc != CC_OK) {
		return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
	}
	/* verify sha256 */
	rc = UTIL_Asn1ReadItemVerifyTagFW(ppAsn1Cert, &asn1Data, CC_X509_CERT_OBJ_IDENTIFIER_TAG_ID, endAddress);
	if ((rc != CC_OK) || (asn1Data.itemSize != sizeof(objSha256Id))) {
		return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
	}
	if ((rc = UTIL_MemCmp(*ppAsn1Cert, objSha256Id, sizeof(objSha256Id))) != CC_TRUE){
		return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
	}
	UTIL_ASN1_GET_NEXT_ITEM_RET(*ppAsn1Cert, asn1Data.itemSize, endAddress);
	/* verify mgf1 + sha256 */
	rc = UTIL_Asn1ReadItemVerifyTagFW(ppAsn1Cert, &asn1Data, CC_X509_CERT_CTX_SPEC_TAG1_ID, endAddress);
	if (rc != CC_OK) {
		return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
	}
	rc = UTIL_Asn1ReadItemVerifyTagFW(ppAsn1Cert, &asn1Data, CC_X509_CERT_SEQ_TAG_ID, endAddress);
	if (rc != CC_OK) {
		return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
	}
	/* verify mgf1 */
	rc = UTIL_Asn1ReadItemVerifyTagFW(ppAsn1Cert, &asn1Data, CC_X509_CERT_OBJ_IDENTIFIER_TAG_ID, endAddress);
	if ((rc != CC_OK) || (asn1Data.itemSize != sizeof(objMgf1Id))) {
		return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
	}
	if ((rc = UTIL_MemCmp(*ppAsn1Cert, objMgf1Id, sizeof(objMgf1Id))) != CC_TRUE){
		return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
	}
	UTIL_ASN1_GET_NEXT_ITEM_RET(*ppAsn1Cert, asn1Data.itemSize, endAddress);
	rc = UTIL_Asn1ReadItemVerifyTagFW(ppAsn1Cert, &asn1Data, CC_X509_CERT_SEQ_TAG_ID, endAddress);
	if (rc != CC_OK) {
		return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
	}
	/* verify sha256 */
	rc = UTIL_Asn1ReadItemVerifyTagFW(ppAsn1Cert, &asn1Data, CC_X509_CERT_OBJ_IDENTIFIER_TAG_ID, endAddress);
	if ((rc != CC_OK) || (asn1Data.itemSize != sizeof(objSha256Id))) {
		return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
	}
	if ((rc = UTIL_MemCmp(*ppAsn1Cert, objSha256Id, sizeof(objSha256Id))) != CC_TRUE){
		return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
	}
	UTIL_ASN1_GET_NEXT_ITEM_RET(*ppAsn1Cert, asn1Data.itemSize, endAddress);

	/* verify last special tag size */
	rc = UTIL_Asn1ReadItemVerifyTagFW(ppAsn1Cert, &asn1Data, CC_X509_CERT_CTX_SPEC_TAG2_ID, endAddress);
	if (rc != CC_OK) {
		return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
	}
	if (asn1Data.itemSize != CC_X509_CERT_CTX_SPEC_TAG2_SIZE){
		return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
	}
	UTIL_ASN1_GET_NEXT_ITEM_RET(*ppAsn1Cert, asn1Data.itemSize, endAddress);

	/* 6. get the issuer name and verify it */
	rc = UTIL_X509VerifyStr(ppAsn1Cert, &strSize, endAddress);
	if (rc != CC_OK || strSize > X509_ISSUER_NAME_MAX_STRING_SIZE ) {
		CC_PAL_LOG_ERR("Failed to UTIL_X509VerifyStr for issuer Name\n");
		return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
	}
	if (pOutCertHeaderInfo != NULL){
		if (strSize>0){
			UTIL_MemCopy((uint8_t*)pOutCertHeaderInfo->IssuerName, (uint8_t*)*ppAsn1Cert, strSize);
			pOutCertHeaderInfo->IssuerName[strSize]=0;
			pOutCertHeaderInfo->setIssuerName = 1;
		} else {
			pOutCertHeaderInfo->setIssuerName = 0;
			return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
		}
	}

	UTIL_ASN1_GET_NEXT_ITEM_RET(*ppAsn1Cert, strSize, endAddress);

	/* 7. skip over the validity period */
	rc = UTIL_Asn1ReadItemVerifyTagFW(ppAsn1Cert, &asn1Data, CC_X509_CERT_SEQ_TAG_ID, endAddress);
	if (rc != CC_OK) {
		CC_PAL_LOG_ERR("Failed to CC_X509_CERT_SEQ_TAG_ID for vallidity period\n");
		return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
	}
	rc = UTIL_Asn1ReadItemVerifyTagFW(ppAsn1Cert, &asn1Data, CC_X509_CERT_UTC_TIME_TAG_ID, endAddress);
	if (rc != CC_OK || asn1Data.itemSize > X509_VALIDITY_PERIOD_MAX_STRING_SIZE) {
		CC_PAL_LOG_ERR("Failed to CC_X509_CERT_UTC_TIME_TAG_ID for notBefore\n");
		return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
	}

	if (pOutCertHeaderInfo != NULL) {
		if ((asn1Data.itemSize>0) && (asn1Data.itemSize<sizeof(pOutCertHeaderInfo->NotBeforeStr))){
			UTIL_MemCopy((uint8_t*)pOutCertHeaderInfo->NotBeforeStr, (uint8_t*)*ppAsn1Cert, asn1Data.itemSize);
			pOutCertHeaderInfo->NotBeforeStr[asn1Data.itemSize] = 0;
			notBeforeStrSize = asn1Data.itemSize;
			pOutCertHeaderInfo->setNotBeforeStr = 1;
		} else {
			pOutCertHeaderInfo->setNotBeforeStr = 0;
		}
	}

	UTIL_ASN1_GET_NEXT_ITEM_RET(*ppAsn1Cert, asn1Data.itemSize, endAddress);

	rc = UTIL_Asn1ReadItemVerifyTagFW(ppAsn1Cert, &asn1Data, CC_X509_CERT_UTC_TIME_TAG_ID, endAddress);
	if (rc != CC_OK) {
		rc = UTIL_Asn1ReadItemVerifyTagFW(ppAsn1Cert, &asn1Data, CC_X509_CERT_GENERALIZED_TIME_TAG_ID, endAddress);
		if (rc != CC_OK || asn1Data.itemSize > X509_VALIDITY_PERIOD_MAX_STRING_SIZE) {
			CC_PAL_LOG_ERR("Failed to CC_X509_CERT_GENERALIZED_TIME_TAG_ID for notAfter\n");
			return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
		}
	}
	if (pOutCertHeaderInfo != NULL) {
		if ((asn1Data.itemSize>0) && (asn1Data.itemSize<sizeof(pOutCertHeaderInfo->NotAfterStr))){
			UTIL_MemCopy((uint8_t*)pOutCertHeaderInfo->NotAfterStr, (uint8_t*)*ppAsn1Cert, asn1Data.itemSize);
			pOutCertHeaderInfo->NotAfterStr[asn1Data.itemSize] = 0;
			notAfterStrSize = asn1Data.itemSize;
			pOutCertHeaderInfo->setNotAfterStr = 1;
		} else {
			pOutCertHeaderInfo->setNotAfterStr = 0;
		}

		rc = CC_PalVerifyCertValidity(pOutCertHeaderInfo->NotBeforeStr,
			notBeforeStrSize,
			pOutCertHeaderInfo->setNotBeforeStr,
			pOutCertHeaderInfo->NotAfterStr,
			notAfterStrSize,
			pOutCertHeaderInfo->setNotAfterStr);

			if (rc != CC_OK) {
				CC_PAL_LOG_ERR("Failed to verify certificate validity\n");
				return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
			}
	}

	UTIL_ASN1_GET_NEXT_ITEM_RET(*ppAsn1Cert, asn1Data.itemSize, endAddress);

	/* 8. get the subject name and verify it */
	rc = UTIL_X509VerifyStr(ppAsn1Cert, &strSize, endAddress);
	if (rc != CC_OK || strSize > X509_SUBJECT_NAME_MAX_STRING_SIZE) {
		CC_PAL_LOG_ERR("Failed to UTIL_X509VerifyStr for subject Name\n");
		return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
	}

	if (pOutCertHeaderInfo != NULL){
		     UTIL_MemCopy((uint8_t*)pOutCertHeaderInfo->SubjectName, (uint8_t*)*ppAsn1Cert, strSize);
			 pOutCertHeaderInfo->SubjectName[strSize]=0;
		     pOutCertHeaderInfo->setSubjectName = 1;
	}
	UTIL_ASN1_GET_NEXT_ITEM_RET(*ppAsn1Cert, strSize, endAddress);

	/* 9. get the pub key */
	rc = UTIL_X509VerifyPubKey(ppAsn1Cert, pOutPubKey, endAddress);
	if (rc != CC_OK) {
		CC_PAL_LOG_ERR("Failed to UTIL_X509VerifyPubKey\n");
		return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;
	}


	return CC_OK;
}
