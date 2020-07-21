/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */



#ifndef UTIL_ASN1_PARSER_H
#define UTIL_ASN1_PARSER_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "cc_pal_types.h"

/* ASN1 data structure */
typedef struct
{
	uint8_t  tagId;
	uint32_t itemSize;
	uint8_t  index;

}CCSbCertAsn1Data_t;

#define UTIL_ASN1_VERIFY_NEXT_ITEM_RET(address, size, endAddress){ \
    if ( ((unsigned long)address > endAddress) || (unsigned long)size > (endAddress-(unsigned long)address) ){ \
            CC_PAL_LOG_ERR("Certificate pointer is beyond the allowed limit\n");\
            return CC_SB_X509_CERT_PARSE_ILLEGAL_VAL;\
    }\
}\

#define UTIL_ASN1_GET_NEXT_ITEM_RET(address, size, endAddress){ \
    UTIL_ASN1_VERIFY_NEXT_ITEM_RET(address, size, endAddress); \
    (address += size); \
}\

/**
 * @brief This function reads ASN1 string and verify its tag
 *
 *
 * @param[in] pInStr - the ASN1 string to read from
 * @param[in] pAsn1Data - output the asn1 fields
 * @param[in] tag - tag to comapre to
 *
 * @return CCError_t - On success the value CC_OK is returned, otherwise failure
 */
CCError_t UTIL_Asn1ReadItemVerifyTag(uint8_t *pInStr, CCSbCertAsn1Data_t *pAsn1Data, uint8_t tag);

/**
 * @brief This function reads ASN1 string, verify its tag and fw the str pointer
 *
 *
 * @param[in] ppInStr - the ASN1 string to read from
 * @param[in] pAsn1Data - output the asn1 fields
 * @param[in] tag - tag to comapre to
 *
 * @return CCError_t - On success the value CC_OK is returned, otherwise failure
 */
CCError_t UTIL_Asn1ReadItemVerifyTagFW(uint8_t **ppInStr, CCSbCertAsn1Data_t *pAsn1Data, uint8_t tag, unsigned long endAddress);

#ifdef __cplusplus
}
#endif

#endif



