/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _CC_AESGCM_ERROR_H
#define _CC_AESGCM_ERROR_H


#include "cc_error.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*!
@file
@brief This file contains the definitions of the CryptoCell AES-GCM errors.
*/

/*!
 @addtogroup cc_aesgcm_error
 @{
*/

/************************ Defines ******************************/

/*! CryptoCell AESGCM module errors. CC_AESGCM_MODULE_ERROR_BASE = 0x00F02700 */
/*! Invalid context pointer. */
#define CC_AESGCM_INVALID_USER_CONTEXT_POINTER_ERROR	(CC_AESGCM_MODULE_ERROR_BASE + 0x00UL)
/*! Illegal context size. */
#define CC_AESGCM_CONTEXT_SIZES_ERROR		   	        (CC_AESGCM_MODULE_ERROR_BASE + 0x01UL)
/*! Invalid encryption mode. */
#define CC_AESGCM_INVALID_ENCRYPT_MODE_ERROR            (CC_AESGCM_MODULE_ERROR_BASE + 0x02UL)
/*! Illegal key size. */
#define CC_AESGCM_ILLEGAL_KEY_SIZE_ERROR                (CC_AESGCM_MODULE_ERROR_BASE + 0x03UL)
/*! Invalid key pointer. */
#define CC_AESGCM_INVALID_KEY_POINTER_ERROR             (CC_AESGCM_MODULE_ERROR_BASE + 0x04UL)
/*! Context is corrupted. */
#define CC_AESGCM_USER_CONTEXT_CORRUPTED_ERROR          (CC_AESGCM_MODULE_ERROR_BASE + 0x05UL)
/*! Invalid data in pointer. */
#define CC_AESGCM_DATA_IN_POINTER_INVALID_ERROR         (CC_AESGCM_MODULE_ERROR_BASE + 0x06UL)
/*! Invalid data out pointer. */
#define CC_AESGCM_DATA_OUT_POINTER_INVALID_ERROR        (CC_AESGCM_MODULE_ERROR_BASE + 0x07UL)
/*! Illegal data in size. */
#define CC_AESGCM_DATA_IN_SIZE_ILLEGAL                  (CC_AESGCM_MODULE_ERROR_BASE + 0x08UL)
/*! Illegal data in or data out address. */
#define CC_AESGCM_DATA_OUT_DATA_IN_OVERLAP_ERROR        (CC_AESGCM_MODULE_ERROR_BASE + 0x09UL)
/*! Illegal data out size. */
#define CC_AESGCM_DATA_OUT_SIZE_INVALID_ERROR           (CC_AESGCM_MODULE_ERROR_BASE + 0x0AUL)
/*! Illegal DMA buffer type. */
#define CC_AESGCM_ILLEGAL_DMA_BUFF_TYPE_ERROR        	(CC_AESGCM_MODULE_ERROR_BASE + 0x0BUL)
/*! Illegal parameter size. */
#define CC_AESGCM_ILLEGAL_PARAMETER_SIZE_ERROR          (CC_AESGCM_MODULE_ERROR_BASE + 0x0CUL)
/*! Invalid parameter pointer. */
#define CC_AESGCM_ILLEGAL_PARAMETER_PTR_ERROR           (CC_AESGCM_MODULE_ERROR_BASE + 0x0DUL)
/*! Invalid data type. */
#define CC_AESGCM_ILLEGAL_DATA_TYPE_ERROR               (CC_AESGCM_MODULE_ERROR_BASE + 0x0EUL)
/*! GCM Tag compare failure. */
#define CC_AESGCM_GCM_TAG_INVALID_ERROR                 (CC_AESGCM_MODULE_ERROR_BASE + 0x0FUL)
/*! Illegal operation. */
#define CC_AESGCM_LAST_BLOCK_NOT_PERMITTED_ERROR        (CC_AESGCM_MODULE_ERROR_BASE + 0x10UL)
/*! Illegal parameter. */
#define CC_AESGCM_ILLEGAL_PARAMETER_ERROR               (CC_AESGCM_MODULE_ERROR_BASE + 0x11UL)
/*! Text data input size is incorrect. */
#define CC_AESGCM_NOT_ALL_DATA_WAS_PROCESSED_ERROR      (CC_AESGCM_MODULE_ERROR_BASE + 0x12UL)
/*! Illegal Tag size. */
#define CC_AESGCM_ILLEGAL_TAG_SIZE_ERROR		        (CC_AESGCM_MODULE_ERROR_BASE + 0x13UL)
/*! Illegal parameters. */
#define CC_AESGCM_ILLEGAL_PARAMS_ERROR		   	        (CC_AESGCM_MODULE_ERROR_BASE + 0x14UL)
/*! Invalid IV pointer. */
#define CC_AESGCM_IV_POINTER_INVALID_ERROR				(CC_AESGCM_MODULE_ERROR_BASE + 0x15UL)
/*! Illegal IV size. */
#define CC_AESGCM_IV_SIZE_ILLEGAL                  		(CC_AESGCM_MODULE_ERROR_BASE + 0x16UL)
/*! Invalid aad pointer. */
#define CC_AESGCM_AAD_POINTER_INVALID_ERROR				(CC_AESGCM_MODULE_ERROR_BASE + 0x17UL)
/*! Illegal AAD size. */
#define CC_AESGCM_AAD_SIZE_ILLEGAL						(CC_AESGCM_MODULE_ERROR_BASE + 0x18UL)
/*! Invalid tag pointer. */
#define CC_AESGCM_TAG_POINTER_INVALID_ERROR				(CC_AESGCM_MODULE_ERROR_BASE + 0x19UL)
/*! Illegal tag size. */
#define CC_AESGCM_TAG_SIZE_ILLEGAL						(CC_AESGCM_MODULE_ERROR_BASE + 0x1AUL)
/*! Additional data was already processed (must be processed only once). */
#define CC_AESGCM_ADATA_WAS_PROCESSED_ERROR             (CC_AESCCM_MODULE_ERROR_BASE + 0x1BUL)
/*! AES-GCM is not supported. */
#define CC_AESGCM_IS_NOT_SUPPORTED						(CC_AESGCM_MODULE_ERROR_BASE + 0xFFUL)


/************************ Enums ********************************/

/************************ Typedefs  ****************************/

/************************ Structs  *****************************/

/************************ Public Variables *********************/

/************************ Public Functions *********************/

#ifdef __cplusplus
}
#endif
/**
@}
 */


#endif /* _CC_AESGCM_ERROR_H */


