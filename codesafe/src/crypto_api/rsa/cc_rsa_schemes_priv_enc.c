/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

/************* Include Files ****************/
#include "cc_pal_mem.h"
#include "cc_pal_types.h"
#include "cc_rsa_error.h"
#include "cc_hash_defs.h"
#include "cc_hash_error.h"
#include "cc_rsa_local.h"
#include "cc_rsa_prim.h"
#include "cc_fips_defs.h"
#include "cc_util_int_defs.h"

/************************ Defines ****************************/

/************************ Enums ******************************/

/************************ Typedefs ***************************/

/************************ Global Data *************************/

#ifdef DEBUG_OAEP_SEED
#include "CRYS_RSA_PSS21_defines.h"
extern uint8_t SaltDB[NUM_OF_SETS_TEST_VECTORS][NUM_OF_TEST_VECTOR_IN_SET][CC_RSA_PSS_SALT_LENGTH];
extern uint16_t Global_Set_Index;
extern uint16_t Global_vector_Index;
#endif

/************* Private function prototype ****************/

#if !defined(_INTERNAL_CC_NO_RSA_ENCRYPT_SUPPORT) && !defined(_INTERNAL_CC_NO_RSA_VERIFY_SUPPORT)

/**********************************************************************************************************/
/*!
@brief This function implements the a private encrypt operation.
       This function combines the RSA decryption primitive and the
       EMSA-PKCS1-v1_5 encoding method, to provide an RSA-based encryption
       method.

@return CC_OK on success.
@return A non-zero value from cc_rsa_error.h on failure.
*/
CEXPORT_C CCError_t CC_RsaPkcs1v15PrivateEncrypt(
			CCRsaUserPrivKey_t  *UserPrivKey_ptr,
			CCRsaPrimeData_t  *PrimeData_ptr,
			uint8_t           *DataIn_ptr,
			uint16_t           DataInSize,
			uint8_t            *Output_ptr)
{
	/* FUNCTION DECLARATIONS */

	CCError_t Error = CC_OK;
    uint32_t regVal;
	/*The modulus size in Bytes*/
	uint16_t K;

	/*In order to save stack memory place -
	 * It is required that the Output_ptr is at least the size of the modulus
	 * It is also required that the RSA computation is done in-place */
	uint8_t *EB_buff = Output_ptr;
	CCRsaPrivKey_t *PrivKey_ptr;
	uint32_t PSSize;

	CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* The function should refuse to operate if the secure disable bit is set */
    CC_UTIL_IS_SECURE_DISABLE_FLAG_SET(regVal);
    if (regVal == SECURE_DISABLE_FLAG_SET) {
        return CC_RSA_SD_ENABLED_ERR;
    }

    /* The function should refuse to operate if the Fatal Error bit is set */
    CC_UTIL_IS_FATAL_ERROR_SET(regVal);
    if (regVal == FATAL_ERROR_FLAG_SET) {
        return CC_RSA_FATAL_ERR_IS_LOCKED_ERR;
    }


	/* if the users context pointer is DX_NULL return an error */
	if (UserPrivKey_ptr == NULL)
		return CC_RSA_INVALID_PUB_KEY_STRUCT_POINTER_ERROR;

	/* checking the Prime Data pointer */
	if (PrimeData_ptr == NULL)
		return CC_RSA_PRIM_DATA_STRUCT_POINTER_INVALID;

	/* if the users Data In pointer is illegal return an error */
	/* note - it is allowed to encrypt a message of size zero ; only on this case a NULL is allowed */
	if (DataIn_ptr == NULL && DataInSize != 0)
		return CC_RSA_DATA_POINTER_INVALID_ERROR;

	/*If the output pointer is DX_NULL return Error*/
	if (Output_ptr == NULL)
		return CC_RSA_INVALID_OUTPUT_POINTER_ERROR;

	PrivKey_ptr = (CCRsaPrivKey_t *)UserPrivKey_ptr->PrivateKeyDbBuff;

	if (UserPrivKey_ptr->valid_tag != CC_RSA_PRIV_KEY_VALIDATION_TAG)
		return CC_RSA_PRIV_KEY_VALIDATION_TAG_ERROR;

	/* .................. initializing local variables ................... */
	/* ------------------------------------------------------------------- */

	/*Initialize K with the modulus size in Bytes*/
	K = ((uint16_t)PrivKey_ptr->nSizeInBits+ 7)/8;

#ifdef DEBUG
	/*Initialize the Output_ptr to Zero*/
	CC_PalMemSet(EB_buff, 0, K);
#endif

	/*-------------------------------------------------------*
	 * Perform Encoding and Encryption accordimg to PKCS1 	 *
	 * Versions:  VER15                                      *
	 *-------------------------------------------------------*/

	/*-------------------------------------------------------*
	 * Step 1 : Check modulus and data sizes         	 *
	 *-------------------------------------------------------*/
	/*Check the modulus size is legal*/
	if (K < 3 + PS_MIN_LEN)
		return CC_RSA_INVALID_MODULUS_SIZE;

	if (DataInSize + 3 + PS_MIN_LEN > K )
		return CC_RSA_INVALID_MESSAGE_DATA_SIZE;
	/* size of PS buffer, it is >= PS_MIN_LEN  */
	PSSize = K -  3 - DataInSize;

	/*-------------------------------------------------------*
	 * Step 2 :  Encode the message                          *
	 *                                                       *
	 *   formating for EMSA-PKCS1-v1_5:                      *
	 *          00 || 01 || PS || 00 || T   	         *
	 *-------------------------------------------------------*/
	EB_buff[0]=0x00; /*set the 00 */
	EB_buff[1]=0x01; /*Block type for EME-PKCS1-v1_5*/

	CC_PalMemSet(&EB_buff[2], 0xFF, PSSize);

	/* 0-byte after PS */
	EB_buff[K-DataInSize-1] = 0x00;
	/* Copy the message data */
	CC_PalMemCopy(&EB_buff[K-DataInSize], DataIn_ptr, DataInSize);

	/*-------------------------------------------*/
	/* Step 3 : RSA computation                  */
	/*-------------------------------------------*/

	Error = CC_RsaPrimDecrypt(UserPrivKey_ptr,
				      PrimeData_ptr,
				      EB_buff,
				      K,
				      Output_ptr);

	return Error;
}
#endif /*!defined(_INTERNAL_CC_NO_RSA_ENCRYPT_SUPPORT) && !defined(_INTERNAL_CC_NO_RSA_VERIFY_SUPPORT)*/



