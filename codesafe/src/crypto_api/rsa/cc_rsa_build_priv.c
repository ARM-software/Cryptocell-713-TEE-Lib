/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

/************* Include Files ****************/

#include "cc_pal_mem.h"
#include "cc_common.h"
#include "cc_common_math.h"
#include "cc_rsa_error.h"
#include "cc_rsa_local.h"
#include "cc_util_int_defs.h"

/************************ Defines ******************************/

/************************ Enums ******************************/

/************************ Typedefs ******************************/

/************************ Global Data ******************************/

/************************ Public Functions ******************************/


#if !defined(_INTERNAL_CC_NO_RSA_DECRYPT_SUPPORT) && !defined(_INTERNAL_CC_NO_RSA_SIGN_SUPPORT)
/******************************************************************************************
   @brief CC_RsaGetPrivKey gets the D,e,n of private key from the database.

   @param[in] UserPrivKey_ptr - A pointer to the private key structure.
			       This structure is used as input to the CC_RsaPrimDecrypt API.

   @param[out] PrivExponent_ptr - A pointer to the exponent stream of bytes (Big-Endian format)

   @param[in/out] PrivExponentSize - the size of the exponent buffer in bytes , it is updated to the
		  actual size of the exponent, in bytes.

   @param[out] PubExponent_ptr - a pointer to the public exponent stream of bytes ( Big endian ).

   @param[in/out] PubExponentSize - the size of the exponent buffer in bytes , it is updated to the
		  actual size of the exponent, in bytes.

   @param[out] Modulus_ptr  - A pointer to the modulus stream of bytes (Big-Endian format).
			   The MS (most significant) bit must be set to '1'.

   @param[in/out] ModulusSize_ptr  - the size of the modulus buffer in bytes , it is updated to the
		  actual size of the modulus, in bytes.
*/
CEXPORT_C CCError_t CC_RsaGetPrivKey(CCRsaUserPrivKey_t *UserPrivKey_ptr,
					   uint8_t             *PrivExponent_ptr,
					   uint16_t            *PrivExponentSize_ptr,
					   uint8_t             *PubExponent_ptr,
					   uint16_t            *PubExponentSize_ptr,
					   uint8_t             *Modulus_ptr,
					   uint16_t            *ModulusSize_ptr )
{
	/* LOCAL DECLERATIONS */

	/* the size in bytes of the modulus and the exponent */
	uint32_t nSizeInBytes;
	uint32_t dSizeInBytes;
	uint32_t eSizeInBytes;
	uint32_t regVal;

	/* the public key database pointer */
	CCRsaPrivKey_t *PrivKey_ptr;

	CCError_t Error;

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

	/* ................. checking the validity of the pointer arguments ....... */
	/* ------------------------------------------------------------------------ */

	/* ...... checking the key database handle pointer .................... */
	if (UserPrivKey_ptr == NULL)
		return CC_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR;

	/* ...... checking the validity of the private exponent pointer ............... */
	if (PrivExponent_ptr == NULL || PrivExponentSize_ptr == NULL || PubExponent_ptr == NULL || PubExponentSize_ptr == NULL){
		return CC_RSA_INVALID_EXPONENT_POINTER_ERROR;
	}

	/* ...... checking the validity of the modulus pointer .............. */
	if (Modulus_ptr == NULL || ModulusSize_ptr == NULL){
		return CC_RSA_INVALID_MODULUS_POINTER_ERROR;
	}

	/* if the users TAG is illegal return an error - the context is invalid */
	if (UserPrivKey_ptr->valid_tag != CC_RSA_PRIV_KEY_VALIDATION_TAG)
		return CC_RSA_PRIV_KEY_VALIDATION_TAG_ERROR;

	/* ...... checking the exponent size ................................ */

	/* setting the pointer to the key database */
	PrivKey_ptr = ( CCRsaPrivKey_t * )UserPrivKey_ptr->PrivateKeyDbBuff;

	if (PrivKey_ptr->OperationMode != CC_RSA_NoCrt) {
		return CC_RSA_WRONG_PRIVATE_KEY_TYPE;
	}

	/* calculating the required size in bytes */
	nSizeInBytes = CALC_FULL_BYTES(PrivKey_ptr->nSizeInBits);
	dSizeInBytes = CALC_FULL_BYTES(PrivKey_ptr->PriveKeyDb.NonCrt.dSizeInBits);
	eSizeInBytes = CALC_FULL_BYTES(PrivKey_ptr->PriveKeyDb.NonCrt.eSizeInBits);

	/* if the size of the modulous is to small return error */
	if (nSizeInBytes > *ModulusSize_ptr)
		return CC_RSA_INVALID_MODULUS_SIZE;

	if (eSizeInBytes > *PubExponentSize_ptr)
		return CC_RSA_INVALID_EXPONENT_SIZE;

	/* if the size of the exponent is to small return error */
	if (dSizeInBytes > *PrivExponentSize_ptr)
		return CC_RSA_INVALID_EXPONENT_SIZE;

	/* .............. loading the output arguments and buffers ............... */
	/* ----------------------------------------------------------------------- */

	/* loading the the buffers */
	Error = CC_CommonReverseMemcpy( Modulus_ptr , (uint8_t*)PrivKey_ptr->n , nSizeInBytes );
	if (Error != CC_OK)
		return Error;

	Error = CC_CommonConvertLswMswWordsToMsbLsbBytes( PubExponent_ptr , *PubExponentSize_ptr, PrivKey_ptr->PriveKeyDb.NonCrt.e ,
						       eSizeInBytes );
	if (Error != CC_OK)
		return Error;


	Error = CC_CommonReverseMemcpy( PrivExponent_ptr , (uint8_t*)PrivKey_ptr->PriveKeyDb.NonCrt.d , dSizeInBytes );
	if (Error != CC_OK)
		return Error;

	/* updating the buffer sizes */
	*ModulusSize_ptr  = (uint16_t)nSizeInBytes;

	*PubExponentSize_ptr = (uint16_t)eSizeInBytes;

	*PrivExponentSize_ptr = (uint16_t)dSizeInBytes;

	return CC_OK;

}/* END OF CC_RsaGetPrivKey */



/******************************************************************************************

   @brief CC_RsaGetPrivKeyCRT exports a CCRsaPrivKey_t structure data

   @param[In] UserPrivKey_ptr - a pointer to the public key structure. this structure will be used as
			    an input to the CC_RsaPrimDecrypt API.

   @param[out] P_ptr - a pointer to the first factor stream of bytes ( Big endian ).
   @param[in/out] PSize_ptr - the size of the first factor buffer in bytes , it is updated to the
		  actual size of the first factor, in bytes.
   @param[out] Q_ptr - a pointer to the second factor stream of bytes ( Big endian ).
   @param[in/out] QSize_ptr - the size of the second factor buffer in bytes , it is updated to the
		  actual size of the second factor, in bytes.
   @param[out] dP_ptr - a pointer to the first factors CRT exponent stream of bytes ( Big endian ).
   @param[in/out] dPSize_ptr - the size of the first factor exponent buffer in bytes , it is updated to the
		  actual size of the first factor exponent, in bytes.
   @param[out] dQ_ptr - a pointer to the second factors CRT exponent stream of bytes ( Big endian ).
   @param[in/out] dQSize_ptr - the size of the second factors CRT exponent buffer in bytes , it is updated to the
		  actual size of the second factors CRT exponent, in bytes.
   @param[out] qInv_ptr - a pointer to the first CRT coefficient stream of bytes ( Big endian ).
   @param[in/out] qInvSize_ptr -  the size of the first CRT coefficient buffer in bytes , it is updated to the
		  actual size of the first CRT coefficient, in bytes.
*/

CEXPORT_C CCError_t CC_RsaGetPrivKeyCRT(CCRsaUserPrivKey_t *UserPrivKey_ptr,
					      uint8_t *P_ptr,
					      uint16_t *PSize_ptr,
					      uint8_t *Q_ptr,
					      uint16_t *QSize_ptr,
					      uint8_t *dP_ptr,
					      uint16_t *dPSize_ptr,
					      uint8_t *dQ_ptr,
					      uint16_t *dQSize_ptr,
					      uint8_t *qInv_ptr,
					      uint16_t *qInvSize_ptr)
{
	/* LOCAL DECLERATIONS */

	/* the size in bytes of the exponents and factors */
	uint32_t PSizeInBytes;
	uint32_t QSizeInBytes;
	uint32_t dPSizeInBytes;
	uint32_t dQSizeInBytes;
	uint32_t qInvSizeInBytes;
	uint32_t regVal;

	/* the public key database pointer */
	CCRsaPrivKey_t *PrivKey_ptr;

	CCError_t Error;

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


	/* FUNCTION DECLERATIONS */
	/* ................. checking the validity of the pointer arguments ....... */
	/* ------------------------------------------------------------------------ */

	/* ...... checking the key database handle pointer .................... */
	if (UserPrivKey_ptr == NULL)
		return CC_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR;

	/* checking the first factor pointer validity */
	if (P_ptr == NULL || PSize_ptr == NULL ){
		return CC_RSA_INVALID_CRT_FIRST_FACTOR_POINTER_ERROR;
	}

	/* checking the second factor pointer validity */
	if (Q_ptr == NULL || QSize_ptr == NULL){
		return CC_RSA_INVALID_CRT_SECOND_FACTOR_POINTER_ERROR;
	}

	/* checking the first factor exponent pointer validity */
	if (dP_ptr == NULL || dPSize_ptr == NULL){
		return CC_RSA_INVALID_CRT_FIRST_FACTOR_EXP_PTR_ERROR;
	}

	/* checking the second factor exponent pointer validity */
	if (dQ_ptr == NULL || dQSize_ptr == NULL){
		return CC_RSA_INVALID_CRT_SECOND_FACTOR_EXP_PTR_ERROR;
	}

	/* checking the CRT coefficient */
	if (qInv_ptr == NULL || qInvSize_ptr == NULL){
		return CC_RSA_INVALID_CRT_COEFFICIENT_PTR_ERROR;
	}

	/* if the users TAG is illegal return an error - the context is invalid */
	if (UserPrivKey_ptr->valid_tag != CC_RSA_PRIV_KEY_VALIDATION_TAG)

		return CC_RSA_PRIV_KEY_VALIDATION_TAG_ERROR;

	/* ...... checking the exponent size ................................ */

	/* setting the pointer to the key database */
	PrivKey_ptr = ( CCRsaPrivKey_t * )UserPrivKey_ptr->PrivateKeyDbBuff;

	if (PrivKey_ptr->OperationMode != CC_RSA_Crt) {
		return CC_RSA_WRONG_PRIVATE_KEY_TYPE;
	}


	PSizeInBytes =  CALC_FULL_BYTES(PrivKey_ptr->PriveKeyDb.Crt.PSizeInBits);
	QSizeInBytes =  CALC_FULL_BYTES(PrivKey_ptr->PriveKeyDb.Crt.QSizeInBits);
	dPSizeInBytes = CALC_FULL_BYTES(PrivKey_ptr->PriveKeyDb.Crt.dPSizeInBits);
	dQSizeInBytes = CALC_FULL_BYTES(PrivKey_ptr->PriveKeyDb.Crt.dQSizeInBits);
	qInvSizeInBytes = CALC_FULL_BYTES(PrivKey_ptr->PriveKeyDb.Crt.qInvSizeInBits);


	/* Check that the input buffer are sufficient. */
	if (PSizeInBytes > *PSize_ptr) {
		return CC_RSA_INVALID_CRT_FIRST_FACTOR_SIZE_ERROR;
	}

	if (QSizeInBytes > *QSize_ptr) {
		return CC_RSA_INVALID_CRT_SECOND_FACTOR_SIZE_ERROR;
	}

	if (dPSizeInBytes > *dPSize_ptr) {
		return CC_RSA_INVALID_CRT_FIRST_FACTOR_EXP_SIZE_ERROR;
	}

	if (dQSizeInBytes > *dQSize_ptr) {
		return CC_RSA_INVALID_CRT_SECOND_FACTOR_EXP_SIZE_ERROR;
	}

	if (qInvSizeInBytes > *qInvSize_ptr) {
		return CC_RSA_INVALID_CRT_COEFFICIENT_SIZE_ERROR;
	}

	/* copy the verctors to the buffers. */
	Error = CC_CommonReverseMemcpy( P_ptr,(uint8_t*)PrivKey_ptr->PriveKeyDb.Crt.P, PSizeInBytes );
	if (Error != CC_OK)
		return Error;

	Error = CC_CommonReverseMemcpy( Q_ptr,(uint8_t*)PrivKey_ptr->PriveKeyDb.Crt.Q, QSizeInBytes );
	if (Error != CC_OK)
		return Error;

	Error = CC_CommonReverseMemcpy( dP_ptr, (uint8_t*)PrivKey_ptr->PriveKeyDb.Crt.dP, dPSizeInBytes );
	if (Error != CC_OK)
		return Error;

	Error = CC_CommonReverseMemcpy( dQ_ptr, (uint8_t*)PrivKey_ptr->PriveKeyDb.Crt.dQ, dQSizeInBytes );
	if (Error != CC_OK)
		return Error;

	Error = CC_CommonReverseMemcpy( qInv_ptr, (uint8_t*)PrivKey_ptr->PriveKeyDb.Crt.qInv, qInvSizeInBytes );
	if (Error != CC_OK)
		return Error;

	*PSize_ptr = (uint16_t)PSizeInBytes;
	*QSize_ptr = (uint16_t)QSizeInBytes;
	*dPSize_ptr = (uint16_t)dPSizeInBytes;
	*dQSize_ptr = (uint16_t)dQSizeInBytes;
	*qInvSize_ptr = (uint16_t)qInvSizeInBytes;

	return CC_OK;

}/* END OF CC_RsaGetPrivKeyCRT */

#endif /*!defined(_INTERNAL_CC_NO_RSA_DECRYPT_SUPPORT) && !defined(_INTERNAL_CC_NO_RSA_SIGN_SUPPORT)*/

