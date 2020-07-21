/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


/************* Include Files ****************/
#include "cc_pal_mem.h"
#include "cc_ecpki_types.h"
#include "cc_common.h"
#include "cc_common_math.h"
#include "cc_ecpki_error.h"
#include "cc_ecpki_local.h"
#include "pki.h"
#include "ec_wrst.h"
#include "cc_ecpki_types.h"
#include "cc_ecpki_error.h"
#include "cc_fips_defs.h"
#include "cc_ecpki_domains_defs.h"
#include "cc_util_int_defs.h"

/************************ Defines ***************************************/

/************************ Enums *****************************************/

/************************ Typedefs **************************************/

/************************ Global Data ***********************************/

extern const getDomainFuncP ecDomainsFuncP[CC_ECPKI_DomainID_OffMode];
/************* Private function prototype *******************************/

/************************ Public Functions ******************************/

/**********************************************************************************
 *      	      CC_EcpkiBuildEcDomain function 			  *
 **********************************************************************************/
/**
 * @brief     The function builds (imports) the ECC Domain structure from EC parameters given
 *            by the user in big endian order of bytes in arrays.<br>
 *
 *            When operating the ECC cryptographic operations this function should be
 *            called the first.
 *
 *            The function performs the following operations:
 *                   - Checks pointers and sizes of of incoming parameters.
 *                   - Converts parameters from big endian bytes arrays into little
 *                     endian words arrays, where most left word is a last significant and
 *                     most left one is a most significant.<br>
 *
 *            Note! Assumed that Domain parameters are cheked by the user and therefore the
 *                  function not performs full parameters validitation.
 *
 * @param pMod -  A pointer to EC modulus.
 * @param pA   -  A pointer to parameter A of elliptic curve. The size
 *                of the buffer must be the same as EC modulus.
 * @param pB   -  A pointer to parameter B of elliptic curve. The size
 *                of the buffer must be the same as EC modulus.
 * @param pOrd - A pointer to order of generator (point G).
 * @param pGx -  A pointer to coordinate X of generator G. The size
 *               of the buffer must be the same as Ec modulus.
 * @param pGy -  A pointer to coordinate Y of generator G. The size
 *               of the buffer must be the same as EC modulus.
 * @param pCofactor -  A pointer to EC cofactor - optional. If the pointer
 *               and the size are set to null, than assumed, that given curve has
 *               cofactor = 1 or cofactor should not be included in the calculations.
 * @param modSizeBytes -  A size of of the EC modulus buffer in bytes.
 *               Note: The sizes of the buffers: pA, pB,
 *                     pGx, pGx are equall to pMod size.
 * @param ordSizeBytes -  A size of of the generator order in bytes.
 * @param cofactorSizeBytes -  A size of cofactor buffer in bytes. According to our
 *                implementation cofactorSizeBytes must be not great, than 4 bytes.
 *	          If cofactor = 1, then, the size and the pointer may be set to null.
 * @param securityStrengthBits - Optional security strength level S in bits:
 *      	 see ANS X9.62-2005 A.3.1.4. If this parameter is equal to 0, then
 *      	 it is ignored, else the function checks the EC order size. If the order
 *      	 is less than max(S-1, 192), then the function returns an error.
 * @param pDomain - A pointer to EC domain structure.
 *
 * @return CCError_t:
 *                         CC_OK
 *                         CC_ECPKI_BUILD_DOMAIN_DOMAIN_PTR_ERROR
 *                         CC_ECPKI_BUILD_DOMAIN_EC_PARAMETR_PTR_ERROR
 *                         CC_ECPKI_BUILD_DOMAIN_EC_PARAMETR_SIZE_ERROR
 *                         CC_ECPKI_BUILD_DOMAIN_SECURITY_STRENGTH_ERROR
 */
CEXPORT_C CCError_t CC_EcpkiBuildEcDomain(
			uint8_t   *pMod,	  	  	/*in*/
			uint8_t   *pA,		 		/*in*/
			uint8_t   *pB,		  		/*in*/
			uint8_t   *pOrd,	          	/*in*/
			uint8_t   *pGx,	  	  		/*in*/
			uint8_t   *pGy,	  	  		/*in*/
			uint8_t   *pCof,	          	/*in*/
			uint32_t   modSizeBytes,	  	/*in*/
			uint32_t   ordSizeBytes,   		/*in*/
			uint32_t   cofSizeBytes,   		/*in*/
			uint32_t   securityStrengthBits,	/*in*/
			CCEcpkiDomain_t  *pDomain		/*out*/)

{
	/* FUNCTION DECLARATIONS */
    uint32_t regVal;
	CCError_t err = CC_OK;
	uint32_t modSizeBits, modSizeWords, ordSizeBits, ordSizeWords;

	/* FUNCTION LOGIC */

    /* The function should refuse to operate if the secure disable bit is set */
    CC_UTIL_IS_SECURE_DISABLE_FLAG_SET(regVal);
    if (regVal == SECURE_DISABLE_FLAG_SET) {
        return CC_ECPKI_SD_ENABLED_ERR;
    }

    /* The function should refuse to operate if the Fatal Error bit is set */
    CC_UTIL_IS_FATAL_ERROR_SET(regVal);
    if (regVal == FATAL_ERROR_FLAG_SET) {
        return CC_ECPKI_FATAL_ERR_IS_LOCKED_ERR;
    }

	/* check input pointers */
	CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

	if (pDomain == NULL)
		return CC_ECPKI_BUILD_DOMAIN_DOMAIN_PTR_ERROR;

	if (pMod == NULL || pA == NULL  || pB == NULL  ||
	    pOrd == NULL || pGx == NULL || pGy == NULL)
		return CC_ECPKI_BUILD_DOMAIN_EC_PARAMETR_PTR_ERROR;

	/* check the sizes */

	if (modSizeBytes == 0 || ordSizeBytes == 0)
		return CC_ECPKI_BUILD_DOMAIN_EC_PARAMETR_SIZE_ERROR;

	if (modSizeBytes > CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS*sizeof(uint32_t))
		return CC_ECPKI_BUILD_DOMAIN_EC_PARAMETR_SIZE_ERROR;

        if (ordSizeBytes > CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS*sizeof(uint32_t))
                return CC_ECPKI_BUILD_DOMAIN_EC_PARAMETR_SIZE_ERROR;

	if (pCof == NULL && cofSizeBytes != 0)
		return CC_ECPKI_BUILD_DOMAIN_COFACTOR_PARAMS_ERROR;

	if (cofSizeBytes > sizeof(uint32_t)) /* according to our implementation */
		return CC_ECPKI_BUILD_DOMAIN_COFACTOR_PARAMS_ERROR;

	/* clean domain structure */
	CC_PalMemSetZero(pDomain, sizeof(CCEcpkiDomain_t));

	/* convert the data to words arrays with little endian order of words,
	   calculate and check exact bit - sizes */

        /* EC modulus */
        modSizeWords = CALC_32BIT_WORDS_FROM_BYTES(modSizeBytes);
        if(modSizeWords>=CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS){         /*To remove static analyzer warning*/
                return CC_ECPKI_INVALID_DATA_IN_PASSED_STRUCT_ERROR;
        }
        err = CC_CommonConvertMsbLsbBytesToLswMswWords(
                                pDomain->ecP, ROUNDUP_BYTES_TO_32BIT_WORD(modSizeBytes),
                                pMod, modSizeBytes);
        if (err != CC_OK) {
                goto End;
	}

        /* correction of mod. size */
        modSizeBits = CC_CommonGetWordsCounterEffectiveSizeInBits(
                                pDomain->ecP, modSizeWords);

        modSizeBytes = CALC_FULL_BYTES(modSizeBits);
        modSizeWords = CALC_FULL_32BIT_WORDS(modSizeBits);
        /* check mod size to prevent KW warnings */
        if (modSizeWords > CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS) {
                err = CC_ECPKI_BUILD_DOMAIN_EC_PARAMETR_SIZE_ERROR;
                goto End;
	}

        pDomain->modSizeInBits = modSizeBits;

        /* Ec order */
	ordSizeWords = CALC_32BIT_WORDS_FROM_BYTES(ordSizeBytes);
	err = CC_CommonConvertMsbLsbBytesToLswMswWords(
				pDomain->ecR, ROUNDUP_BYTES_TO_32BIT_WORD(ordSizeBytes),
				pOrd, ordSizeBytes);
	if (err != CC_OK) {
                goto End;
	}

        /* correction of order size */
	ordSizeBits = CC_CommonGetWordsCounterEffectiveSizeInBits(
				pDomain->ecR, ordSizeWords);
        /* according to EC curves features */
        if(ordSizeBits > modSizeBits + 1) {
                err = CC_ECPKI_BUILD_DOMAIN_EC_PARAMETR_SIZE_ERROR;
                goto End;
	}

	pDomain->ordSizeInBits = ordSizeBits;

        /* check curve security strength, if it is given > 0 */
	if(securityStrengthBits > 0  &&
           ordSizeBits < CC_MAX(2*securityStrengthBits-1, 192)) {
		err = CC_ECPKI_BUILD_DOMAIN_SECURITY_STRENGTH_ERROR;
                goto End;
	}

	/* A - parameter */
	err = CC_CommonConvertMsbLsbBytesToLswMswWords(
				pDomain->ecA, sizeof(uint32_t)*modSizeWords,
				pA, modSizeBytes);
	if (err != CC_OK) {
                goto End;
	}

	/* B - parameter */
	err = CC_CommonConvertMsbLsbBytesToLswMswWords(
				pDomain->ecB, sizeof(uint32_t)*modSizeWords,
				pB, modSizeBytes);
	if (err != CC_OK) {
                goto End;
	}

	/* Gx */
	err = CC_CommonConvertMsbLsbBytesToLswMswWords(
				pDomain->ecGx, sizeof(uint32_t)*modSizeWords,
				pGx, modSizeBytes);
	if (err != CC_OK) {
                goto End;
	}

	/* Gy */
	err = CC_CommonConvertMsbLsbBytesToLswMswWords(
				pDomain->ecGy, sizeof(uint32_t)*modSizeWords,
				pGy, modSizeBytes);
	if (err != CC_OK) {
                goto End;
	}

	/* Cofactor */
        if(cofSizeBytes > 0) {
                err = CC_CommonConvertMsbLsbBytesToLswMswWords(
                                        &pDomain->ecH, 1/*ecH is of size 1 word*/,
                                        pCof, cofSizeBytes);
                if (err != CC_OK) {
			goto End;
		}
        } else {
                pDomain->ecH = 1;
        }

        /* Calculate Barrett tags for modulus and order */

	err = PkiCalcNp(&pDomain->llfBuff[0], pDomain->ecP, modSizeBits);
	if (err != CC_OK) {
                goto End;
	}

	err = PkiCalcNp(&pDomain->llfBuff[CC_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS],
                        pDomain->ecR, ordSizeBits);
	if (err != CC_OK) {
                goto End;
	}

	pDomain->barrTagSizeInWords = CC_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS;


	/* set Domain ID to unknown (builded) mode */
	pDomain->DomainID = CC_ECPKI_DomainID_Builded;
End:
	if (err != CC_OK) {
		/* clean domain structure */
		CC_PalMemSetZero(pDomain, sizeof(CCEcpkiDomain_t));
	}
	return err;

} /* End CC_EcpkiBuildEcDomain */



/**
 @brief    the function returns the domain pointer
 @return   return domain pointer

*/
const CCEcpkiDomain_t *CC_EcpkiGetEcDomain(CCEcpkiDomainID_t domainId)
{
	if (domainId >= CC_ECPKI_DomainID_OffMode) {
		return NULL;
	}

	if (ecDomainsFuncP[domainId] == NULL) {
		return NULL;
	}

	return ((ecDomainsFuncP[domainId])());
}
