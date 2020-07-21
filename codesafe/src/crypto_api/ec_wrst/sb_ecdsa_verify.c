/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#define CC_PAL_LOG_CUR_COMPONENT CC_LOG_MASK_ASYM_ECC

/************* Include Files ****************/

#include "cc_pal_mem.h"
#include "cc_hal_plat.h"
#include "cc_regs.h"
#include "cc_ecpki_error.h"
#include "cc_ecpki_local.h"
#include "cc_ecpki_types.h"
#include "cc_ecpki_domain_secp256r1.h"
#include "cc_common.h"
#include "cc_fips_defs.h"
#include "ec_wrst.h"
#include "ec_wrst_error.h"
#include "pka_ec_wrst.h"
#include "pka_ec_wrst_glob_regs.h"
#include "pka_ec_wrst_dsa_verify_regs.h"


/*
 *  Created on: 18 Mar 2018
 *      Author: Yury Kreimer
 */

/* Macros for checking and return errors */
#define CHECK_ERROR(err)  if((err)) goto End
#define CHECK_AND_SET_ERROR(expr, errMsg)  if((expr)) {err = (errMsg); goto End;}
#define CHECK_AND_RETURN_ERROR(expr, errMsg)  if((expr)) {err = (errMsg); return err;}

/**************************************************************************
 *	              EcdsaVerify function
 **************************************************************************/
/**
   @brief  Prepares and copies all the parameters into PKA registers and then
           calls PkaEcdsaVerify function for verifying signature
           according to EC DSA algorithm.

   @param[in] pPublX - Pointer to x coordinate of the public key
   @param[in] pPublY - Pointer to y coordinate of the public key
   @param[in] pR     - Pointer to C-part of the signature (called also R-part).
   @param[in] pS     - Pointer to D-part of the signature (called also S-part).
   @param[in] pMsgDgst     - Pointer to the digest of the message.
   @return <b>CCError_t</b>: <br>
              CC_OK <br>
                          ECWRST_SCALAR_MULT_INVALID_MOD_ORDER_SIZE_ERROR <br>
                          CC_ECIES_INVALID_PUBL_KEY_PTR_ERROR <br>
 **/
CEXPORT_C CCError_t SbEcdsaVerify(uint32_t *pPublX, uint32_t *pPublY,
                                  uint32_t *pR, uint32_t *pS, uint8_t *pMsgDgst)
{
    CCError_t err = CC_OK;
    uint32_t regVal;
    const CCEcpkiDomain_t * domain = 0;
    EcWrstDomain_t *llfBuff = 0;
    int32_t modSizeInBits, modSizeInWords, ordSizeInBits, ordSizeInWords;
    uint32_t pkaReqRegs = PKA_MAX_COUNT_OF_PHYS_MEM_REGS;

    /* The function should refuse to operate if the secure disable bit is set */
    CC_UTIL_IS_SECURE_DISABLE_FLAG_SET(regVal);
    if (regVal == SECURE_DISABLE_FLAG_SET) {
        return CC_ECDSA_VERIFY_SD_ENABLED_ERR;
    }

    /* The function should refuse to operate if the Fatal Error bit is set */
    CC_UTIL_IS_FATAL_ERROR_SET(regVal);
    if (regVal == FATAL_ERROR_FLAG_SET) {
        return CC_ECDSA_VERIFY_FATAL_ERR_IS_LOCKED_ERR;
    }

    CHECK_AND_SET_ERROR(pPublX == NULL, CC_ECIES_INVALID_PUBL_KEY_PTR_ERROR );
    CHECK_AND_SET_ERROR(pPublY == NULL, CC_ECIES_INVALID_PUBL_KEY_PTR_ERROR );
    CHECK_AND_SET_ERROR(pR == NULL, CC_ECDSA_VERIFY_INVALID_SIGNATURE_IN_PTR_ERROR );
    CHECK_AND_SET_ERROR(pS == NULL, CC_ECDSA_VERIFY_INVALID_SIGNATURE_IN_PTR_ERROR );
    CHECK_AND_SET_ERROR(pMsgDgst == NULL, CC_ECDSA_VERIFY_INVALID_MESSAGE_DATA_IN_PTR_ERROR );
    domain  = CC_EcpkiGetSecp256r1DomainP();
    CHECK_AND_SET_ERROR(domain == NULL, CC_ECDSA_VERIFY_INVALID_DOMAIN_ID_ERROR );

    llfBuff = (EcWrstDomain_t*)&domain->llfBuff;
    CHECK_AND_SET_ERROR(llfBuff == NULL, CC_ECDSA_VERIFY_INVALID_DOMAIN_ID_ERROR );

    /* set domain parameters */
    modSizeInBits  = domain->modSizeInBits;
    modSizeInWords = CALC_FULL_32BIT_WORDS(modSizeInBits);
    ordSizeInBits  = domain->ordSizeInBits;
    ordSizeInWords = CALC_FULL_32BIT_WORDS(ordSizeInBits);
    CHECK_AND_RETURN_ERROR ((ordSizeInWords > (CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 1)) ||
                            (modSizeInWords > CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS), ECWRST_SCALAR_MULT_INVALID_MOD_ORDER_SIZE_ERROR);

    /*  Init PKA for modular operations with EC modulus or EC order and   *
     *   registers size according to maximal of them                       */
    err = PkaInitAndMutexLock(CC_MAX(ordSizeInBits, modSizeInBits), &pkaReqRegs);
    CHECK_AND_RETURN_ERROR (err != CC_OK, err);
    /* set order and modulus mod sizes */
    CC_HAL_WRITE_REGISTER(CC_REG_OFFSET (CRY_KERNEL, PKA_L0), ordSizeInBits);
    CC_HAL_WRITE_REGISTER(CC_REG_OFFSET (CRY_KERNEL, PKA_L2), modSizeInBits);

    /* Set input data into PKA registers */
    /* EC order and its Barrett tag */
    PkaCopyDataIntoPkaReg(ECC_REG_N/*dest_reg*/, 1, domain->ecR/*src_ptr*/, ordSizeInWords);
    PkaCopyDataIntoPkaReg(ECC_REG_NP, 1, llfBuff->ordTag, CC_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS);
    /* signature C, D */
    PkaCopyDataIntoPkaReg(EC_VERIFY_REG_C, 1, pR, ordSizeInWords);
    PkaCopyDataIntoPkaReg(EC_VERIFY_REG_D, 1, pS, ordSizeInWords);
    /* message representative EC_VERIFY_REG_F */
    PkaCopyBeByteBuffIntoPkaReg(EC_VERIFY_REG_F, 1, pMsgDgst, 8);
    /* Load modulus and its Barrett tag */
    PkaCopyDataIntoPkaReg(EC_VERIFY_REG_TMP_N, 1, domain->ecP, modSizeInWords);
    PkaCopyDataIntoPkaReg(EC_VERIFY_REG_TMP_NP, 1, llfBuff->modTag, CC_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS);
    /* set pG */
    PkaCopyDataIntoPkaReg(EC_VERIFY_REG_P_GX, 1, domain->ecGx, modSizeInWords);
    PkaCopyDataIntoPkaReg(EC_VERIFY_REG_P_GY, 1, domain->ecGy, modSizeInWords);
    /* set pW */
    PkaCopyDataIntoPkaReg(EC_VERIFY_REG_P_WX, 1, pPublX, modSizeInWords);
    PkaCopyDataIntoPkaReg(EC_VERIFY_REG_P_WY, 1, pPublY, modSizeInWords);
    PkaCopyDataIntoPkaReg(ECC_REG_EC_A, 1, domain->ecA, modSizeInWords);

    /* Verify */
    err = PkaEcdsaVerify();

    PkaFinishAndMutexUnlock(pkaReqRegs);

    End:
    return err;

}

