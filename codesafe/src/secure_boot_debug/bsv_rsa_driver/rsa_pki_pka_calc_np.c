/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#define CC_PAL_LOG_CUR_COMPONENT HOST_LOG_MASK_SECURE_BOOT

#include "secureboot_stage_defs.h"
#include "rsa_pki_pka.h"
#include "rsa_bsv.h"


/************************ Defines ******************************/
#define RSA_CALC_FULL_32BIT_WORDS(numBits)      ((numBits + 32 - 1)/32)


/************************ Enums ********************************/

/************************ Typedefs  ****************************/

/************************ Structs  ******************************/

/************************ Public Variables **********************/
/* SRAM address used for the PKA */
extern uint32_t g_SramPkaAddr;

/************************ Public Functions ******************************/

#ifdef PKA_DEBUG
  uint8_t tempRes[268];
#endif

/**
 * The function uses the modulus data saved in register indexed by RegN, to calculate
 * the Barrett tag Np. Np is saved into Register indexed by regNp.
 *
 *  For RSA it uses truncated sizes:
 *      Np = truncated(2^(3*A+3*X-1) / ceiling(n/(2^(N-2*A-2*X)));
 *
 *      function assumes modulus in PKA reg 0, and output is to PKA reg 1
 *
 */
uint32_t  RSA_HW_PKA_CalcNpIntoPkaReg(uint32_t lenId,
                uint32_t    sizeNbits,
                int8_t      regN,
                int8_t      regNp,   // out
                int8_t      regTemp1,
                int8_t      regTempN,
                unsigned long VirtualHwBaseAddr)
{
    uint32_t err = 0;
    int32_t i;
    uint32_t  A = RSA_PKA_BIG_WORD_SIZE_IN_BITS;
    uint32_t  X = RSA_PKA_EXTRA_BITS;

    /*Sizes in words and bits  */
    int32_t wT,bNom,wNom;
    uint32_t val;
    int32_t sh, st;

    // clear temp registers
    RSA_PKA_Clear(LenIDmax, regTemp1, 0/*Tag*/,VirtualHwBaseAddr);
    RSA_PKA_Clear(LenIDmax, regTempN, 0/*Tag*/,VirtualHwBaseAddr);
    RSA_PKA_Clear(LenIDmax, regNp, 0/*Tag*/,VirtualHwBaseAddr);

    // copy modulus (regN) into temprarty register - regTempN
    RSA_PKA_Copy(LenIDmax, regTempN /* OpDest */, regN /* OpSrc */, 0/*Tag*/, VirtualHwBaseAddr);

    /*-----------------------------------------------*/
    if (sizeNbits <= (2*A + 2*X)) {
        wNom = RSA_CALC_FULL_32BIT_WORDS(sizeNbits+A+X-1);
        /* Sizes of nominator (N+A+X-1) in 32-bit words */
        bNom = (sizeNbits+A+X-1) % 32; /*remain bits*/
        if (bNom) {
            val = 1UL << bNom;
        } else {
            wNom++;
            val = 1UL;
        }

        /* Set rT2 = 2^(N+A+X-1) */
        RSA_PKA_WRITE_WORD_TO_REG(val, wNom-1, regTemp1, VirtualHwBaseAddr);
        // use LenIDmax for small sizes, since lenId is exact mod size which is not enought in this case!!!
        RSA_PKA_Div(LenIDmax, regTemp1, regTempN, regNp, 0/*Tag*/,VirtualHwBaseAddr);
    }
    /* If  (N > 2*A + 2*X) - truncated */
    /*---------------------------------*/
    else {
        /* Set rT1 = 2^D, where D=(3*A+3*X-1) division nominator size */
        /*------------------------------------------------------------*/

        wNom = RSA_CALC_FULL_32BIT_WORDS(3*A + 3*X - 1); /*words count in nominator */
        /* Calc. sizes of Nominator */
        bNom = (3*A + 3*X - 1) % 32; /*remain bits count*/
        val = 1UL << bNom;

        /* Set rT1 = 2^D, where D=(3*A+3*X-1) */
        RSA_PKA_WRITE_WORD_TO_REG(val, wNom-1, regTemp1, VirtualHwBaseAddr);
        /* Set rN = high part of the modulus as divisor */
        /*-----------------------------------------------*/

        /* count low bits to truncate the modulus */
        st = sizeNbits - 2*A - 2*X;
        /* count of words to truncate */
        wT = st / 32;
        /* shift for truncation */
        sh = st % 32;

        /* prevent further ceiling increment, if it not needed */
        RSA_PKA_SUB_IM(lenId+1/*LenID*/, regTempN, 1/*OpBIm*/, regTempN, 0/*Tag*/,VirtualHwBaseAddr);

        /* truncate modulus by words and then by bits */
        for (i=0; i<wT; i++) {
            RSA_PKA_SHR0(lenId+1/*LenID*/, regTempN, 32-1, regTempN, 0/*Tag*/,VirtualHwBaseAddr);
        }
        if (sh) {
            RSA_PKA_SHR0(lenId+1/*LenID*/, regTempN, sh-1, regTempN, 0/*Tag*/,VirtualHwBaseAddr);
        }

        /* Ceiling */
        RSA_PKA_Add_IM(lenId+1/*LenID*/, regTempN, 1/*OpBIm*/, regTempN, 0/*Tag*/,VirtualHwBaseAddr);
		RSA_PKA_Div(LenIDmax/*LenID*/ , regTemp1, regTempN, regNp, 0/*Tag*/,VirtualHwBaseAddr);
    }

    // clear temp registers
    RSA_PKA_Clear(LenIDmax, regTemp1, 0/*Tag*/,VirtualHwBaseAddr);
    RSA_PKA_Clear(LenIDmax, regTempN, 0/*Tag*/,VirtualHwBaseAddr);

    return err;
}


