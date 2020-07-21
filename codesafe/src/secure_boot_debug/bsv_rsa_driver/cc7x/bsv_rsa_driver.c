/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#define CC_PAL_LOG_CUR_COMPONENT HOST_LOG_MASK_SECURE_BOOT

/************* Include Files ****************/
#include "rsa_pki_pka.h"
#include "rsa_bsv.h"
#include "cc_pka_hw_plat_defs.h"
#include "bsv_rsa_driver.h"
#include "secureboot_stage_defs.h"

uint32_t BsvRsaCalcNp(unsigned long hwBaseAddress,
                  uint32_t *pN,
                  uint32_t *pNp)
{
    uint32_t rc = CC_OK;
    int8_t rN = 0, rNp = 1;
    int8_t rT1 = 2;
    int8_t rTempN = 4;
    uint32_t regsCount = 7;

    /* initialize the PKA engine on default mode */
    rc = RSA_PKA_InitPka(BSV_CERT_RSA_KEY_SIZE_IN_BITS, regsCount, hwBaseAddress);
    if (rc != CC_OK) {
        return rc;
    }

    /* copy modulus N into r0 register */
    RSA_HW_PKI_PKA_CopyDataIntoPkaReg( rN/*dstReg*/, 1/*LenID*/,
                                       pN/*src_ptr*/, BSV_CERT_RSA_KEY_SIZE_IN_WORDS, hwBaseAddress );

    /* Compute Np on the fly. register index rNp will contain the value of Np */
    RSA_HW_PKA_CalcNpIntoPkaReg(0, /*LenID*/
                                BSV_CERT_RSA_KEY_SIZE_IN_BITS,
                                rN,
                                rNp,
                                rT1,
                                rTempN,
                                hwBaseAddress);

    /* copy result into output: rNp =>pNp */
    RSA_HW_PKI_PKA_CopyDataFromPkaReg( pNp, RSA_HW_PKI_PKA_BARRETT_MOD_TAG_SIZE_IN_WORDS,
                                       rNp/*srcReg*/, hwBaseAddress );

    /* Finish PKA operations (waiting PKI done and close PKA clocks) */
    RSA_HW_PKI_PKA_FinishPKA( hwBaseAddress );

    return CC_OK;
}

uint32_t BsvRsaCalcExponent( unsigned long hwBaseAddress,
                         uint32_t *pBase,
                         uint32_t *pN,
                         uint32_t *pNp,
                         uint32_t *pRes )
{

    uint32_t rc = 0;
    uint32_t Exp = RSA_EXP_VAL; /* Fix value for the Exponent */
    uint32_t regsCount = 7;     /*5 working + 2 temp registers*/

    /* initialize the PKA engine on default mode */
    rc = RSA_PKA_InitPka(BSV_CERT_RSA_KEY_SIZE_IN_BITS, regsCount, hwBaseAddress);
    if (rc != CC_OK) {
        return rc;
    }

    /* copy modulus N into r0 register */
    RSA_HW_PKI_PKA_CopyDataIntoPkaReg(0/*dstReg*/, 1/*LenID*/,
                                      pN/*src_ptr*/, BSV_CERT_RSA_KEY_SIZE_IN_WORDS, hwBaseAddress);

    /* copy the NP into r1 register NP */
    RSA_HW_PKI_PKA_CopyDataIntoPkaReg(1/*dstReg*/, 1/*LenID*/, pNp/*src_ptr*/,
                                      RSA_HW_PKI_PKA_BARRETT_MOD_TAG_SIZE_IN_WORDS, hwBaseAddress);

    /* copy input data into PKI register: DataIn=>r2 */
    RSA_HW_PKI_PKA_CopyDataIntoPkaReg(2/*dstReg*/, 1/*LenID*/,
                                      pBase, BSV_CERT_RSA_KEY_SIZE_IN_WORDS, hwBaseAddress);

    /* copy exponent data PKI register: e=>r3 */
    RSA_HW_PKI_PKA_CopyDataIntoPkaReg(3/*dstReg*/, 1/*LenID*/,
                                      &Exp, RSA_EXP_SIZE_WORDS, hwBaseAddress);


    /* .. calculate the exponent Res = OpA**OpB mod N;                  ... */
    RSA_HW_PKI_PKA_ModExp(0/*LenID*/, 2/*OpA*/, 3/*OpB*/, 4/*Res*/, 0/*Tag*/, hwBaseAddress);

    /* copy result into output: r4 =>DataOut */
    RSA_HW_PKI_PKA_CopyDataFromPkaReg(pRes, BSV_CERT_RSA_KEY_SIZE_IN_WORDS,
                                      4/*srcReg*/, hwBaseAddress);

    /* Finish PKA operations (waiting PKI done and close PKA clocks) */
    RSA_HW_PKI_PKA_FinishPKA( hwBaseAddress );

    return CC_OK;

}

CCError_t BsvRsaPssDecode(unsigned long hwBaseAddress,
                          CCHashResult_t mHash,
                          uint8_t *pEncodedMsg,
                          int32_t *pVerifyStat,
                          BsvPssDecodeWorkspace_t  *pWorkspace)
{
    CCError_t error = CC_OK;
    uint32_t stat = 0;
    uint8_t *pDbMask8;
    uint32_t *pDbMask32;
    uint32_t tmpBuff[HASH_RESULT_SIZE_IN_WORDS + 1/*for counter*/];
    uint32_t i, counter;

    /* check input pointers */
    if((mHash == NULL) ||
            (pEncodedMsg == NULL) ||
            (pVerifyStat == NULL) ||
            (pWorkspace == NULL)) {
        return CC_BOOT_RSA_VERIFIER_INVALID_PARAM_FAILURE;
    }

    UTIL_MemSet((uint8_t*)pWorkspace, 0, sizeof(BsvPssDecodeWorkspace_t));
    *pVerifyStat = CC_FALSE; /*set status to "not valid"*/

    /* internal pointers */
    pDbMask32 = pWorkspace->dbMask;
    pDbMask8 = (uint8_t*)pDbMask32;

    /*   operating the RSA PSS decoding scheme      */

    /* 9.1.2 <1,2,3> meet  */
    /* 9.1.2 <4> Check that the rightmost octet of EM = 0xbc */
    if (pEncodedMsg[BSV_CERT_RSA_KEY_SIZE_IN_BYTES - 1] != 0xbc) {
        error = CC_BOOT_RSA_VERIFIER_CMP_FAILURE;
        goto End;
    }

    /*  9.1.2 <6> Check that the leftmost (8*emLen - emLenbit) of  *
     *   masked DB are equalled to 0, i.e. in our case MSbit = 0    */
    if (pEncodedMsg[0] & 0x80) {
        error = CC_BOOT_RSA_VERIFIER_CMP_FAILURE;
        goto End;
    }

    /*  9.1.2 <7> Let dbMask = MGF1(H,emLen-hLen-1)                *
     *  B.2.1 MGF1:                                                *
     *  For counter from 0 to  | L / hLen | , do the following:    *
     *  a.  Convert counter to an octet string C of length 4       *
     *  b.  Concatenate the hash of the seed H and C to the octet  *
     *      string T:  T = T || Hash(H || C)                       *
     *      C = C + 1                                              */

    /* copy the HASH from the EM (EncodedMsg) to the temp buffer */
    UTIL_MemCopy((uint8_t*)tmpBuff, &pEncodedMsg[MASKED_DB_SIZE], HASH_RESULT_SIZE_IN_BYTES);

    for (counter = 0; counter <= (MASKED_DB_SIZE/HASH_RESULT_SIZE_IN_BYTES); counter++ ) {

        /* a. tmp = H||C */
        tmpBuff[HASH_RESULT_SIZE_IN_WORDS] = UTIL_INVERSE_UINT32_BYTES(counter);
         /* b. Calculate and concatenate the hash on dbMask buffer: *
         *           T = T || HASH(H || C)                          */
        error = _BSV_SHA256(hwBaseAddress, (uint8_t *)tmpBuff,
                             (HASH_RESULT_SIZE_IN_WORDS+1)*CC_32BIT_WORD_SIZE,
                             &pDbMask32[counter*HASH_RESULT_SIZE_IN_WORDS]);

        if (error != CC_OK) {
            goto End;
        }
    }

    /*  9.1.2 <8> Xor operation */
    for (i=0; i < MASKED_DB_SIZE; i++) {
        pDbMask8[i] ^= pEncodedMsg[i];
    }

    /*  9.1.2 <9> Set the leftmost (8emLen - emBits) bits of the leftmost
                      octet in DB to zero (in this case it is MS bit only) */
    pDbMask8[0] &= 0x7F;

    /*  9.1.2 <10> Check, that padding PS is zero and next byte = 0x01*/
    for (i = 0; i < BSV_CERT_RSA_KEY_SIZE_IN_BYTES - HASH_RESULT_SIZE_IN_BYTES - RSA_PSS_SALT_LENGTH - 2; i++) {
        stat |= pDbMask8[i];
    }
    if ((stat != 0) || (pDbMask8[i] != 0x01)) {
        error = CC_BOOT_RSA_VERIFIER_CMP_FAILURE;
        goto End;
    }

    /*  9.1.2 <11> Let salt be the last sLen octets in DB */
    /*  9.1.2 <12> Let M' => (0x) 00 00 00 00 00 00 00 00 || mHash || salt*/

    UTIL_MemSet(pEncodedMsg, 0x00, RSA_PSS_PAD1_LEN); /* PS zero padding */
    /* Hash and Salt */
    UTIL_MemCopy(&pEncodedMsg[RSA_PSS_PAD1_LEN], (uint8_t*)mHash, HASH_RESULT_SIZE_IN_BYTES);
    UTIL_MemCopy(&pEncodedMsg[RSA_PSS_PAD1_LEN + HASH_RESULT_SIZE_IN_BYTES],
                 &pDbMask8[MASKED_DB_SIZE - RSA_PSS_SALT_LENGTH], RSA_PSS_SALT_LENGTH);

    /*  9.1.2 <13> H' = Hash(M') ==> dbMask*/
    error = _BSV_SHA256(hwBaseAddress,
                         pEncodedMsg,
                         (RSA_PSS_PAD1_LEN + HASH_RESULT_SIZE_IN_BYTES + RSA_PSS_SALT_LENGTH),
                         pDbMask32/*H'*/);

    if (error != CC_OK) {
       goto End;
    }

    /*  9.1.2 <14> Compare H' == H; Note: If buffers are equalled,        *
     *   then CC_TRUE = 1 is returned                                      */
    *pVerifyStat = UTIL_MemCmp((uint8_t*)pDbMask32/*H'*/, (uint8_t*)tmpBuff/*hash on EM*/, sizeof(CCHashResult_t));

    if(*pVerifyStat != CC_TRUE) {
        error = CC_BOOT_RSA_VERIFIER_CMP_FAILURE;
        *pVerifyStat = CC_FALSE;
        goto End;
    }

    /* end of function, clean temp buffers */
End:
    UTIL_MemSet((uint8_t*)pWorkspace, 0, sizeof(BsvPssDecodeWorkspace_t));

    return error;

}

CCError_t BsvRsaPssVerify(unsigned long hwBaseAddress,
                          uint32_t *NBuff,
                          uint32_t *NpBuff,
                          uint32_t *signature,
                          CCHashResult_t hashedData,
                          uint32_t *pWorkSpace,
                          size_t workspaceSize)
{
    uint32_t error = CC_OK;
    BsvPssVerifyIntWorkspace_t *pPssWorkspace = NULL;
    uint32_t isVerified = CC_FALSE;

    /* check input pointers */
    if((NBuff == NULL) ||
            (NpBuff == NULL) ||
            (signature == NULL) ||
            (hashedData == NULL) ||
            (pWorkSpace == NULL) ||
            (workspaceSize < sizeof(BsvPssVerifyIntWorkspace_t))) {
        return CC_BOOT_RSA_VERIFIER_INVALID_PARAM_FAILURE;
    }
    pPssWorkspace = (BsvPssVerifyIntWorkspace_t *)pWorkSpace;

    UTIL_MemSet((uint8_t*)pWorkSpace, 0, workspaceSize);

    error = BsvRsaCalcExponent(hwBaseAddress, signature, NBuff, NpBuff, pPssWorkspace->ED);
    if (error != CC_OK) {
         goto End;
    }

    /* reverse to big.end format for decoding */
    UTIL_ReverseBuff((uint8_t*)pPssWorkspace->ED, BSV_CERT_RSA_KEY_SIZE_IN_BYTES);

    error =  BsvRsaPssDecode(hwBaseAddress,
                             hashedData,
                             (uint8_t *)pPssWorkspace->ED,
                             (int32_t *)&isVerified,
                             &pPssWorkspace->pssDecode);
    if (error != CC_OK) {
         goto End;
    }
    if (isVerified != CC_TRUE){
        error = CC_BOOT_RSA_VERIFIER_CMP_FAILURE;
        goto End;
    }

 End:
     /* zeroing temp buffer */
     UTIL_MemSet((uint8_t*)pWorkSpace, 0, workspaceSize);
     return error;


}

