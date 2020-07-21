/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

/************* Include Files ****************/

#include "cc_pal_types.h"
#include "cc_pal_mem.h"
#include "cc_pal_log.h"
#include "cc_rng_plat.h"
#include "cc_common.h"
#include "cc_common_math.h"
#include "cc_rnd_common.h"
#include "cc_rnd_error.h"
#include "cc_rnd_local.h"
#include "llf_rnd.h"
#include "llf_rnd_trng.h"
#include "llf_rnd_error.h"
#include "cc_pal_abort.h"
#include "cc_pal_mutex.h"
#include "cc_fips_defs.h"
#include "cc_util_pm.h"
#include "cc_rnd.h"
#include "cc_aes.h"
#include "cc_util_int_defs.h"

/*********************************Typedefs ******************************/
/* rotate 32-bits word by 16 bits */
#define RND_ROT32(x) ( (x) >> 16 | (x) << 16 )

/* inverse the bytes order in a word */
#define RND_REVERSE32(x)  ( ((RND_ROT32((x)) & 0xff00ff00UL) >> 8) | ((RND_ROT32((x)) & 0x00ff00ffUL) << 8) )

/**************** Global Data to be read by RNG function ****************/

extern CC_PalMutex *pCCGenVecMutex;


/************************************************************************************/
/***********************           Private functions            *********************/
/************************************************************************************/

/**
 *      The function adds value to the number N, presented as bytes array
 *      iv_ptr, where MSbyte is a most left one.
 *
 *      Algorithm:
 *          n = (iv + val) mod 2^(8*sizeBytes).
 *      Assumed: The array (AES IV) has size 8 bytes and is aligned to 32-bit
 *               words. The val is > 0.
 *
 * @author reuvenl (7/1/2012)
 *
 * @param iv_ptr
 * @param val - value to add
 */
static void RndAddValToIv(uint32_t *iv_ptr, uint32_t val)
{
        int32_t i;
        uint32_t *ptr = iv_ptr;
        uint32_t tmp, curr;

        for (i = 3; i >= 0; i--) {
#ifndef BIG__ENDIAN
                tmp = curr = RND_REVERSE32(ptr[i]);
#else
                tmp = curr = ptr[i];
#endif
                tmp += val;

#ifndef BIG__ENDIAN
                ptr[i] = RND_REVERSE32(tmp);
#else
                ptr[i] = tmp;
#endif

                if (tmp < curr)
                        val = 1;
                else
                        break;
        }
}

/****************************************************************************************/
/**
  @brief The function performs NIST 800-90, 10.2.1.2. algorithm of Update function.

  @param [in/out] rndState_ptr  - Pointer to the RND internal state buffer.
  @param [in/out] State - The pointer to the internal State buffer of DRNG.
  @param [in] providedData_ptr - The pointer to provided data buffer. The size of data
                                must be exactly of size of Seed.
  @param [in/out] seed_ptr - The pointer to the Seed = (Key || V) buffer.
  @param [in] skipSetUp - Flag, if set, then first two steps of algorithm sould be skipped.
  @param [in/out] aesCtxID_ptr - The pointer to AES context.

    Note: Updated result (Key||V) are in Seed buffer of the State.

  @return CCError_t - On success CC_OK is returned, on failure a
                         value MODULE_* as defined in ...
 */
 static CCError_t RndUpdate(
                                CCRndState_t    *rndState_ptr,      /*in/out*/
                                uint8_t             *providedData_ptr,    /*in*/
                                uint8_t             *seed_ptr,      /*in/out - Key,V*/
                                uint8_t              skipSetUp)     /*in*/
{
    /* LOCAL DECLARATIONS */

    CCError_t  error = CC_OK;
    uint32_t keySizeWords;
    /* size of seed */
    uint32_t seedSizeInWords;
    CCAesUserContext_t aesCtxID;
    CCAesUserKeyData_t keyData;

    /* pointers to current key and iv  */
    uint8_t *k_ptr, *iv_ptr;


    /* FUNCTION LOGIC */

    /* Initializations */

    keySizeWords = rndState_ptr->KeySizeWords;

    /* seed size in AES blocks */
    seedSizeInWords = keySizeWords + CC_AES_CRYPTO_BLOCK_SIZE_IN_WORDS;

    /* set key and iv pointers */
    k_ptr = (uint8_t*)&seed_ptr[0];
    iv_ptr = (uint8_t*)&seed_ptr[keySizeWords*sizeof(uint32_t)];

    /*----------------------------------------------------------------- */
    /*    NIST 800-90, 10.2.1.2. Algorithm of Update function           */
    /*  Where: output performed into StateSeed buffer without using of  */
    /*        temp buffer                                               */
    /*----------------------------------------------------------------- */

    /* Init AES operation on CTR mode */
    error = CC_AesInit(&aesCtxID, CC_AES_ENCRYPT, CC_AES_MODE_CTR, CC_AES_PADDING_NONE);
    if (error != CC_OK) {
        error = CC_RND_AES_ERROR;
        return error;
    }

    keyData.pKey = k_ptr;
    keyData.keySize = keySizeWords*sizeof(uint32_t);
    error = CC_AesSetKey(&aesCtxID, CC_AES_USER_KEY, &keyData, sizeof(keyData));
    if (error != CC_OK) {
        error = CC_RND_AES_ERROR;
        return error;
    }

    error = CC_AesSetIv(&aesCtxID, iv_ptr);
    if (error != CC_OK) {
        error = CC_RND_AES_ERROR;
        return error;
    }

    /* if not set skipSetUp flag, then perform one dummy encrypt for
       incrementing IV */
    if (!skipSetUp) {
        /* Dummy encrypt for increment the IV:                *
           V = (V+1) mod 2^outLenBits                     */
        error =  CC_AesBlock(&aesCtxID,
                       providedData_ptr,
                       CC_AES_BLOCK_SIZE_IN_BYTES,
                       seed_ptr);
        if (error != CC_OK) {
            error = CC_RND_AES_ERROR;
            return error;
        }
    }

    /* 2.2. Encrypt the SEED on AES CTR mode */
    {
        size_t dataSize = seedSizeInWords*sizeof(uint32_t);
        error = CC_AesFinish(&aesCtxID,
                       dataSize,
                       providedData_ptr, /*in*/
                       dataSize,
                       seed_ptr,  /*out*/
                       &dataSize );
        if (error != CC_OK) {
            error = CC_RND_AES_ERROR;
            return error;
        }
    }

    return error;

} /* End of RndUpdate */


/****************************************************************************************/
/**
  @brief The function performs NIST 800-90, 10.2.1.4.2. algorithm of
         Seed Derivation function.

  @param [in/out] rndState_ptr - The pointer to RND internal State buffer.
  @param [in] inputBuff_ptr - The pointer to input buffer, containing the input seed source
                  data, placed beginning from byte 8 and additional (at less 16)
                  empty bytes for padding. The size of the buffer must be
                  at less (8 + inputDataSizeBytes + 16) bytes.
  @param [in] inputDataSizeBytes - The size in bytes of the input data = actual size of
                                  input seed source data to process (must be multiple of 4 bytes).
  @param [out] output_ptr - The pointer to the output data buffer.
                           The size (in bytes) of the buffer and output data
                           are equal to (AES key size + AES block size).
  @param [in] outDataSizeBytes - The size of output data. According to NIST 800-90
                                the size must be <= 64 bytes.

    Note: Overlapping of inputBuff and output is not allowed.

  @return CCError_t - On success CC_OK is returned, on failure a
                         value MODULE_* as defined in ...
 */
static CCError_t RndDf(
                            CCRndState_t    *rndState_ptr,              /*in/out*/
                            uint32_t            *inputBuff_ptr,     /*in*/
                            uint32_t            inputDataSizeBytes,         /*in*/
                            uint8_t            *output_ptr,                 /*out*/
                            size_t            outDataSizeBytes)           /*in*/
{
    /* LOCAL DECLARATIONS */

    CCError_t  error = CC_OK;

    CCAesUserContext_t    aesContext;
    CCAesUserKeyData_t keyData;

    /* AES key size in words (defining also security strength) and its ID */
    uint32_t keySizeWords;
    /* pointers to precomputed initial MAC vectors (two-dimensional) and  *
    *  current key and iv                             */
    uint8_t *initMac_ptr, *iv_ptr;
    /* loop counter */
    uint32_t i;
        /* padded data size */
        uint32_t paddedDataSizeBytes;

    /* temp ptr */
    uint8_t *inputPtr;

    /*   Data for Security Strength = 128 and 256 bit.
         Note: Key buffer is common for 128 and 256 bits*/
    const uint8_t Key[32] =
    {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
            0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F};
    const uint8_t InitialMac128[2][CC_RND_BASIC_BLOCK_SIZE_IN_BYTES] =
    {{0xc6,0xa1,0x3b,0x37,0x87,0x8f,0x5b,0x82,0x6f,0x4f,0x81,0x62,0xa1,0xc8,0xd8,0x79},
            {0x95,0x03,0xe3,0xa2,0x24,0x5a,0x2b,0xe4,0x3c,0x98,0x74,0xed,0xfe,0x1b,0xed,0x9e}};
    const uint8_t InitialMac256[3][CC_RND_BASIC_BLOCK_SIZE_IN_BYTES] =
    {{0xF2,0x90,0x00,0xB6,0x2A,0x49,0x9F,0xD0,0xA9,0xF3,0x9A,0x6A,0xDD,0x2E,0x77,0x80},
            {0x9D,0xBA,0x41,0xA7,0x77,0xF3,0xB4,0x6A,0x37,0xB7,0xAA,0xAE,0x49,0xD6,0xDF,0x8D},
            {0x2F,0x7A,0x3C,0x60,0x07,0x08,0xD1,0x24,0xAC,0xD3,0xC5,0xDE,0x3B,0x65,0x84,0x47}};


    /* FUNCTION LOGIC */

    /* Initializations */

    keySizeWords = rndState_ptr->KeySizeWords;

        if (keySizeWords != CC_RND_AES_KEY_128_SIZE_WORDS &&
            keySizeWords != CC_RND_AES_KEY_256_SIZE_WORDS) {
                return CC_RND_ILLEGAL_AES_KEY_SIZE_ERROR;
    }
    if (outDataSizeBytes != (keySizeWords*sizeof(uint32_t) + CC_AES_BLOCK_SIZE_IN_BYTES)) {
                return CC_RND_ILLEGAL_DATA_SIZE_ERROR;
    }

    inputPtr = (uint8_t*)inputBuff_ptr;
    /*----------------------------------------------------------------- */
    /* [1]: NIST 800-90, 10.2.1.4.2. Block_Cipher_df Process.           */
    /*      Algorithm of Seed Derivation function               */
    /*  Note: step 8 is done because init Key and IV are hard coded     */
    /*----------------------------------------------------------------- */

    /* Set L, N and padding 0x80....0 in the input buffer.
       Note: input data was set before; L, N values must be in bytes  */
    #ifdef BIG__ENDIAN
    ((uint32_t*)inputBuff_ptr)[0] = inputDataSizeBytes; /* L */
    ((uint32_t*)inputBuff_ptr)[1] = outDataSizeBytes;   /* N */
    #else
    /* convert L,N to little endian */
    ((uint32_t*)inputBuff_ptr)[0] = CC_COMMON_REVERSE32(inputDataSizeBytes); /* L */
    ((uint32_t*)inputBuff_ptr)[1] = CC_COMMON_REVERSE32(outDataSizeBytes);   /* N */
    #endif
        /* size of padded data for AES MAC */
        paddedDataSizeBytes = CC_RND_TRNG_SRC_INNER_OFFSET_BYTES + inputDataSizeBytes + 1;
    inputPtr[paddedDataSizeBytes-1] = 0x80;
        /* set size of input to AES-MAC, rounded up to AES block */
        inputDataSizeBytes = ((paddedDataSizeBytes + CC_AES_BLOCK_SIZE_IN_BYTES - 1) / CC_AES_BLOCK_SIZE_IN_BYTES) * CC_AES_BLOCK_SIZE_IN_BYTES;
        /* zeroe padding */
    CC_PalMemSet(&inputPtr[paddedDataSizeBytes], 0, inputDataSizeBytes - paddedDataSizeBytes);


    /*****************************************************
    * [1] 12: Compression of seed source material        *
    ******************************************************/

    for (i = 0; i < (outDataSizeBytes/CC_RND_BASIC_BLOCK_SIZE_IN_BYTES); i++) {

        /* set pointer to initial precomputed IV  value */
        if (keySizeWords == CC_RND_AES_KEY_128_SIZE_WORDS) {
            initMac_ptr = (uint8_t*)&InitialMac128[i][0];
        } else {
            initMac_ptr = (uint8_t*)&InitialMac256[i][0];
        }

        /* AES MAC */
        error = CC_AesInit(&aesContext, CC_AES_ENCRYPT, CC_AES_MODE_CBC_MAC, CC_AES_PADDING_NONE);
        if (error != CC_OK) {
            error = CC_RND_AES_ERROR;
            return error;
        }

        keyData.pKey = (uint8_t*)&Key[0];
        keyData.keySize = keySizeWords*sizeof(uint32_t);
        error = CC_AesSetKey(&aesContext, CC_AES_USER_KEY, &keyData, sizeof(keyData));
        if (error != CC_OK) {
            error = CC_RND_AES_ERROR;
            return error;
        }

        error = CC_AesSetIv(&aesContext, initMac_ptr);
        if (error != CC_OK) {
            error = CC_RND_AES_ERROR;
            return error;
        }

        {
            size_t dataOutSize = CC_AES_BLOCK_SIZE_IN_BYTES;
            error = CC_AesFinish(&aesContext,
                           inputDataSizeBytes,
                           inputPtr,
                           inputDataSizeBytes,
                           output_ptr + i*CC_AES_BLOCK_SIZE_IN_BYTES, /*output*/
                           &dataOutSize );
            if (error != CC_OK) {
                error = CC_RND_AES_ERROR;
                return error;
            }
        }
    }

        /* set K and IV pointers and sizes for AES_CTR encryption */
    keyData.pKey = (uint8_t*)output_ptr;
    keyData.keySize = keySizeWords*sizeof(uint32_t);
    iv_ptr = (uint8_t*)output_ptr + keySizeWords*sizeof(uint32_t);

    /* Encrypt (K,IV) by AES-CBC using output buff */
    error = CC_AesInit(&aesContext, CC_AES_ENCRYPT, CC_AES_MODE_CBC, CC_AES_PADDING_NONE);
    if (error != CC_OK) {
            error = CC_RND_AES_ERROR;
        return error;
    }

    error = CC_AesSetKey(&aesContext, CC_AES_USER_KEY, &keyData, sizeof(keyData));
    if (error != CC_OK) {
            error = CC_RND_AES_ERROR;
        return error;
    }

    error = CC_AesSetIv(&aesContext, iv_ptr);
    if (error != CC_OK) {
            error = CC_RND_AES_ERROR;
        return error;
    }

    CC_PalMemSet(output_ptr, 0, outDataSizeBytes);

    error = CC_AesFinish(&aesContext,
                   outDataSizeBytes,
                   output_ptr/*in*/,
                   outDataSizeBytes,
                   output_ptr,/*out*/
                   &outDataSizeBytes);
    if (error != CC_OK) {
        error = CC_RND_AES_ERROR;
        return error;
    }

    return error;

} /* END of RndDf */


/****************************************************************************************/
/**
  @brief The function performs: NIST 800-90, 10.2.1.3.2  Instantiate function or
         NIST 800-90, 10.2.1.4.2 Reseeding function, according to given flag.

  @param f_rng  [in]        - pointer to DRBG function
  @param p_rng  [in/out]    - Pointer to the random context
  @param [in] isInstantiate - The flag defining which algorithm to perform:
                             0 - Instantiate; 1 - Reseeding.
  @param isContinued[in] isContinued - The variable indicates is the required process should
                   continue a  previous one or restart TRNG.
  @param [in/out] pTrngWorkBuff - The temp buffer for specific operations
                 on entropy generation and estimation.

       NOTE! The function works according to TRNG random source generation state as follows:

        1. If isContinued = 0, i.e. indicates that the TRNG was not started
           previously, the function starts it, else waits to end of TRNG generation.
        2. Performs deterministic part of NIST CTR_DRBG Instantiation or Reseeding algorithm.

       NOTE!! To ensure, that the function not uses the results from previous started TRNG, the user must
              call CC_RndUnInstantiation function previously to this function.


  @return CCError_t - On success CC_OK is returned, on failure a
                         value MODULE_* as defined in cc_error.h
 */
static CCError_t RndInstantiateOrReseed(
                                             CCRndGenerateVectWorkFunc_t *f_rng,     /*in */
                                             void                  *p_rng,          /*in/out*/
                                             CCBool_t              isInstantiate,   /*in*/
                                             CCBool_t              isContinued,     /*in*/
                                             CCTrngWorkBuff_t  *pTrngWorkBuff )   /*in/out*/
{

        /* LOCAL DECLARATIONS */

        /* error identifier definition */
        CCError_t error = CC_OK;

        uint32_t  *entrSource_ptr;
        uint32_t  keySizeWords;
        uint32_t  sourceSizeBytes;
        size_t    seedSizeBytes;
        /* TRNG parameters structure */
        CCTrngParams_t  trngParams;

        CCRndState_t   *rndState_ptr;
        bool isFipsSupported = true;


        /* FUNCTION LOGIC */

        /* ............. check parameters ............... */


        rndState_ptr = (CCRndState_t *)p_rng;
        if ((rndState_ptr == NULL) || (f_rng == NULL))
                return CC_RND_STATE_PTR_INVALID_ERROR;

        if (pTrngWorkBuff == NULL)
                return CC_RND_WORK_BUFFER_PTR_INVALID_ERROR;

        /* for Reseeding check valid tag and Instantiation done bit */
        if (isInstantiate == CC_FALSE) {
                if (rndState_ptr->ValidTag != CC_RND_WORK_STATE_VALID_TAG)
                        return CC_RND_STATE_VALIDATION_TAG_ERROR;

                if (!(rndState_ptr->StateFlag & CC_RND_INSTANTIATED))
                        return CC_RND_INSTANTIATION_NOT_DONE_ERROR;
        }
        /* for instantiation, set RND generate function ptr to NULL */
        else {
                *f_rng = NULL;
        }

        /* set users TRNG parameters into rndState structure */
        if (isContinued == CC_FALSE) {
                error = RNG_PLAT_SetUserRngParameters(rndState_ptr, &trngParams);
                if (error != CC_OK)
                        return error;
        }

        /* key size */
        keySizeWords = rndState_ptr->KeySizeWords;

        /* check user passed key size and additional data sizes */

        if (keySizeWords != CC_RND_AES_KEY_128_SIZE_WORDS &&
            keySizeWords != CC_RND_AES_KEY_256_SIZE_WORDS)
                return CC_RND_ILLEGAL_AES_KEY_SIZE_ERROR;

        if (rndState_ptr->AddInputSizeWords > CC_RND_ADDITINAL_INPUT_MAX_SIZE_WORDS)
                return CC_RND_ADDITIONAL_INPUT_SIZE_ERROR;

         /* Get entropy (including random Nonce) from TRNG and set
          it into Entropy Temp buffer. Update the needed size of
          TRNG source for receiving required entropy. Note:     */
        /*--------------------------------------------------------*/
        CHECK_FIPS_SUPPORTED(isFipsSupported);

    /* Case of RND KAT or TRNG KAT testing  */
    if (rndState_ptr->StateFlag & CC_RND_KAT_DRBG_Mode) {
        entrSource_ptr = (uint32_t*)pTrngWorkBuff;
        /* set source sizes given by the user in KAT test and placed
           in the rndWorkBuff */
        sourceSizeBytes = entrSource_ptr[0];
        if (sourceSizeBytes == 0) {
            return CC_RND_KAT_DATA_PARAMS_ERROR;
        }
    } else {
       error = LLF_RND_GetTrngSource(
                                     &rndState_ptr->trngState,    /*in/out*/
                                     &trngParams,       /*in/out*/
                                      &entrSource_ptr,   /*out*/
                                     &sourceSizeBytes,  /*out*/
                                     (uint32_t*)pTrngWorkBuff /*in*/,
                                     isFipsSupported);

        if (error != CC_OK) {
                error = CC_RND_TRNG_ERRORS_ERROR;
                goto EndWithError;
        }
    }

        /* Set additional data into work buffer */
        CC_PalMemCopy(
                      (uint8_t*)&entrSource_ptr[(sourceSizeBytes>>2)+CC_RND_TRNG_SRC_INNER_OFFSET_WORDS],
                      (uint8_t*)&rndState_ptr->AdditionalInput[0],
                      sizeof(uint32_t)*rndState_ptr->AddInputSizeWords);

        /*--------------------------------------------------------------------- */
        /*   [1] NIST 800-90: 10.2.1.3.2  Instantiate or  10.2.1.4.2 Reseeding  */
        /*--------------------------------------------------------------------- */
        /* set input and output data sizes for DF */
        sourceSizeBytes += sizeof(uint32_t)*rndState_ptr->AddInputSizeWords;
        seedSizeBytes = keySizeWords*sizeof(uint32_t) + CC_AES_BLOCK_SIZE_IN_BYTES;


        /* 2.1. if Derivation Function is used, call it */
        error = RndDf(
                         rndState_ptr,                    /*in*/
                         entrSource_ptr,  /*in buffer - data starts from */
                         sourceSizeBytes,           /*in - size of entropy  */
                         (uint8_t*)&rndState_ptr->AdditionalInput[0],  /*out - seed material*/
                         seedSizeBytes);            /*in*/


        if (error != CC_OK)
                goto EndWithError;

        /* 3,4: Set Key = 0x00000... and IV = 0x0000... into Seed buffer */
        if (isInstantiate == 1)
                CC_PalMemSetZero(rndState_ptr->Seed, sizeof(uint32_t)*(keySizeWords + CC_AES_CRYPTO_BLOCK_SIZE_IN_WORDS));


        /* 2.2. Call Update for Additional data */
        error = RndUpdate(
                             rndState_ptr,     /*in/out*/
                             (uint8_t*)&rndState_ptr->AdditionalInput[0],        /*in - provided data*/
                             (uint8_t*)&rndState_ptr->Seed[0], /*in/out - Key||V inside the state: */
                             0);                /*in - skipSetUp*/

        if (error != CC_OK)
                goto EndWithError;

        /* [1] 6:  Reset State parameters           */
        /*------------------------------------------*/

        rndState_ptr->ReseedCounter = 1;

        /* Set Instantiation flag = 1 (because it was zeroed in TRNG) */
        rndState_ptr->StateFlag |= CC_RND_INSTANTIATED;

        /* Set a valid tag and disable previous value flag (only for
           Instantiation mode) */
        if (isInstantiate == 1) {
                rndState_ptr->ValidTag = CC_RND_WORK_STATE_VALID_TAG;
                rndState_ptr->StateFlag &= ~CC_RND_PreviousIsValid;
        }

        /* Clean additional input buffer */
        rndState_ptr->AddInputSizeWords = 0;
        CC_PalMemSetZero(rndState_ptr->AdditionalInput, sizeof(rndState_ptr->AdditionalInput));

        goto End;


        EndWithError:

        /* In case of error, clean the secure sensitive data from rndState */
        CC_PalMemSetZero(rndState_ptr, sizeof(CCRndState_t));
        *f_rng=NULL;
        if (error == LLF_RND_CRNGT_TEST_FAIL_ERROR)
        {
                error = LLF_RND_TRNG_GENERATION_NOT_COMPLETED_ERROR;
                CC_FIPS_SET_RND_CONT_ERR();
        }

        End:
        CC_PalMemSetZero((uint8_t*)pTrngWorkBuff, sizeof(CCTrngWorkBuff_t));

        return error;

} /* End of RndInstantiateOrReseed function */



/************************************************************************************/
/***********************           Public functions            *********************/
/************************************************************************************/

/****************************************************************************************/
/**
  @brief The function performs NIST 800-90, 10.2.1.5.2 algorithm of Generate function.

  NOTE: The function should change the data in given output buffer also if an error occurs.


  @param [in/out] p_rng  - Pointer to the random context.
  @param [out] out_ptr - The pointer to output buffer.
  @param [in] outSizeBytes - The required size of random data in bytes.

  @return CCError_t - On success CC_OK is returned, on failure a
                         value MODULE_* as defined in ...

 */
CEXPORT_C CCError_t CC_RndGenerateVector(void *p_rng,
                          unsigned char   *out_ptr,      /*out*/
                          size_t    outSizeBytes)     /*in*/
{
    /* LOCAL DECLARATIONS */

    CCError_t  error = CC_OK;
    uint32_t regVal;

    uint32_t keySizeWords;
    size_t seedSizeWords;
    uint32_t remainBytes, countBlocks;
    CCAesUserContext_t  AesUserContext;
    CCAesUserKeyData_t keyData;
    CCRndState_t  *rndState_ptr=NULL;

    uint32_t *temp;


    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* Verify Security disable isn't set */
    CC_UTIL_IS_SECURE_DISABLE_FLAG_SET(regVal);
    if (regVal == CC_TRUE) {
        return CC_RND_SECURE_DISABLE_ERROR;
    }

    /* check if fatal error bit is set to ON */
    CC_UTIL_IS_FATAL_ERROR_SET(regVal);
    if (regVal == CC_TRUE) {
        return CC_RND_FATAL_ERR_IS_LOCKED_ERROR;
    }

    /* ................... checking parameters validity ..................... */
    /* ---------------------------------------------------------------------- */

    if (p_rng == NULL){
        return CC_RND_CONTEXT_PTR_INVALID_ERROR;
    }
    rndState_ptr = (CCRndState_t *) p_rng;

    if (out_ptr == NULL) {
        return CC_RND_DATA_OUT_POINTER_INVALID_ERROR;
    }

    if (outSizeBytes == 0) {
        return CC_OK ; /* because of PSS*/
    }

    /* Verify max value of outSizeBytes */
    if (outSizeBytes > 0xFFFF)
        return CC_RND_ILLEGAL_PARAMETER_ERROR;

    error = CC_PalMutexLock(pCCGenVecMutex, CC_INFINITE);
    if (error != CC_OK) {
        CC_PalAbort("Fail to acquire mutex\n");
    }

    if (rndState_ptr->ValidTag != CC_RND_WORK_STATE_VALID_TAG) {
        error = CC_RND_STATE_VALIDATION_TAG_ERROR;
        goto End;
    }

    /* Check, that instantiation was done */
    if (!(rndState_ptr->StateFlag & CC_RND_INSTANTIATED)) {
        error = CC_RND_INSTANTIATION_NOT_DONE_ERROR;
        goto End;
    }

    /* [1] 1: Check Reseed counter in the rndState
    Note: In [1] reseedCounter must be less than 2^48. In our implementation
    supplied more severe limitation of this parameter (counter < 2^32) that
    may only increase security */
    if (rndState_ptr->ReseedCounter >= CC_RND_MAX_RESEED_COUNTER) {
        error = CC_RND_RESEED_COUNTER_OVERFLOW_ERROR;
        goto End;
    }

    /* Initializations */
    /*-----------------*/
    temp = rndState_ptr->PreviousAdditionalInput;

    /* Set key and seed sizes */
    keySizeWords = rndState_ptr->KeySizeWords;
    seedSizeWords = keySizeWords + CC_AES_CRYPTO_BLOCK_SIZE_IN_WORDS;

    /* check user provided parameters */
    if (keySizeWords != CC_RND_AES_KEY_128_SIZE_WORDS &&
        keySizeWords != CC_RND_AES_KEY_256_SIZE_WORDS) {
        error = CC_RND_ILLEGAL_AES_KEY_SIZE_ERROR;
        goto End;
    }

    if (rndState_ptr->AddInputSizeWords > CC_RND_ADDITINAL_INPUT_MAX_SIZE_WORDS) {
        error = CC_RND_ADDITIONAL_INPUT_SIZE_ERROR;
        goto End;
    }

    /* Function logic  */
    /*-----------------*/

    /*----------------------------------------------------------------- */
    /*   [1] NIST 800-90, 10.2.1.5.2. CTR_DRBG Generate Process         */
    /*----------------------------------------------------------------- */

    /* [1] 2:  If additional input valid, then call Derivation and Update functions */
    if (rndState_ptr->AddInputSizeWords  > 0) {

        /* move additional data two words right for DF operation */
        CC_PalMemCopy( (uint8_t*)&temp[CC_RND_TRNG_SRC_INNER_OFFSET_WORDS],
                 (uint8_t*)&rndState_ptr->AdditionalInput[0],
                 sizeof(uint32_t)*rndState_ptr->AddInputSizeWords);

        /* 2.1. Derivation Function call. If prediction resistance */
        error = RndDf(rndState_ptr,                                     /*in*/
                   &temp[0], /*in - AdditionalInput*/
                   sizeof(uint32_t)*rndState_ptr->AddInputSizeWords, /*in - AddInputSizeWords*/
                   (uint8_t*)&rndState_ptr->AdditionalInput[0],      /*out - recalculated additional data*/
                   sizeof(uint32_t)*seedSizeWords);                  /*in*/
        if (error != CC_OK) {
            goto End;
        }

        /* 2.2. Call Update with recalculated additional (provided) data */
        error = RndUpdate(rndState_ptr,  /*in/out*/
                       (uint8_t*)&rndState_ptr->AdditionalInput[0], /*in - provided data*/
                       (uint8_t*)&rndState_ptr->Seed[0],            /*in/out - Key||V*/
                       0);   /*in - skipSetUp*/
        if (error != CC_OK) {
            goto End;
        }
    } else {   /* 2.3. Set AdditionalInput = 000000...0  */
        CC_PalMemSetZero(rndState_ptr->AdditionalInput, sizeof(rndState_ptr->AdditionalInput));
    }


    /*------------------------------------------------------------------------------*/
    /* [1] 4: Calculation of random: In loop {V = V+1; out = AES_ECB(Key,CTR=V)}    */
    /*        Note: This algorithm is equaled to out = AES_CTR(Key,dataIn=00000...) */
    /*------------------------------------------------------------------------------*/

    /*   Initialization of AES engine with calculated Key on CTR mode */

    /* Increment counter V = V+1 */
    RndAddValToIv(&rndState_ptr->Seed[keySizeWords], 1/*val*/);

    /* Init AES operation on CTR mode */
    error = CC_AesInit(&AesUserContext, CC_AES_ENCRYPT, CC_AES_MODE_CTR, CC_AES_PADDING_NONE);
    if (error != CC_OK) {
        error = CC_RND_AES_ERROR;
        goto End;
    }

    keyData.pKey = (uint8_t*)&rndState_ptr->Seed[0];
    keyData.keySize = keySizeWords*sizeof(uint32_t);
    error = CC_AesSetKey(&AesUserContext, CC_AES_USER_KEY, &keyData, sizeof(keyData));
    if (error != CC_OK) {
        error = CC_RND_AES_ERROR;
        goto End;
    }

    error = CC_AesSetIv(&AesUserContext, (uint8_t*)&rndState_ptr->Seed[keySizeWords]);
    if (error != CC_OK) {
        error = CC_RND_AES_ERROR;
        goto End;
    }

    /* If mode is working mode and previous generated block is not valid,*
    *  then generate one dummy block and save it as previous value        */
    if (!(rndState_ptr->StateFlag & CC_RND_KAT_DRBG_Mode) &&
        !(rndState_ptr->StateFlag & CC_RND_PreviousIsValid)) {

        CC_PalMemSetZero(rndState_ptr->PreviousRandValue, sizeof(rndState_ptr->PreviousRandValue));

        error = CC_AesBlock(&AesUserContext,
                      (uint8_t*)&rndState_ptr->PreviousRandValue[0],
                      CC_AES_BLOCK_SIZE_IN_BYTES,
                      (uint8_t*)&rndState_ptr->PreviousRandValue[0]);
        if (error != CC_OK) {
            error = CC_RND_AES_ERROR;
            goto End;
        }

        /* set previous valid */
        rndState_ptr->StateFlag |= CC_RND_PreviousIsValid;
    }

    /* calculate remaining size in bytes  (must be > 0 for       *
    *  finish operation) */
    remainBytes = outSizeBytes & (CC_AES_BLOCK_SIZE_IN_BYTES-1);
    countBlocks = outSizeBytes >> 4;
    if (remainBytes == 0) {
        remainBytes = CC_AES_BLOCK_SIZE_IN_BYTES;
    } else {
        countBlocks++;
    }

    /* generate full blocks of input data */
    if (outSizeBytes - remainBytes > 0) {

        CC_PalMemSetZero(out_ptr, outSizeBytes-remainBytes);

        error = CC_AesBlock(&AesUserContext,
                      out_ptr,
                      outSizeBytes - remainBytes,
                      out_ptr);
        if (error != CC_OK) {
            error = CC_RND_AES_ERROR;
            goto End;
        }
    }

    /* save PreviousRandValue in temp buffer */
    CC_PalMemCopy(temp, rndState_ptr->PreviousRandValue, sizeof(rndState_ptr->PreviousRandValue));

    /* Generate full random block for last output data */
    CC_PalMemSetZero(rndState_ptr->PreviousRandValue, sizeof(rndState_ptr->PreviousRandValue));

    {
        size_t dataOutSize = CC_AES_BLOCK_SIZE_IN_BYTES;
        error = CC_AesFinish(&AesUserContext,
                       CC_AES_BLOCK_SIZE_IN_BYTES,
                       (uint8_t*)&rndState_ptr->PreviousRandValue[0],
                       CC_AES_BLOCK_SIZE_IN_BYTES,
                       (uint8_t*)&rndState_ptr->PreviousRandValue[0],
                       &dataOutSize);
        if (error != CC_OK) {
            error = CC_RND_AES_ERROR;
        }
    }
    if (error != CC_OK) {
        goto End;
    }

    /* output remain bytes */
        CC_PalMemCopy( out_ptr + outSizeBytes  - remainBytes,
             (uint8_t*)&rndState_ptr->PreviousRandValue[0], remainBytes );


    /*  Perform CPRNGT - continuous test on each block  */
    /*---------------------------------------------------*/
    if (!(rndState_ptr->StateFlag & CC_RND_KAT_DRBG_Mode)) {
        error = LLF_RND_RndCprngt((uint8_t*)&temp[0], /*prev*/
                       out_ptr,              /*buff_ptr*/
                       (uint8_t*)&rndState_ptr->PreviousRandValue[0], /*last_ptr*/
                       countBlocks);   /*in*/
        if (error != CC_OK) {
            CC_FIPS_SET_RND_CONT_ERR();
            goto End;
        }
    }

    /* calculate current value of the counter: V = V+countBlocks */
    RndAddValToIv(&rndState_ptr->Seed[keySizeWords], countBlocks);

    /*------------------------------------------*/
    /* [1] 6:    Update Key,V in the State      */
    /*------------------------------------------*/


    error = RndUpdate(rndState_ptr, /*in/out*/
                   (uint8_t*)&rndState_ptr->AdditionalInput[0],  /*in - saved additional input */
                   (uint8_t*)&rndState_ptr->Seed[0], /*in/out - Key||V*/
                   1);  /*skipSetUp*/
    if (error != CC_OK) {
        goto End;
    }

    /* [1] 6:    Increment Reseed counter       */
    /*------------------------------------------*/
    rndState_ptr->ReseedCounter++;


End:
    if (error != CC_OK) {
        CC_PalMemSetZero (out_ptr, outSizeBytes);
    }
    /* Clean additional input  */
    if (rndState_ptr->AddInputSizeWords != 0) {
        rndState_ptr->AddInputSizeWords = 0;
        CC_PalMemSetZero(rndState_ptr->AdditionalInput, sizeof(rndState_ptr->AdditionalInput));
    }

        if (CC_PalMutexUnlock(pCCGenVecMutex) != CC_OK) {
        CC_PalAbort("Fail to release mutex\n");
    }

    return error;

} /* End of CC_RndGenerateVector */


/** -----------------------------------------------------------------------------
  @brief The function performs instantiation of RNG and creates new
         internal State (including Seed) of RNG.

         It implements the CTR_DRBG_Instantiate function of 9.1 [1].
      This function must be called at least once per system reset (boot) and
         required before any random generation can be produced.

  @param [in] f_rng        - pointer to DRBG function
  @param [in/out] p_rng   - Pointer to the random context
  @param [in/out] entrEstimBuff_ptr - The temp buffer for specific operations
                                on entropy estimator.
                          Note: for projects, which not use entropy estimator (e.g.
                                SW projects), the pointer may be set to NULL.

  @return CCError_t - On success CC_OK is returned, on failure a
                         value MODULE_* as defined in ...
 */
CEXPORT_C CCError_t CC_RndInstantiation(
                                            CCRndGenerateVectWorkFunc_t *f_rng,     /*in */
                                            void                  *p_rng,          /*in/out*/
                                            CCTrngWorkBuff_t  *pTrngWorkBuff/*in/out*/ )
{


        /* error identifier definition */
        CCError_t error = CC_OK;
        uint32_t regVal;

        CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

        /* Verify Security disable isn't set */
        CC_UTIL_IS_SECURE_DISABLE_FLAG_SET(regVal);
        if (regVal == CC_TRUE) {
            return CC_RND_SECURE_DISABLE_ERROR;
        }

        /* check if fatal error bit is set to ON */
        CC_UTIL_IS_FATAL_ERROR_SET(regVal);
        if (regVal == CC_TRUE) {
            return CC_RND_FATAL_ERR_IS_LOCKED_ERROR;
        }

        /* check parameters */
        if (pTrngWorkBuff == NULL)
                return CC_RND_WORK_BUFFER_PTR_INVALID_ERROR;

        /* call on Instantiation mode */
        error = RndInstantiateOrReseed(
                                          f_rng,
                                          p_rng,
                                          CC_TRUE/*isInstantiate*/,
                                          CC_FALSE/*isContinued*/,
                                          pTrngWorkBuff);

        return error;

}

/** ------------------------------------------------------------/
  @brief The function performs reseeding of RNG Seed, and performs:
         1. Mixing of additional entropy into the working state.
         2. Mixing additional input provided by the user called additional input buffer.

         The function implements the CTR_DRBG_Reseeding function of 9.2 [1].
      This function must be called if reseed counter > reseed interval,
         in our implementation it is 2^32-1.

  @param [in] f_rng        - pointer to DRBG function
  @param [in/out] p_rng   - Pointer to the random context
  @param [in/out] entrEstimBuff_ptr - The temp buffer for specific operations
                                on entropy estimator.

  @return CCError_t - On success CC_OK is returned, on failure a
                         value MODULE_* as defined in ...
 */
CEXPORT_C CCError_t CC_RndReseeding(
                                        CCRndGenerateVectWorkFunc_t *f_rng,     /*in */
                                        void                  *p_rng,          /*in/out*/
                                        CCTrngWorkBuff_t  *pTrngWorkBuff/*in/out*/)
{

        /* FUNCTION DECLARATIONS */

        /* error identifier definition */
        CCError_t error;
        uint32_t regVal;

        /* FUNCTION LOGIC */

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* Verify Security disable isn't set */
    CC_UTIL_IS_SECURE_DISABLE_FLAG_SET(regVal);
    if (regVal == CC_TRUE) {
        return CC_RND_SECURE_DISABLE_ERROR;
    }

    /* check if fatal error bit is set to ON */
    CC_UTIL_IS_FATAL_ERROR_SET(regVal);
    if (regVal == CC_TRUE) {
        return CC_RND_FATAL_ERR_IS_LOCKED_ERROR;
    }

        /* check parameters */
        if (pTrngWorkBuff == NULL) {
                return CC_RND_WORK_BUFFER_PTR_INVALID_ERROR;
    }

        /* increase CC counter at the beginning of each operation */
        error = CC_IS_WAKE;
        if (error != CC_SUCCESS) {
            CC_PalAbort("Fail to increase PM counter\n");
        }

        /* call on Reseeding mode */
        error = RndInstantiateOrReseed(
                                          f_rng, /*in*/
                                          p_rng, /*in/out*/
                                          CC_FALSE/*isInstantiate*/,
                                          CC_FALSE/*isContinued*/,
                                          pTrngWorkBuff );   /*in/out*/

        /* decrease CC counter at the end of each operation */
        error = CC_IS_IDLE;
        if (error != CC_SUCCESS) {
            CC_PalAbort("Fail to decrease PM counter\n");
        }

        return error;


}/* END OF CC_RndReseeding */

/******************************************************************************************/
/**
  @brief This function loads the AdditionaInput and its Size, given by the
        user, into the random context;

  @param [in] f_rng        - pointer to DRBG function
  @param [in/out] p_rng   - Pointer to the random context
  @param [in] AdditonalInput_ptr - The pointer to Additional input buffer.
  @param [in] AdditonalInputSize - The size of Additional input in bytes - must
        be up to 12 words and multiple of 4 bytes.

  @return CCError_t - On success CC_OK is returned, on failure a
                         value MODULE_* as defined in cc_rnd_error.h
*/
CEXPORT_C CCError_t CC_RndAddAdditionalInput(
                                                 void                  *p_rng,          /*in/out*/
                                                 uint8_t *additonalInput_ptr,
                                                 size_t  additonalInputSizeBytes)
{


        /* The return error identifiers */
        CCError_t error = CC_OK;
        uint32_t regVal;

        CCRndState_t   *rndState_ptr;

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* Verify Security disable isn't set */
    CC_UTIL_IS_SECURE_DISABLE_FLAG_SET(regVal);
    if (regVal == CC_TRUE) {
        return CC_RND_SECURE_DISABLE_ERROR;
    }

    /* check if fatal error bit is set to ON */
    CC_UTIL_IS_FATAL_ERROR_SET(regVal);
    if (regVal == CC_TRUE) {
        return CC_RND_FATAL_ERR_IS_LOCKED_ERROR;
    }

        if (p_rng == NULL) {
                return CC_RND_CONTEXT_PTR_INVALID_ERROR;
    }
        if ((additonalInput_ptr == NULL) &&
            (additonalInputSizeBytes != 0))
                return CC_RND_ADDITIONAL_INPUT_BUFFER_NULL;

        /* check Additional Input size - must be up to 12 words and multiple  *
        *  of 4 bytes                                 */
        if (additonalInputSizeBytes > sizeof(uint32_t)*CC_RND_ADDITINAL_INPUT_MAX_SIZE_WORDS ||
                additonalInputSizeBytes % sizeof(uint32_t)) {
                return CC_RND_ADDITIONAL_INPUT_SIZE_ERROR;

        }
        error = CC_PalMutexLock(pCCGenVecMutex, CC_INFINITE);
        if (error != CC_OK) {
                CC_PalAbort("Fail to acquire mutex\n");
        }

        rndState_ptr = (CCRndState_t *)p_rng;

        CC_PalMemSetZero( rndState_ptr->AdditionalInput,
                           sizeof(rndState_ptr->AdditionalInput));

        if (additonalInput_ptr != NULL) {
                /* Copy the data from user to the global buffer: AdditionalInput */
                CC_PalMemCopy( rndState_ptr->AdditionalInput,
                                additonalInput_ptr,
                                additonalInputSizeBytes );
        }

        /* Set the AdditionalInput flag to indicate that data written to the buffer
        and the size of the data */
        rndState_ptr->AddInputSizeWords = additonalInputSizeBytes / sizeof(uint32_t);

        if (CC_PalMutexUnlock(pCCGenVecMutex) != CC_OK) {
                CC_PalAbort("Fail to release mutex\n");
        }

        return error;
}


#ifndef _INTERNAL_CC_ONE_SEED

/**********************************************************************************************************/
/**
  @brief The CC_RndEnterKatMode function sets KAT mode bit into StateFlag
         of global random context structure.

    The user must call this function before calling functions performing KAT tests.

  @param p_rng   - Pointer to the random context
  @param entrData_ptr  - entropy data,
  @param entrSize      - entropy size in bytes,
  @param nonce_ptr     - nonce,
  @param nonceSize     - nonce size in bytes,
  @param pTrngWorkBuff  - RND working buffer, must be the same buffer,
              which should be passed into Instantiation/Reseeding functions.

     Note: Total size of entropy and nonce must be not great than:
            CC_RND_MAX_KAT_ENTROPY_AND_NONCE_SIZE, defined

  @return CCError_t - On success CC_OK is returned, on failure a
                         value MODULE_* as defined in ...
 */
CEXPORT_C CCError_t CC_RndEnterKatMode(
                                           void                  *p_rng,          /*in/out*/
                                           uint8_t            *entrData_ptr,
                                           size_t               entrSize,
                                           uint8_t              *nonce_ptr,
                                           size_t               nonceSize,
                                           CCTrngWorkBuff_t  *pTrngWorkBuff/*out*/)
{

        /* FUNCTION DECLARATIONS */

        /* error identifier definition */
        CCError_t error = CC_OK;
        uint8_t  *buf_ptr;
        uint32_t regVal;

        CCRndState_t   *rndState_ptr;

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* Verify Security disable isn't set */
    CC_UTIL_IS_SECURE_DISABLE_FLAG_SET(regVal);
    if (regVal == CC_TRUE) {
        return CC_RND_SECURE_DISABLE_ERROR;
    }

    /* check if fatal error bit is set to ON */
    CC_UTIL_IS_FATAL_ERROR_SET(regVal);
    if (regVal == CC_TRUE) {
        return CC_RND_FATAL_ERR_IS_LOCKED_ERROR;
    }

        /* check Entropy Input size - must be up to 12 words*/
        if ((entrData_ptr == NULL) && (entrSize == 0)) {
                return CC_OK;
        } else if ((entrData_ptr == NULL) || (entrSize == 0)) {
                return CC_RND_ILLEGAL_PARAMETER_ERROR;
        }

        if ((nonce_ptr == NULL) && (nonceSize != 0)) {
                return CC_RND_ILLEGAL_DATA_PTR_ERROR;
        }

        if (pTrngWorkBuff == NULL) {
                return CC_RND_WORK_BUFFER_PTR_INVALID_ERROR;
        }
        if (p_rng == NULL) {
                return CC_RND_CONTEXT_PTR_INVALID_ERROR;
        }

        /* check entropy size */
        if (entrSize > sizeof(uint32_t)*CC_RND_ENTROPY_TEMP_BUFFER_MAX_SIZE_WORDS) {
                return CC_RND_ILLEGAL_DATA_SIZE_ERROR;
        }

        error = CC_PalMutexLock(pCCGenVecMutex, CC_INFINITE);
        if (error != CC_OK) {
                CC_PalAbort("Fail to acquire mutex\n");
        }

        rndState_ptr = (CCRndState_t *)p_rng;
        /* Set KAT mode */
        rndState_ptr->StateFlag |= CC_RND_KAT_DRBG_Mode;

        /* Copy concatenated entropy and nonce data with defined offset  */
        /*---------------------------------------------------------------*/
        /* set pointer to begin of RND entropy source */
        buf_ptr = (uint8_t*)pTrngWorkBuff + CC_RND_TRNG_SRC_INNER_OFFSET_BYTES;

        CC_PalMemCopy(buf_ptr, entrData_ptr, entrSize);

        if ((nonce_ptr != NULL) && (nonceSize != 0)) {

                /* check nonce size */
                if ((entrSize + nonceSize) > sizeof(uint32_t)*CC_RND_ENTROPY_TEMP_BUFFER_MAX_SIZE_WORDS) {
                        error = CC_RND_ILLEGAL_DATA_SIZE_ERROR;
                        goto End;
                }

                CC_PalMemCopy(buf_ptr + entrSize, nonce_ptr, nonceSize);

                /* Calculate total source size */
                entrSize += nonceSize;
        }

        /* Set total size into workBuff on begin of RND source buffer, i.e.   *
        *  two words backward                             */
        *((uint32_t*)pTrngWorkBuff) = entrSize;

End:
        if (CC_PalMutexUnlock(pCCGenVecMutex) != CC_OK) {
                CC_PalAbort("Fail to release mutex\n");
        }

        return error;

}/* END OF CC_RndEnterKatMode  */

/**********************************************************************************************************/
/**
 * @brief The CC_RndDisableKatMode function disables KAT mode bit into StateFlag
 *        of global random context.
 *
 * @param [in/out] p_rng   - Pointer to the random context
 *
 *   The user must call this function after KAT tests before actual using RND module
 *   (Instantiation etc.).
 *
 * @return - no return value.
 */
CEXPORT_C void CC_RndDisableKatMode(void *p_rng)
{
        /* FUNCTION LOGIC */

        CCRndState_t   *rndState_ptr = (CCRndState_t *)p_rng;
        if (rndState_ptr == NULL){
            return;
        }

    CHECK_AND_RETURN_UPON_FIPS_ERROR();

        /* Disable KAT mode bit */
        rndState_ptr->StateFlag &= ~CC_RND_KAT_DRBG_Mode;

        return;

}/* END OF CC_RndDisableKatMode  */


/** -----------------------------------------------------------------------------
 * @brief The CC_RndUnInstantiation cleans the unused RNG State for security goals.
 *
 * @return CCError_t - On success CC_OK is returned, on failure a
 *                        value MODULE_* as defined in ...
 */
CEXPORT_C CCError_t CC_RndUnInstantiation(CCRndGenerateVectWorkFunc_t *f_rng, void *p_rng)
{

        CCError_t error = CC_OK;
        uint32_t regVal;

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* Verify Security disable isn't set */
    CC_UTIL_IS_SECURE_DISABLE_FLAG_SET(regVal);
    if (regVal == CC_TRUE) {
        return CC_RND_SECURE_DISABLE_ERROR;
    }

    /* check if fatal error bit is set to ON */
    CC_UTIL_IS_FATAL_ERROR_SET(regVal);
    if (regVal == CC_TRUE) {
        return CC_RND_FATAL_ERR_IS_LOCKED_ERROR;
    }

        /* check parameters */
        if ((p_rng == NULL) || (f_rng == NULL)) {
                return CC_RND_CONTEXT_PTR_INVALID_ERROR;
        }
        *f_rng=NULL;
        CC_PalMemSetZero(p_rng, sizeof(CCRndState_t));

        return error;
}


#endif /*_INTERNAL_CC_ONE_SEED*/
