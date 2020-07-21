/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#define CC_PAL_LOG_CUR_COMPONENT CC_LOG_MASK_CC_API

#include "cc_pal_types.h"
#include "cc_pal_mem.h"
#include "cc_des.h"
#include "cc_des_error.h"
#include "sym_adaptor_driver.h"
#include "dma_buffer.h"
#include "cc_sym_error.h"
#include "cc_context_relocation.h"
#include "cc_fips_defs.h"
#include "cc_des_data.h"

#if ( CC_DRV_CTX_SIZE_WORDS > CC_DES_USER_CTX_SIZE_IN_WORDS )
#error CC_DES_USER_CTX_SIZE_IN_WORDS is not defined correctly.
#endif

#define DES_MAX_BLOCK_SIZE 0x100000

typedef struct _DesSingleKey {
    uint8_t key[CC_DES_KEY_SIZE_IN_BYTES];
} DesSingleKey;

static const DesSingleKey DesWeakKeysTable[] = NIST_TDES_WEAK_KEYS_LIST;
#define DES_NUM_OF_WEAK_KEYS        (sizeof(DesWeakKeysTable) / sizeof(DesSingleKey))

static CCError_t DesVerifyWeakKeys(CCDesKey_t* key, CCDesNumOfKeys_t numOfKeys)
{
    uint32_t i = 0;

    /*
     ARM TrustZone CryptoCell-710 TEE System Specification, VERSION 1.61 (CCS_FIPS-9):
     The 3DES implementation should include 2 keys and 3 keys 3DES verification to SP 800-67
     */
    if (numOfKeys != CC_DES_3_KeysInUse) {
        return CC_OK;
    }

    if ((CC_PalMemCmp(key->key1, key->key2, CC_DES_KEY_SIZE_IN_BYTES) == 0)
                    || (CC_PalMemCmp(key->key2, key->key3, CC_DES_KEY_SIZE_IN_BYTES) == 0)) {
        return CC_DES_ILLEGAL_PARAMS_ERROR;
    }

    /*
     ARM TrustZone CryptoCell-710 TEE System Specification, VERSION 1.61 (CCS_FIPS-8):
     The 3DES implementation should include weak keys verification according to SP 800-67
     */
    for (i = 0; i < DES_NUM_OF_WEAK_KEYS; ++i) {
        if ((CC_PalMemCmp(DesWeakKeysTable[i].key, key->key1, CC_DES_KEY_SIZE_IN_BYTES) == 0)
                        || (CC_PalMemCmp(DesWeakKeysTable[i].key,
                                         key->key2,
                                         CC_DES_KEY_SIZE_IN_BYTES)
                                        == 0)
                        || (CC_PalMemCmp(DesWeakKeysTable[i].key,
                                         key->key3,
                                         CC_DES_KEY_SIZE_IN_BYTES)
                                        == 0)) {
            return CC_DES_ILLEGAL_PARAMS_ERROR;
        }
    }

    /*
     ARM TrustZone CryptoCell-710 TEE System Specification, VERSION 1.61 (CCS_FIPS-8 and CCS_FIPS-9):
     in any case of weak key the operation should be stopped and error should be return (without changing the FIPS state to error).
     */

    return CC_OK;
}

/*!
 * Converts Symmetric Adaptor return code to CC error code.
 *
 * \param symRetCode Symmetric Adaptor return error.
 * \param errorInfo Ignored.
 *
 * \return CCError_t one of CC_* error codes defined in cc_error.h
 */
static CCError_t SymAdaptor2CCDesErr(int symRetCode, uint32_t errorInfo)
{
    errorInfo = errorInfo;
    switch (symRetCode) {
        case CC_RET_UNSUPP_ALG:
            return CC_DES_IS_NOT_SUPPORTED;
        case CC_RET_UNSUPP_ALG_MODE:
        case CC_RET_UNSUPP_OPERATION:
            return CC_DES_ILLEGAL_OPERATION_MODE_ERROR;
        case CC_RET_INVARG:
            return CC_DES_ILLEGAL_PARAMS_ERROR;
        case CC_RET_INVARG_KEY_SIZE:
            return CC_DES_ILLEGAL_NUM_OF_KEYS_ERROR;
        case CC_RET_INVARG_CTX_IDX:
            return CC_DES_INVALID_USER_CONTEXT_POINTER_ERROR;
        case CC_RET_INVARG_CTX:
            return CC_DES_USER_CONTEXT_CORRUPTED_ERROR;
        case CC_RET_INVARG_BAD_ADDR:
            return CC_DES_DATA_IN_POINTER_INVALID_ERROR;
        case CC_RET_NOMEM:
            return CC_OUT_OF_RESOURCE_ERROR;
        case CC_RET_INVARG_INCONSIST_DMA_TYPE:
            return CC_ILLEGAL_RESOURCE_VAL_ERROR;
        case CC_RET_PERM:
        case CC_RET_NOEXEC:
        case CC_RET_BUSY:
        case CC_RET_OSFAULT:
        default:
            return CC_FATAL_ERROR;
    }
}

static enum drv_cipher_mode MakeSepDesMode(CCDesOperationMode_t OperationMode)
{
    enum drv_cipher_mode result;

    switch (OperationMode) {
        case CC_DES_ECB_mode:
            result = DRV_CIPHER_ECB;
            break;
        case CC_DES_CBC_mode:
            result = DRV_CIPHER_CBC;
            break;
        default:
            result = DRV_CIPHER_NULL_MODE;
    }

    return result;
}

/**
 * @brief This function is used to initialize the DES machine.
 *        To operate the DES machine, this should be the first function called.
 *
 * @param[in] ContextID_ptr  - A pointer to the DES context buffer allocated by the user
 *                       that is used for the DES machine operation.
 *
 * @param[in,out] IV_ptr - The buffer of the IV.
 *                          In ECB mode this parameter is not used.
 *                          In CBC this parameter should contain the IV values.
 *
 * @param[in] Key_ptr - A pointer to the user's key buffer.
 *
 * @param[in] NumOfKeys - The number of keys used: 1, 2, or 3 (defined in the enum).
 *
 * @param[in] EncryptDecryptFlag - A flag that determines whether the DES should perform
 *                           an Encrypt operation (0) or a Decrypt operation (1).
 *
 * @param[in] OperationMode - The operation mode: ECB or CBC.
 *
 *
 * @return CCError_t - On success the value CC_OK is returned,
 *                        and on failure a value from cc_error.h
 */

CIMPORT_C CCError_t CC_DesInit(CCDesUserContext_t *ContextID_ptr,
                               CCDesIv_t IV_ptr,
                               CCDesKey_t *Key_ptr,
                               CCDesNumOfKeys_t NumOfKeys,
                               CCDesEncryptMode_t EncryptDecryptFlag,
                               CCDesOperationMode_t OperationMode)
{
    int symRc = CC_RET_OK;

    /* pointer on SEP DES context struct*/
    struct drv_ctx_cipher *pDesContext;

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* ............... checking the parameters validity ................... */
    /* -------------------------------------------------------------------- */

    /* if the users context ID pointer is NULL return an error */
    if (ContextID_ptr == NULL) {
        return CC_DES_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    /* check if the operation mode is legal */
    if (OperationMode >= CC_DES_NumOfModes) {
        return CC_DES_ILLEGAL_OPERATION_MODE_ERROR;
    }

    /* if the operation mode selected is CBC then check the validity of
     the IV counter pointer */
    if ((OperationMode == CC_DES_CBC_mode) && (IV_ptr == NULL)) {
        return CC_DES_INVALID_IV_PTR_ON_NON_ECB_MODE_ERROR;
    }

    /* If the number of keys is invalid return an error */
    if ((NumOfKeys >= CC_DES_NumOfKeysOptions) || (NumOfKeys == 0)) {
        return CC_DES_ILLEGAL_NUM_OF_KEYS_ERROR;
    }

    /*check the validity of the key pointer */
    if (Key_ptr == NULL) {
        return CC_DES_INVALID_KEY_POINTER_ERROR;
    }

    /* Check the Encrypt / Decrypt flag validity */
    if (EncryptDecryptFlag >= CC_DES_EncryptNumOfOptions) {
        return CC_DES_INVALID_ENCRYPT_MODE_ERROR;
    }

    if (DesVerifyWeakKeys(Key_ptr, NumOfKeys) != CC_OK) {
        return CC_DES_ILLEGAL_PARAMS_ERROR;
    }

    /* Get pointer to contiguous context in the HOST buffer */
    pDesContext = (struct drv_ctx_cipher *) RcInitUserCtxLocation(ContextID_ptr->buff,
                                                                  sizeof(CCDesUserContext_t),
                                                                  sizeof(struct drv_ctx_cipher));
    if (pDesContext == NULL) {
        return CC_DES_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    /* Zeroization of new context */
    CC_PalMemSetZero(pDesContext, sizeof(struct drv_ctx_cipher));

    pDesContext->alg = DRV_CRYPTO_ALG_DES;
    pDesContext->mode = MakeSepDesMode(OperationMode);
    pDesContext->direction = (enum drv_crypto_direction) EncryptDecryptFlag;
    pDesContext->key_size = NumOfKeys * CC_DRV_DES_BLOCK_SIZE;

    CC_PalMemCopy(pDesContext->key, Key_ptr, pDesContext->key_size);

    if (pDesContext->mode == DRV_CIPHER_CBC) {
        CC_PalMemCopy(pDesContext->block_state, IV_ptr, CC_DES_IV_SIZE_IN_BYTES);
    }

    symRc = SymDriverAdaptorInit((uint32_t *) pDesContext, pDesContext->alg, pDesContext->mode);
    return CC_CRYPTO_RETURN_ERROR(symRc, 0, SymAdaptor2CCDesErr);
}

/**
 * @brief This function is used to process a block on the DES machine.
 *        This function should be called after the CryptoCell_DesInit function was called.
 *
 *
 * @param[in] ContextID_ptr - a pointer to the DES context buffer allocated by the user that
 *                       is used for the DES machine operation. this should be the same context that was
 *                       used on the previous call of this session.
 *
 * @param[in] DataIn_ptr - The pointer to the buffer of the input data to the DES. The pointer does
 *                         not need to be aligned.
 *
 * @param[in] DataInSize - The size of the input data in bytes: must be not 0 and must be multiple
 *                         of 8 bytes.
 *
 * @param[in/out] DataOut_ptr - The pointer to the buffer of the output data from the DES. The pointer does not
 *                              need to be aligned.
 *
 * @return CCError_t - On success CC_OK is returned, on failure a
 *                        value MODULE_* cc_des_error.h
 */
CIMPORT_C CCError_t CC_DesBlock(CCDesUserContext_t *ContextID_ptr,
                                uint8_t *DataIn_ptr,
                                size_t DataInSize,
                                uint8_t *DataOut_ptr)
{
    int symRc = CC_RET_OK;

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* pointer on SEP DES context struct*/
    struct drv_ctx_cipher *pDesContext;
    /* if the users context ID pointer is NULL return an error */
    if (ContextID_ptr == NULL) {
        return CC_DES_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    /* if the users Data In pointer is illegal return an error */
    if (DataIn_ptr == NULL) {
        return CC_DES_DATA_IN_POINTER_INVALID_ERROR;
    }

    /* if the users Data Out pointer is illegal return an error */
    if (DataOut_ptr == NULL) {
        return CC_DES_DATA_OUT_POINTER_INVALID_ERROR;
    }

    /* data size must be a positive number and a block size mult */
    if (((DataInSize % CC_DES_BLOCK_SIZE_IN_BYTES) != 0) || (DataInSize == 0)) {
        return CC_DES_DATA_SIZE_ILLEGAL;
    }

    /* max size validation */
    if (DataInSize > DES_MAX_BLOCK_SIZE) {
        return CC_DES_DATA_SIZE_ILLEGAL;
    }

    /* Get pointer to contiguous context in the HOST buffer */
    pDesContext = (struct drv_ctx_cipher *) RcGetUserCtxLocation(ContextID_ptr->buff);

    symRc = SymDriverAdaptorProcess((uint32_t *) pDesContext,
                                    DataIn_ptr,
                                    DataOut_ptr,
                                    DataInSize,
                                    pDesContext->alg);
    return CC_CRYPTO_RETURN_ERROR(symRc, 0, SymAdaptor2CCDesErr);
}

/**
 * @brief This function is used to end the DES processing session.
 *        It is the last function called for the DES process.
 *
 *
 * @param[in] ContextID_ptr  - A pointer to the DES context buffer allocated by the user that
 *                       is used for the DES machine operation. this should be the
 *                       same context that was used on the previous call of this session.
 *
 * @return CCError_t - On success the value CC_OK is returned,
 *                        and on failure a value from cc_error.h
 */
CIMPORT_C CCError_t CC_DesFree(CCDesUserContext_t *ContextID_ptr)
{
    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* if the users context ID pointer is NULL return an error */
    if (ContextID_ptr == NULL) {
        return CC_DES_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    CC_PalMemSetZero(ContextID_ptr, sizeof(CCDesUserContext_t));

    return CC_OK;
}

/**
 * @brief This function is used to operate the DES machine in one integrated operation.
 *
 *        The actual macros that will be used by the users are:
 *
 *
 * @param[in,out] IVCounter_ptr - this parameter is the buffer of the IV or counters on mode CTR.
 *                          On ECB mode this parameter has no use.
 *                          On CBC mode this parameter should containe the IV values.
 *
 * @param[in] Key_ptr - a pointer to the users key buffer.
 *
 * @param[in] KeySize - Thenumber of keys used by the DES as defined in the enum.
 *
 * @param[in] EncryptDecryptFlag - This flag determains if the DES shall perform an Encrypt operation [0] or a
 *                           Decrypt operation [1].
 *
 * @param[in] OperationMode - The operation mode : ECB or CBC.
 *
 * @param[in] DataIn_ptr - The pointer to the buffer of the input data to the DES. The pointer does
 *                         not need to be aligned.
 *
 * @param[in] DataInSize - The size of the input data in bytes: must be not 0 and must be multiple
 *                         of 8 bytes.
 *
 * @param[in/out] DataOut_ptr - CC_DES_BLOCK_SIZE_IN_BYTES The pointer to the
 *                  buffer of the output data from the DES. The
 *                  pointer does not need to be aligned.
 *
 * @return CCError_t - On success CC_OK is returned, on failure a
 *                        value MODULE_* cc_des_error.h
 *
 */
CIMPORT_C CCError_t CC_Des(CCDesIv_t IV_ptr,
                           CCDesKey_t *Key_ptr,
                           CCDesNumOfKeys_t NumOfKeys,
                           CCDesEncryptMode_t EncryptDecryptFlag,
                           CCDesOperationMode_t OperationMode,
                           uint8_t *DataIn_ptr,
                           size_t DataInSize,
                           uint8_t *DataOut_ptr)
{
    CCDesUserContext_t UserContext;
    CCError_t Error = CC_OK;

    /* if no data to process -we're done */
    if (DataInSize == 0) {
        goto end;
    }

    Error = CC_DesInit(&UserContext, IV_ptr, Key_ptr, NumOfKeys, EncryptDecryptFlag, OperationMode);
    if (Error != CC_OK) {
        goto end;
    }

    Error = CC_DesBlock(&UserContext, DataIn_ptr, DataInSize, DataOut_ptr);
    if (Error != CC_OK) {
        goto end;
    }

    end: (void) CC_DesFree(&UserContext);

    return Error;
}
