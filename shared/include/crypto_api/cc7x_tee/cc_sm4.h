/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

/*! @file
@brief This file contains all the enums and definitions that are used for the
CryptoCell SM4 APIs, as well as the APIs themselves.
*/


/*!
 @addtogroup cc_sm4
 @{
     */


#ifndef CC_SM4_H
#define CC_SM4_H

#include "cc_pal_types.h"
#include "cc_sm4_defs.h"


#ifdef __cplusplus
extern "C"
{
#endif


/************************ Functions *****************************/

/*!
@brief This function is used to initialize a SM4 operation context.
       This must be the first API called to operate the SM4 cryptographic
       machine.

@return \c CC_OK on success,
@return A non-zero value from cc_sm4_error.h on failure.
*/
CIMPORT_C CCError_t  CC_Sm4Init(
    /*! [in]  Pointer to the SM4 context buffer that is allocated by the caller
    and initialized by this API. Must be used in all subsequent calls that are
    part of the same operation. */
    CCSm4UserContext_t *pContext,
    /*! [in]  A flag specifying whether an SM4 Encrypt (CC_SM4_ENCRYPT) or
    Decrypt (CC_SM4_DECRYPT) operation should be performed. */
    CCSm4EncryptMode_t encryptDecryptFlag,
    /*! [in]  The operation cipher/mode: ECB / CBC / CTR / OFB. */
    CCSm4OperationMode_t operationMode
);


/*!
@brief This function sets the key information for the SM4 operation, in the
context that was initialized by ::CC_Sm4Init().

@return \c CC_OK on success,
@return A non-zero value from cc_sm4_error.h on failure.
*/
CIMPORT_C CCError_t  CC_Sm4SetKey(
    /*! [in]  Pointer to the SM4 context, after it was initialized by
    ::CC_Sm4Init(). */
    CCSm4UserContext_t *pContext,
    /*! [in]  Pointer to the key data struct to be used for the SM4 operation.
    Must be 128 bits. */
    CCSm4Key_t pKey
);


/*!
@brief This function sets the IV or counter data for the following SM4
       operations on the same context.
       The context must be first initialized by ::CC_Sm4Init().
       It must be called at least once prior to the first ::CC_Sm4Block()
       operation on the same context - for those ciphers that require it.
       If needed, it can also be called to override the IV in the middle of a
       sequence of ::CC_Sm4Block() operations.

@return \c CC_OK on success,
@return A non-zero value from cc_sm4_error.h on failure.
*/
CIMPORT_C CCError_t CC_Sm4SetIv(
    /*! [in]  Pointer to the SM4 context. */
    CCSm4UserContext_t *pContext,
    /*! [in]  Pointer to the buffer of the IV, counter or tweak.
              <ul><li>For CBC mode - the IV value.</li>
              <li>For CTR mode - the counter.</li> </ul> */
    CCSm4Iv_t pIV
);


/*!
@brief This function retrieves the current IV or counter data from the SM4
       context.

@return \c CC_OK on success,
@return A non-zero value from cc_sm4_error.h on failure.
*/
CIMPORT_C CCError_t CC_Sm4GetIv(
    /*! [in]  Pointer to the SM4 context. */
    CCSm4UserContext_t *pContext,
    /*! [out] Pointer to the buffer of the IV or counter.
              <ul><li>For CBC mode - the IV value.</li>
              <li>For CTR mode - the counter.</li> </ul> */
    CCSm4Iv_t pIV
);

/*!
@brief This function performs a SM4 operation on an input data buffer, according
       to the configuration defined in the context parameter.
       It can be called as many times as needed, until all the input data is
       processed.
       The functions ::CC_Sm4Init(), ::CC_Sm4SetKey(), and for some ciphers
       ::CC_Sm4SetIv(), must be called before the first call to this API with
       the same context.
       \note For OFB this function does not support buffer in-place operation
       (pDataIn != pDataOut).

@return \c CC_OK on success,
@return A non-zero value from cc_sm4_error.h on failure.
*/
CIMPORT_C CCError_t  CC_Sm4Block(
    /*! [in]  Pointer to the SM4 context. */
    CCSm4UserContext_t *pContext,
    /*! [in]  Pointer to the buffer of the input data to the SM4. The pointer
    does not need to be aligned. For TrustZone, the size of the scatter/gather
    list that represents the data buffer is limited to 128 entries, and the size
    of each entry is limited to 64KB (entries larger than 64KB are broken into
    fragments <= 64KB). */
    uint8_t *pDataIn,
    /*! [in]  Size of the input data in bytes. For all modes it must be >0 and a
    multiple of 16 bytes. */
    size_t dataSize,
    /*! [out] Pointer to the output buffer. The pointer does not need to be
    aligned. For TrustZone, the size of the scatter/gather list that represents
    the data buffer is limited to 128 entries, and the size of each entry is
    limited to 64KB (entries larger than 64KB are broken into fragments <=
    64KB). */
    uint8_t *pDataOut
);


/*!
@brief This function is used to finish SM4 operation.
       It processes the last data block if needed, and finalizes the SM4
       operation (cipher-specific).
       \note For OFB this function does not support buffer in-place operation
       (pDataIn != pDataOut).

@return \c CC_OK on success,
@return A non-zero value from cc_sm4_error.h on failure.
*/
CIMPORT_C CCError_t  CC_Sm4Finish(
    /*! [in]  Pointer to the SM4 context. */
    CCSm4UserContext_t *pContext,
    /*! [in]  Pointer to the buffer of the input data to the SM4. The pointer
    does not need to be aligned. For TrustZone, the size of the scatter/gather
    list that represents the data buffer is limited to 128 entries, and the size
    of each entry is limited to 64KB (entries larger than 64KB are broken into
    fragments <= 64KB). */
    uint8_t *pDataIn,
    /*! [in]  The size of the input data in bytes. Can be 0. For ECB and CBC
    modes it must be a multiple of 16 bytes. */
    size_t dataSize,
    /*! [out] Pointer to the output buffer. The pointer does not need to be
    aligned. For TrustZone, the size of the scatter/gather list that represents
    the data buffer is limited to 128 entries, and the size of each entry is
    limited to 64KB (entries larger than 64KB are broken into fragments <=
    64KB). */
    uint8_t *pDataOut
);


/*!
@brief This function releases and clears resources after SM4 operations.

@return \c CC_OK on success,
@return A non-zero value from cc_sm4_error.h on failure.
*/
CIMPORT_C CCError_t  CC_Sm4Free(
    /*! [in] Pointer to the SM4 context. */
    CCSm4UserContext_t *pContext
);


/*!
@brief  This function performs a SM4 operation with a given key in a single call
        for all SM4 supported modes, and can be used when all data is available
        at the beginning of the operation.
        \note For OFB this function does not support buffer in-place operation
        (pDataIn != pDataOut).

@return \c CC_OK on success,
@return A non-zero value from cc_sm4_error.h on failure.
*/
CIMPORT_C CCError_t  CC_Sm4(
    /*! [in] Pointer to the buffer of the IV or counter.
    <ul><li> ForCBC mode - the IV value.</li>
    <li>For CTR mode - the counter.</li></ul> */
    CCSm4Iv_t pIV,
    /*! [in]  Pointer to the key data struct to be used for the SM4 operation.
    Must be 128 bits. */
    CCSm4Key_t pKey,
    /*! [in]  A flag specifying whether an SM4 Encrypt (CC_SM4_ENCRYPT) or
    Decrypt (CC_SM4_DECRYPT) operation should be performed. */
    CCSm4EncryptMode_t encryptDecryptFlag,
    /*! [in]  The operation cipher/mode: ECB / CBC / CTR. */
    CCSm4OperationMode_t operationMode,
    /*! [in]  Pointer to the buffer of the input data to the SM4. The pointer
    does not need to be aligned. For TrustZone, the size of the scatter/gather
    list representing the data buffer is limited to 128 entries,
                                                   and the size of each entry is limited to 64KB (fragments larger than 64KB are broken into fragments <= 64KB). */
    uint8_t *pDataIn,
    /*! [in]  Size of the input data in bytes. For all modes it must be >0, and
    a multiple of 16 bytes. */
    size_t dataSize,
    /*! [out] Pointer to the output buffer. The pointer does not need to be
    aligned. For TrustZone, the size of the scatter/gather list that represents
    the data buffer is limited to 128 entries, and the size of each entry is
    limited to 64KB (entries larger than 64KB are broken into fragments <=
    64KB). */
    uint8_t *pDataOut
);

#ifdef __cplusplus
}
#endif
 /*!
 @}
 */
#endif /* #ifndef CC_SM4_H */

