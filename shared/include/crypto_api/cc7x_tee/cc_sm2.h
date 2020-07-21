/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _CC_SM2_H
#define _CC_SM2_H



/*!
 @file
 @brief This file defines the APIs that support the SM2 functions.

 @details
   Using Sign/Verify API is straightforward. Call the Sign/Verify functions and provide the message hash that should be
   calculated by Sm2ComputeMessageDigest.

   Use the key exchange APIs in the following order:
   <ol> <li>Both parties should first call to the CC_Sm2KeyExchangeContext_init() function.</li>

   <li>Party A should call CC_Sm2CalculateECPoint() and send the
   ephemeral public key to the party B.</li>

   <li> After calling CC_EcpkiPubKeyExport() the ephemeral public key should be sent as
   a byte array.</li>

   <li>The party B needs to verify that the ephemeral public key from party A is on the
   curve, by calling CC_EcpkiPublKeyBuildAndCheck() with checkmode=ECpublKeyPartlyCheck.</li>

   <li>Party B in its order should call to CC_Sm2CalculateECPoint() and
   CC_Sm2CalculateSharedSecret() functions and send the ephemeral public key and,
   optionally the outside confirmation value to the party A.</li>

   <li>The party A - calls CC_Sm2CalculateSharedSecret() and optionally sends
   to party B its outside confirmation value.</li>

   <li>Each party may call the CC_Sm2Confirmation() function if a confirmation value was used in the previous steps.</li>

   <li> In case of an agreement, each party calls the CC_Sm2Kdf() function in order to finally get
   the shared key.</li></ol>
    */

/*!
 @addtogroup cc_sm2
 @{
 */


#include "cc_error.h"
#include "cc_ecpki_types.h"
#include "cc_rnd_common.h"
#include "cc_sm3_defs.h"
#include "cc_pal_types.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*! SM2 - Length of the module in words. */
#define CC_SM2_MODULE_LENGTH_IN_WORDS   8
/*! SM2- Length of the the base point order in words. */
#define CC_SM2_ORDER_LENGTH_IN_WORDS    8
/*! SM2 -  Length of the module in bytes. */
#define CC_SM2_MODULE_LENGTH_IN_BYTES   32
/*! SM2 - Length of the base point order in bytes. */
#define CC_SM2_ORDER_LENGTH_IN_BYTES    32
/*! SM2 - Max length of ID in bytes. */
#define CC_SM2_MAX_ID_LEN_IN_BITS       65535
/*! SM2 - Max length of ID in bytes. */
#define CC_SM2_MAX_ID_LEN_IN_BYTES       CC_SM2_MAX_ID_LEN_IN_BITS / CC_BITS_IN_BYTE
/*! SM2 - Max length of message in bytes. */
#define CC_SM2_MAX_MESSEGE_LEN          (1UL << 29)
/*! SM2 - Signature output size in bytes. */
#define CC_SM2_SIGNATURE_LENGTH_IN_BYTES    CC_SM2_ORDER_LENGTH_IN_BYTES * 2
/*! SM2-  Confirmation value size in bytes. */
#define CC_SM2_CONF_VALUE_LENGTH_IN_BYTES   CC_SM3_RESULT_SIZE_IN_BYTES
/*! SM2-  Max size of input and ID -
 * chosen based on implementation of certification KAT tests.*/
#define CERT_SM2_DEFAULT_INPUT_AND_ID_SIZE  32




/**************************************************************************
 *                Structs
 **************************************************************************/
/*! SM2 self-test data structure for Chinese certification. */
typedef struct CCSm2FipsKatContext_t{
    uint8_t                         workBuff[2 + CC_SM2_MODULE_LENGTH_IN_BYTES*4 +
                                                 CC_SM2_ORDER_LENGTH_IN_BYTES*2 + CERT_SM2_DEFAULT_INPUT_AND_ID_SIZE];
                                            /*!< The working buffer for ::CC_Sm2ComputeMessageDigest. */
    CCRndGenerateVectWorkFunc_t     f_rng;  /*!< A pointer to DRBG function.*/
    void                            *p_rng; /*!< A pointer to the random context - the input to f_rng.*/
}CCSm2FipsKatContext_t;
/*! SM2 self-test data structure for certification. */
typedef struct CCSm2KeyGenCHCertContext_t{
    uint8_t                         workBuff[2 + CC_SM2_MODULE_LENGTH_IN_BYTES*4 +
                                                 CC_SM2_ORDER_LENGTH_IN_BYTES*2 + CERT_SM2_DEFAULT_INPUT_AND_ID_SIZE];
                                            /*!< The working buffer for ::CC_Sm2ComputeMessageDigest */
}CCSm2KeyGenCHCertContext_t;



/*! A structure to define key exchange context. All byte arrays in this structure are stored in the big-endian byte ordering,
* and all word arrays are in the little endian byte and word ordering. */

typedef struct CC_Sm2KeContext_t {
    /*! A flag to define the initiator of the key exchange protocol. */
    int                         isInitiator;
    /*! The first bit encodes whether this party wants a confirmation. The second bit encodes the confirmation for other party
     * for example: 3 - for both partys, 1 - only this party wants confirmation, 2 - only the other party wants confirmation.*/
    uint8_t                     confirmation;
    /*! The public key of this party.*/
    CCEcpkiUserPublKey_t        pubKey;
    /*! The private key of this party.*/
    CCEcpkiUserPrivKey_t        privKey;
    /*! The public key of the other party.*/
    CCEcpkiUserPublKey_t        remotePubKey;
    /*! The ephemeral public key of this party.*/
    CCEcpkiPointAffine_t        ephemeral_pub;
    /*! The size in bytes of the ephemeral public key of this party.*/
    size_t                      eph_pub_key_size;
    /*! The ephemeral public key of other party.*/
    CCEcpkiPointAffine_t        remote_ephemeral_pub;
    /*! The size in bytes of the ephemeral public key of other party.*/
    size_t                      remote_eph_pub_key_size;
    /*! Pointer to the ID of this party as string.*/
    const char                  *pId;
    /*! The size in bytes of the ID of this party.*/
    size_t                      idlen;
    /*! Pointer to the ID of the other party as string (remote ID).*/
    const char                  *pRemoteId;
    /*! The size in bytes of the ID of the other party.*/
    size_t                      remoteIdLen;
    /*! t value calculated and stored in CC_Sm2CalculateECPoint() function. */
    uint32_t                    t[CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
    /*!  The shared secret, V/U value (shared secret) calculated and stored in CC_Sm2CalculateSharedSecret() function. */
    CCEcpkiPointAffine_t        V;
    /*!  The internal confirmation value of this side calculated and stored if confirmation == 1 or
     * confirmation == 3 in CC_Sm2CalculateSharedSecret() function.   */
    uint8_t                     conf_value[CC_SM3_RESULT_SIZE_IN_BYTES];
    /*!  Size of the confirmation value. */
    size_t                      conf_value_size;
    /*!  ID digests of this party - calculated and stored in
     * CC_Sm2KeyExchangeContext_init() function.*/
    uint8_t                     Z[CC_SM3_RESULT_SIZE_IN_BYTES];
    /*!  ID digests of the other party - calculated and stored in
     * CC_Sm2KeyExchangeContext_init() function.*/
    uint8_t                     Z_remote[CC_SM3_RESULT_SIZE_IN_BYTES];
    /*!  Size of the ID digest*/
    size_t                      Z_value_size;
} CC_Sm2KeContext_t;

/**************************************************************************
 *                    CC_Sm2Sign
 **************************************************************************/
/*!
@brief This function performs an SM2 sign operation.

 @details Algorithm according to the Public key cryptographic algorithm SM2 based
on elliptic curves. Part 2: Digital signature algorithm

It takes as an input the message digest as little-endian words that come
 as an output from the ::CC_Sm2ComputeMessageDigest() function.

@return \c CC_OK on success.
@return A non-zero value on failure as defined cc_ecpki_error.h,
cc_sm3_error.h, or cc_rnd_error.h.
*/

CIMPORT_C CCError_t CC_Sm2Sign(
        CCRndGenerateVectWorkFunc_t     f_rng,             /*!< [in]      A pointer to DRBG function.*/
        void                            *p_rng,            /*!< [in/out]  A pointer to the random context - the input to f_rng.*/
        const CCEcpkiUserPrivKey_t      *pSm2PrivKey,      /*!< [in]      A pointer to a private key structure. */
        const uint32_t                  *pHashInput,       /*!< [in]      A pointer to the hash of the input data. */
        const size_t                    HashInputSize,     /*!< [in]      Size in words to the hash of the input data. */
        uint8_t                         *pSignatureOut,    /*!< [out]     Pointer to a buffer for output of signature. */
        size_t                          *pSignatureOutSize /*!< [in/out]  A pointer to the signature size. Used to pass the size of the
                                                                            SignatureOut buffer (in), which must be >= 2 * OrderSizeInBytes.
                                                                            When the API returns, it is replaced with the size
                                                                            of the actual signature (out). */
);

/**************************************************************************
 *                    CC_Sm2Verify
 **************************************************************************/
/*!
@brief This function performs an SM2 verify operation in integrated form.

 @details Algorithm according to the Public key cryptographic algorithm SM2 based on elliptic curves.
                        Part 2: Digital signature algorithm

It takes as an input the message digest as little-endian words that come
 as an output from the ::CC_Sm2ComputeMessageDigest() function.

@return \c CC_OK on success.
@return A non-zero value on failure as defined cc_ecpki_error.h or cc_sm3_error.h.
*/

CIMPORT_C CCError_t CC_Sm2Verify (
        const CCEcpkiUserPublKey_t      *pUserPublKey,         /*!< [in]     A pointer to a public key structure. */
        uint8_t                         *pSignatureIn,         /*!< [in]     A pointer to the signature to be verified. */
        const size_t                    SignatureSizeBytes,    /*!< [in]     The size of the signature (in bytes).  */
        const uint32_t                  *pHashInput,           /*!< [in]     A pointer to the hash of the input data that was signed. */
        const size_t                    HashInputSize          /*!< [in]     Size in words of the hash of the input data. */
);


/******************************************************************************
 *                CC_Sm2ComputeMessageDigest
 ******************************************************************************/
/*!
@brief This function calculates both the ID digest and the message digest.

@return \c CC_OK on success.
@return A non-zero value on failure as defined cc_ecpki_error.h or cc_sm3_error.h.
*/

/******************************************************************************/

CIMPORT_C CCError_t CC_Sm2ComputeMessageDigest (
        const CCEcpkiUserPublKey_t  *pUserPublKey,  /*!< [in]       A pointer to the public key. */
        const char                  *pId,           /*!< [in]       A pointer to the ID. */
        const size_t                idlen,          /*!< [in]       The size of ID in bytes. */
        const uint8_t               *pMsg,          /*!< [in]       A pointer to the message. */
        const size_t                msglen,         /*!< [in]       The size of the message in bytes. */
        uint8_t                     *pWorkingBuffer,/*!< [in]       The working buffer. */
        const size_t                wblen,          /*!< [in]       The working buffer size should be at least
                                                                            2 + modSizeInBytes*4 + ordSizeInBytes*2 + idlen + msglen*/

        uint32_t                    *pOut,          /*!< [out]     A pointer to a buffer for the output. */
        size_t                      *pOutlen        /*!< [in/out]  A pointer to the output length in words. */
);



/******************************************************************************
 *                    CC_Sm2KeyExchangeContext_init
 * *****************************************************************************/
/*!
@brief The context initiation.

@return \c CC_OK on success.
@return A non-zero value on failure.
 */

CIMPORT_C CCError_t CC_Sm2KeyExchangeContext_init(
        CC_Sm2KeContext_t               *pCtx,              /*!< [in/out]    You should allocate this pointer. This function initiates it.*/
        uint8_t                         *pWorkingBuffer,    /*!< [in]        The working buffer. */
        const size_t                    wblen,              /*!< [in]        The working buffer size should be at least
                                                                                  2 + modSizeInBytes*4 + ordSizeInBytes*2 + max(idlen, ridlen). */
        CCEcpkiUserPublKey_t            *pPubKey,           /*!< [in]        The data of the public key. */
        CCEcpkiUserPrivKey_t            *pPrivKey,          /*!< [in]        The data of the private key. */
        CCEcpkiUserPublKey_t            *pRemoteUserPubKey, /*!< [in]        The data of the remote public key. */
        const char                      *pId,                /*!< [in]       A pointer to the ID. */
        size_t                          idlen,              /*!< [in]        The ID size in bytes. */
        const char                      *pRemoteId,          /*!< [in]       A pointer to an remote ID. */
        size_t                          remoteIdLen,        /*!< [in]        The remote ID size in bytes. */
        uint8_t                         is_initiator,       /*!< [in]        Set to 1 if it is an initiator side. */
        uint8_t                         conf_required       /*!< [in]        Bit mask - 1st bit if you want confirmation, 2nd bit if the other party wants confirmation.*/
);

/**************************************************************************
 *                    CC_Sm2KeyExchangeContext_cleanup
 * **************************************************************************/
/*!
@brief The context cleanup.

@return void.
*/
CIMPORT_C void CC_Sm2KeyExchangeContext_cleanup(
        CC_Sm2KeContext_t           *pCtx );      /*!< [in]        A pointer to a context structure. */

/**************************************************************************
 *                    Sm2 KDF
 * *************************************************************************/
/*!
@brief The KDF

@return \c CC_OK on success.
@return A non-zero value on failure
*/

CIMPORT_C CCError_t CC_Sm2Kdf (
        const CC_Sm2KeContext_t     *pCtx,                  /*!< [in] A pointer to a key exchange context.*/
        const size_t                SharedSecretSizeInBits, /*!< [in] The required size of the key in bits. */
        uint8_t                     *pKeyOut,               /*!< [in] A pointer to a buffer for the derived key. */
        size_t                      *pKeyOutSize            /*!< [in/out] A pointer to the derived key size in bytes.*/
);

/**************************************************************************
 *                    CC_Sm2CalculateECPoint
 * *************************************************************************/
/*!

@brief Calculates a random ECPoint.

@return \c CC_OK on success.
@return A non-zero value on failure
*/

CIMPORT_C CCError_t CC_Sm2CalculateECPoint (
        CCRndGenerateVectWorkFunc_t f_rng,        /*!< [in]         A pointer to DRBG function. */
        void                        *p_rng,       /*!< [in/out]     A pointer to the random context - the input to f_rng. */
        CC_Sm2KeContext_t           *pCtx,        /*!< [in/out]     A pointer to a KE context.  */
        CCEcpkiUserPublKey_t        *pRandomPoint /*!< [out]        The output random EC point as an ephemeral public key. */
);




/**************************************************************************
 *                    CC_Sm2CalculateSharedSecret
 * *************************************************************************/
/*!

@brief Calculates shared secret and optionally the internal confirmation value and stores
     *  them into the context. Optionally calculates output confirmation value.

@return \c CC_OK on success.
@return A non-zero value on failure.
 */

CIMPORT_C CCError_t CC_Sm2CalculateSharedSecret (
        CC_Sm2KeContext_t           *pCtx,                      /*!< [in/out]   A pointer to the key exchange context.*/
        const CCEcpkiUserPublKey_t  *pRandomPoint,              /*!< [in]       A pointer to the random point from the second party. */
        uint8_t                     *pConfirmationValueOut,     /*!< [out]      The output confirmation value.        */
        size_t                      *pConfirmationValueOutSize  /*!< [in/out]   A pointer to the output confirmation value size in bytes.   */
);



/**************************************************************************
 *                    CC_Sm2Confirmation
 * *************************************************************************/
/*!

@brief Verifies the confirmation value sent by other side with the one
calculated and stored in the context.

@return \c CC_OK on success.
@return A non-zero value on failure.
*/



CIMPORT_C CCError_t CC_Sm2Confirmation (
        const CC_Sm2KeContext_t     *pCtx,                      /*!< [in/out]   Pointer to the key exchange context.*/
        const uint8_t               *pConfirmationValue,        /*!< [in]       A pointer to a second party confirmation value. */
        const size_t                confirmationValueSize       /*!< [in/out]   Second party confirmation size. */
) ;





#ifdef __cplusplus
}
#endif
/*!
 @}
 */

#endif
