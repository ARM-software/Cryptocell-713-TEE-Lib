/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

/*!
@file
@brief This file contains all the enumerations and definitions that are used for the
        CryptoCell CPP APIs, as well as the APIs themselves.

        The TEE side support for CPP includes the "control" APIs which allow
        the following functionality:
		<ul>
        <li>Configure the watchdog (enable/disable and setting the timer).</li>
        <li>Set the in and out sMMU stream ID to be used by the operation.</li>
        <li>Set watchdog timer.</li>
        <li>Register and unregister a callback to be called on when the hardware
           indicates the TEE needs to accept or reject a REE CPP key slot
	   usage.</li>
	   </ul>

        The TEE side support for CPP also includes the "flow" API that allows you to implement the "policy" reference
        application:
		<ul>
        <li>Get the parameters of the requested operation (key index, algorithm,
           operation, mode and data size), verify them and reload the
           watchdog timer.</li>
        <li>Get ancillary parameters about the requested operations: IV or CTR,
           depending on the requested mode of operation.</li>
        <li>Get an array of the bus addresses and sizes of the buffers involved
           in the operation.</li>
		</ul>
*/

/*!
 @addtogroup cc_cpp_apis
 @{
     */

#ifndef _CC_CPP_H_
#define _CC_CPP_H_

#include "cc_pal_types.h"
#include "cc_address_defs.h"
#include "cc_lli_defs.h"

/*! 128 bits key length equal to 4 words. */
#define CC_128_BIT_KEY_SIZE_IN_WORDS    4
/*! 256 bits key length equal to 8 words. */
#define CC_256_BIT_KEY_SIZE_IN_WORDS    8
/*! 128 bits key length equal to 16 bytes. */
#define CC_128_BIT_KEY_SIZE_IN_BYTES    16
/*! 256 bits key length equal to 32 bytes. */
#define CC_256_BIT_KEY_SIZE_IN_BYTES    32

/*! This error is returned when Secure Disable control is set. */
#define CC_CPP_SD_ENABLED_ERROR         (CC_CPP_MODULE_ERROR_BASE + 0)
/*! This error is returned when one pf function parameters is wrong. */
#define CC_CPP_WRONG_PARAMETERS_ERROR   (CC_CPP_MODULE_ERROR_BASE + 1)
/*! This error is returned when watchdog is expired. */
#define CC_CPP_EXPIRED_WATCHDOG_ERROR   (CC_CPP_MODULE_ERROR_BASE + 2)
/*! This error is returned when required operation is not supported. */
#define CC_CPP_NOT_SUPPORTED_OP_ERROR   (CC_CPP_MODULE_ERROR_BASE + 3)
/*! This error is returned when device is locked in fatal error state. */
#define CC_CPP_FATAL_ERR_IS_LOCKED_ERR  (CC_CPP_MODULE_ERROR_BASE + 4)

/*!
@brief This structure is used to report back buffers used by CPP operations.
*/
typedef struct CCCppBuffer_t {
    CCDmaAddr_t bus_addr;   /*!< Buffer address. */
    size_t      size;       /*!< Buffer size.*/
}CCCppBuffer_t;

/*!
@brief This structure is used to report back buffers used by CPP operations.
*/
typedef struct CCCppBufInfo_t {
    CCCppBuffer_t buffers[LLI_MAX_NUM_OF_ENTRIES];  /*!< Buffer parameters. */
    uint32_t numberOfEntries;                       /*!< Number of entries. */
}CCCppBufInfo_t;

/*!
@brief This structure is used to report CPP operation parameters.
*/
typedef enum CCCppOp_t {
     CC_CPP_ENCRYPT_OP = 0, /*!< Encrypt operation. */
     CC_CPP_DECRYPT_OP = 1  /*!< Decrypt operation. */
}CCCppOp_t;

/*!
@brief This structure is used to report CPP operation parameters.
*/
typedef enum CCCppMode_t {
    CC_CPP_CBC_MODE = 1,    /*!< CBC mode. */
    CC_CPP_CTR_MODE = 2,    /*!< CTR mode. */
    CC_CPP_NOT_SUPPORTED_MODE, /*!< Unsupported mode. */
}CCCppMode_t;

/*!
@brief This structure is used to report CPP key size parameters.
*/
typedef enum CCCppKeySize_t {
    CC_CPP_KEY_SIZE_128 = 0,    /*!< 128 bit key. */
    CC_CPP_KEY_SIZE_256 = 2,    /*!< 256 bit key. */
    CC_CPP_NOT_SUPPORTED_KEY_SIZE, /*!< Unsupported key size. */
}CCCppKeySize_t;


/*!
@brief This structure is used to report CPP operation parameters.
*/
typedef enum CCCppEngine_t {
     CC_CPP_AES_ENGINE = 0, /*!< AES engine. */
     CC_CPP_SM4_ENGINE = 1  /*!< SM4 engine. */
}CCCppEngine_t;

/*!
@brief This structure is used to report CPP operation parameters.
*/
typedef struct {
     uint32_t       dataSize;   /*!< Data size. */
     uint8_t        keySlot;    /*!< Key slot.  */
     CCCppKeySize_t keySize;    /*!< Key size. */
     CCCppMode_t    mode;       /*!< Mode CTR/CBC. */
     CCCppEngine_t  engine;     /*!< Cryptographic engine AES/SM4. */
     CCCppOp_t      direction;  /*!< Direction encrypt/decrypt. */
     union {
         /*! IV data in bytes. */
         unsigned char iv[CC_128_BIT_KEY_SIZE_IN_BYTES];
         /*! IV data in words. */
         uint32_t iv_data[CC_128_BIT_KEY_SIZE_IN_WORDS];
     }ivData; /*!< IV data.*/
}CCCppOpParams_t;

/*!
@brief The typedef of CPP event function ("policy").
*/
typedef void (*CCCppEventFunction)(void*);

/*!
@brief This function sets stream ID to the appropriate register.

@return \c CC_OK on success.
@return A non-zero value in case of failure.
*/
CCError_t CC_CppStreamIdSet(
        uint16_t read_stream_id, /*!< [in]  Reads stream ID value. */
        uint16_t write_stream_id /*!< [in]  Writes stream ID value. */ );

/*!
@brief This function sets watchdog.

@return \c CC_OK on success.
@return A non-zero value in case of failure.
*/
CCError_t CC_CppWatchdogSet(
        CCBool enable,        /*!< [in]  Enable or disable watchdog. */
        uint32_t cycles       /*!< [in]  Number of watchdog cycles. */  );

/*!
@brief This function sets CPP Operation Key.

@return \c CC_OK on success.
@return A non-zero value in case of failure.
*/
CCError_t CC_CppKeySet(
        CCCppEngine_t  engine,   /*!< [in]  CPP engine type. */
        CCCppKeySize_t keySize, /*!< [in]  CPP key size.  */
        uint8_t *pKey           /*!< [in]  CPP key value . */);
/*!
@brief This function parses descriptor loaded to register by hardware and
       fill bufInfoIn and bufInfoOut structures.

@return \c CC_OK on success.
@return A non-zero value in case of failure.
*/
CCError_t CC_CppBufInfoGet (
        CCCppBufInfo_t *bufInfoIn,/*!< [out] Buffer in data. */
        CCCppBufInfo_t *bufInfoOut/*!< [out] Buffer out data. */);

/*!
@brief This function handles CPP Operation.

@return \c CC_OK on success.
@return A non-zero value in case of failure.
*/
CCError_t CC_CppHandleOp(
        CCBool accept/*!< [in] Accepts or rejects CPP operation. */
        );

/*!
@brief This function receives the currently pending CPP operation for processing.

@return \c CC_OK on success.
@return A non-zero value in case of failure.
*/
CCError_t CC_CppRecvOp(
        CCCppOpParams_t *opParams /*!< [out] CPP operation parameters. */
        );

/*!
@brief This function registers external function ("policy") to handle CPP event.

@return  void
*/
void CC_CppRegisterEventRoutine (CCCppEventFunction pFunc);
/*!
 @}
 */
#endif // _CC_CPP_H_
