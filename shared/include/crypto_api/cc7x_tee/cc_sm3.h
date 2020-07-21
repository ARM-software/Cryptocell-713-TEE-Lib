/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */
#ifndef _CC_SM3_H
#define _CC_SM3_H

/*!
@file
@brief This file contains all the enums and definitions
that are used for the CryptoCell SM3 APIs, as well as the APIs themselves.
*/

/*!
 @addtogroup cc_sm3
 @{
     */




#include "cc_pal_types.h"
#include "cc_error.h"
#include "cc_sm3_defs.h"

#ifdef __cplusplus
extern "C"
{
#endif


/*****************************************************************************/
/*!
@brief This function initializes the SM3 machine and the SM3 Context.

It receives a pointer to SM3 context, and initializes it with the cryptographic
attributes that are needed for the SM3 block operation (initializes H's value
for the SM3 algorithm).

 @param pContextID  Pointer to the SM3 context buffer. (allocated by the user)

 @return \c CC_OK on success.
 @return  A non-zero value from cc_sm3_error.h on failure.
*/
CIMPORT_C CCError_t CC_Sm3Init(CCSm3UserContext_t *pContextID);


/*****************************************************************************/
/*!
@brief This function processes a block of data to be HASHed.

It updates a SM3 Context that was previously initialized by ::CC_Sm3Init() or
updated by a previous call to ::CC_Sm3Update().

@param pContextID  Pointer to the SM3 context buffer. (allocated by the user)

@param pDataIn     Pointer to the buffer that stores the data to be hashed.

@param DataInSize  The size of the data to be hashed in bytes.

 @return \c CC_OK on success.
 @return A non-zero value from cc_sm3_error.h on failure.
*/
CIMPORT_C CCError_t CC_Sm3Update(CCSm3UserContext_t *pContextID, uint8_t *pDataIn, size_t DataInSize);


/*****************************************************************************/
/*!
@brief This function finalizes the process of SM3 data block.

It receives a handle to the SM3 Context, which was previously initialized by
::CC_Sm3Init() or by ::CC_Sm3Update().
It "adds" a header to the data block according to the relevant SM3 standard,
and computes the final message digest.

 @param pContextID  Pointer to the SM3 context buffer.

 @retval Sm3ResultBuff Pointer to the result buffer for the the message digest.

 @return \c CC_OK on success.
 @return A non-zero value from cc_sm3_error.h on failure.
*/
CIMPORT_C CCError_t CC_Sm3Finish(CCSm3UserContext_t *pContextID, CCSm3ResultBuf_t Sm3ResultBuff);


/*****************************************************************************/
/*!
@brief This function frees the context if the operation had failed.

@param pContextID  Pointer to the SM3 context buffer.

 @return \c CC_OK on success
 @return A non-zero value from cc_sm3_error.h on failure.
*/
CIMPORT_C CCError_t  CC_Sm3Free(CCSm3UserContext_t *pContextID);


/*****************************************************************************/
/*!
@brief This function provides an SM3 function to process one buffer of data.

The function allocates an internal SM3 Context, and initializes it with the
cryptographic attributes that are needed for the SM3 block operation
(initializes the value of H for the SM3 algorithm).
Then it processes the data block, calculating the SM3 hash.
Finally, it returns the data buffer's message digest.

 @param pDataIn     Pointer to the buffer that stores the data to be hashed.

 @param DataInSize  The size of the data to be hashed in bytes.

 @retval Sm3ResultBuff Pointer to the result buffer for the the message digest.

 @return \c CC_OK on success.
 @return A non-zero value from cc_sm3_error.h on failure.
 */
CIMPORT_C CCError_t CC_Sm3(uint8_t *pDataIn, size_t DataInSize, CCSm3ResultBuf_t Sm3ResultBuff);


#ifdef __cplusplus
}
#endif

 /*!
 @}
 */
#endif
