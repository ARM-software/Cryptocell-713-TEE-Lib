/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

/*!
@file
@brief This file contains all the enums and definitions
that are used for the CryptoCell Hash APIs, as well as the APIs themselves.
*/

/*!
@addtogroup cc_hash
@brief This product supports the following Hash algorithms (or modes, according to product):
<ul><li> CC_HASH_MD5_mode (producing 16 byte output).</li>
<li> CC_HASH_SHA1_mode (producing 20 byte output).</li>
<li> CC_HASH_SHA224_mode (producing 28 byte output).</li>
<li> CC_HASH_SHA256_mode (producing 32 byte output).</li>
<li> CC_HASH_SHA384_mode (producing 48 byte output).</li>
<li> CC_HASH_SHA512_mode (producing 64 byte output).</li></ul>

HASH calculation can be performed in either of the following two modes of operation:
<ul><li> Integrated operation - Processes all data in a single function call. This flow is applicable when all data is available prior to the
	 cryptographic operation.</li>
<li> Block operation - Processes a subset of the data buffers, and is called multiple times in a sequence. This flow is applicable when the
     next data buffer becomes available only during/after processing of the current data buffer.</li></ul>

The following is a typical Hash Block operation flow:
<ol><li> ::CC_HashInit - this function initializes the Hash machine on the CryptoCell level by setting the context pointer that is used on the entire
	 Hash operation.</li>
<li> ::CC_HashUpdate - this function runs a Hash operation on a block of data allocated by the user. This function may be called as many times
     as required.</li>
<li> ::CC_HashFinish - this function ends the Hash operation. It returns the digest result and clears the context.</li></ol>
@{
    */



#ifndef _CC_HASH_H
#define _CC_HASH_H


#include "cc_pal_types.h"
#include "cc_error.h"
#include "cc_hash_defs.h"

#ifdef __cplusplus
extern "C"
{
#endif


/************************ Public Variables **********************/

/************************ Public Functions **********************/


/************************************************************************************************/
/*!
@brief This function initializes the Hash machine and the Hash Context.

It receives as input a pointer to store the context handle to the Hash Context,
and initializes the Hash Context with the cryptographic attributes that are needed for the Hash block operation (initializes H's value for the Hash algorithm).

@return \c CC_OK on success.
@return A non-zero value from cc_hash_error.h on failure.
*/
CIMPORT_C CCError_t CC_HashInit(
                        CCHashUserContext_t     *ContextID_ptr,         /*!< [in]  Pointer to the Hash context buffer allocated by the user that is used
										for the HASH machine operation. */
                        CCHashOperationMode_t  OperationMode           /*!< [in]  One of the supported Hash modes, as defined in CCHashOperationMode_t(). */
);

/************************************************************************************************/
/*!
@brief This function processes a block of data to be HASHed.

It updates a HASH Context that was previously initialized by CC_HashInit() or updated by a previous call to CC_HashUpdate().

@return \c CC_OK on success.
@return A non-zero value from cc_hash_error.h on failure.
*/

CIMPORT_C CCError_t CC_HashUpdate(
                        CCHashUserContext_t  *ContextID_ptr,         /*!< [in]  Pointer to the Hash context buffer allocated by the user, which is used for the
										   HASH machine operation. */
                        uint8_t                 *DataIn_ptr,            /*!< [in]  Pointer to the input data to be HASHed.
                                                                                   The size of the scatter/gather list representing the data buffer is limited to
										   128 entries, and the size of each entry is limited to 64KB
										   (fragments larger than 64KB are broken into fragments <= 64KB). */
                        size_t                  DataInSize             /*!< [in]  Byte size of the input data. Must be > 0.
                                                                                    If not a multiple of the Hash block size (64 for MD5, SHA-1 and SHA-224/256,
										    128 for SHA-384/512), no further calls
                                                                                    to CC_HashUpdate() are allowed in this context, and only CC_HashFinish()
										    can be called to complete the computation. */
);

/************************************************************************************************/
/*!
@brief This function finalizes the hashing process of data block.

It receives a handle to the Hash context, which was previously initialized by CC_HashInit() or by CC_HashUpdate().
It "adds" a header to the data block according to the relevant Hash standard, and computes the final message digest.

@return \c CC_OK on success.
@return A non-zero value from cc_hash_error.h on failure.
*/

CIMPORT_C CCError_t CC_HashFinish(
                        CCHashUserContext_t  *ContextID_ptr,         /*!< [in]  Pointer to the Hash context buffer allocated by the user that is used for
										   the HASH machine operation. */
                        CCHashResultBuf_t       HashResultBuff         /*!< [in]  Pointer to the word-aligned 64 byte buffer. The actual size of the HASH
										   result depends on CCHashOperationMode_t(). */
);


/************************************************************************************************/
/*!
@brief This function is a utility function that frees the context if the operation has failed.

The function executes the following major steps:
<ol><li> Checks the validity of all of the inputs of the function. </li>
<li> Clears the user's context.</li>
<li> Exits the handler with the \c OK code.</li></ol>

@return \c CC_OK on success.
@return A non-zero value from cc_hash_error.h on failure.
*/

CIMPORT_C CCError_t  CC_HashFree(
                        CCHashUserContext_t  *ContextID_ptr         /*!< [in]  Pointer to the HASH context buffer allocated by the user that is used for
										 the HASH machine operation. */
);


/************************************************************************************************/
/*!
@brief This function processes a single buffer of data.

The function allocates an internal hash context, and initializes it with the cryptographic attributes
that are needed for the Hash block operation (initialize H's value for the Hash algorithm).
Then it processes the data block, calculating the Hash. Finally, it returns the data buffer message digest.

@return \c CC_OK on success.
@return A non-zero value from cc_hash_error.h on failure.
 */

CIMPORT_C CCError_t CC_Hash  (
                        CCHashOperationMode_t  OperationMode,       /*!< [in]  One of the supported HASH modes, as defined in CCHashOperationMode_t(). */
                        uint8_t                   *DataIn_ptr,          /*!< [in]  Pointer to the input data to be HASHed.
                                                                                   The size of the scatter/gather list representing the data buffer is limited
										   to 128 entries, and the size of each entry is limited to 64KB
										   (fragments larger than 64KB are broken into fragments <= 64KB). */
                        size_t                     DataSize,            /*!< [in]  The size of the data to be hashed in bytes. */
                        CCHashResultBuf_t         HashResultBuff       /*!< [out] Pointer to a word-aligned 64 byte buffer. The actual size of the HASH
										   result depends on CCHashOperationMode_t(). */
);



#ifdef __cplusplus
}
#endif
 /*!
 @}
 */
#endif
