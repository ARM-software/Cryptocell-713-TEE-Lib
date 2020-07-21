/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef  _CC_UTIL_BACKUP_RESTORE_H
#define  _CC_UTIL_BACKUP_RESTORE_H


/*!
@file
@brief This file contains CryptoCell Utility backup and restore functions and definitions.
*/

/*!
 @addtogroup backup_restore_util
 @{
     */


#ifdef __cplusplus
extern "C"
{
#endif

#include "cc_pal_types.h"
#include "cc_util_error.h"
#include "cc_util_defs.h"

/******************************************************************************
*                        	DEFINITIONS
******************************************************************************/
/*!
@brief This function performs backup or restore of memory buffer, according to the flag it is given.
It should not be called directly, but only through the \c CC_UTIL_RAM_BACKUP and \c CC_UTIL_RAM_RESTORE macros.

@return \c CC_OK on success.
@return A non-zero value from \ref cc_util_error.h on failure.
*/
CCError_t CC_UtilBackupAndRestore(
	uint8_t *pSrcBuff,		/*!< [in] Host memory buffer to backup/restore from. */
	uint8_t *pDstBuff,		/*!< [out] Host memory buffer for encrypted/decrypted data. */
	size_t blockSize,		/*!< [in] The size of the data to backup/restore (signature size not included) must be smaller than 64KB. */
	CCBool_t isSramBackup		/*!< [in] The operation type:
						<ul><li> \c CC_TRUE: backup.</li>
						<li> \c CC_FALSE: restore.</li></ul>  */
	);


/*!
@brief This macro is used for power management. Use it upon entry to System-on-Chip suspended state,
to perform Secure backup of on-chip Secure RAM to an off-chip DRAM.
This backed-up data is encrypted and signed with the session key.
The backup must be coupled with a matching restore operation when waking up from a suspended state.
Restoring must be done to the exact same address that was backed up, with the exact same size that was backed up.
\note The session key must be initialized prior to using this API. \par
\note The backup destination buffer should be 16 bytes bigger than the source buffer to accommodate the signature.

@return \c CC_OK on success.
@return A non-zero value from cc_util_error.h on failure.
*/
#define CC_UTIL_RAM_BACKUP(srcAddr, dstAddr, blockSize)	\
	CC_UtilBackupAndRestore(srcAddr, dstAddr, blockSize, CC_TRUE)


/*!
@brief This macro is used for power management. Use it upon wakeup from suspended state,
to restore the data that was backed up upon entry to suspended state.
The source buffer is decrypted and verified with the session key.
The restore operation must match a previous backup operation.
Restoring must be done to the same address and with the same size that was previously backed up.
\note The session key cannot be replaced between matching backup and restore operations. \par
\note If the FIPS certification support is set to ON, this function is also responsible for delivering the TEE FIPS status to the REE
after waking up from suspended state.

@return \c CC_OK on success.
@return A non-zero value from cc_util_error.h on failure.
*/
#define CC_UTIL_RAM_RESTORE( srcAddr, dstAddr, blockSize)	\
	CC_UtilBackupAndRestore(srcAddr, dstAddr, blockSize, CC_FALSE)




#ifdef __cplusplus
}
#endif
/*!
 @}
 */

#endif /*_CC_UTIL_BACKUP_RESTORE_H*/
