/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

/*!
 @file
 @brief This file contains functions for memory operations.

 The functions are generally implemented as wrappers to different operating-system calls.

 \note None of the described functions validate the input parameters, so that the behavior
       of the APIs in case of an illegal parameter is dependent on the behavior of the operating system.
 */


 /*!
  @addtogroup cc_pal_mem
  @{
  */

#ifndef _CC_PAL_MEM_H
#define _CC_PAL_MEM_H


#ifdef __cplusplus
extern "C"
{
#endif

#include "cc_pal_types.h"
#include "cc_pal_mem_plat.h"
#include "cc_pal_malloc_plat.h"
#include <stdlib.h>
#include <string.h>

    /*----------------------------
      PUBLIC FUNCTIONS
-----------------------------------*/

    /**** ----- Memory Operations APIs ----- ****/
 /* verify these parameter descriptions */
/*!
  @brief This function compares between two given buffers, according to the given size.

 @param aSize Size of buffer expressed in bytes.
 @param aSource Source buffer.
 @param aTarget Target buffer.
  @return The return values are according to operating system return values.
 */
#define CC_PalMemCmp(aTarget, aSource, aSize) CC_PalMemCmpPlat(aTarget, aSource, aSize)

/*!
  @brief This function copies \p aSize bytes from the source buffer to the destination buffer.
  @param aSize Size of buffer expressed in bytes.
  @param aSource Source buffer.
  @param aDestination Destination buffer.
  @return void.
 */
#define CC_PalMemCopy(aDestination, aSource, aSize) CC_PalMemCopyPlat(aDestination, aSource, aSize)

/*!
  @brief This function moves \p aSize bytes from the source buffer to the destination buffer.
  This function supports overlapped buffers.
  @param aSize Size of buffer expressed in bytes.
  @param aSource Source buffer.
  @param aDestination Destination buffer.
  @return void.
 */
#define CC_PalMemMove(aDestination, aSource, aSize) CC_PalMemMovePlat(aDestination, aSource, aSize)


/*!
  @brief This function sets \p aSize bytes of \p aChar in the given buffer.
  @param aSize Size of buffer expressed in bytes.
  @param aChar Target character.
  @param aTarget Target buffer.
  @return void.
 */
#define CC_PalMemSet(aTarget, aChar, aSize) CC_PalMemSetPlat(aTarget, aChar, aSize)


/*!
  @brief This function sets \p aSize bytes in the given buffer with zeroes.
  @param aSize Size of buffer expressed in bytes.
  @param aTarget Target buffer
  @return void.
 */
#define CC_PalMemSetZero(aTarget, aSize) CC_PalMemSetZeroPlat(aTarget, aSize)


/*!
  @brief This function allocates a memory buffer according to \p aSize.
  @param aSize Size of buffer expressed in bytes.
  @return A pointer to the allocated buffer on success.
  @return NULL on failure.
 */
#define CC_PalMemMalloc(aSize) CC_PalMemMallocPlat(aSize)

/*!
  @brief This function reallocates a memory buffer according to \p aNewSize.
         The contents of the old buffer is moved to the new location.
  @param aBuffer Target buffer.
  @param aNewSize New size of buffer expressed in bytes.
  @return A pointer to the newly-allocated buffer on success.
  @return NULL on failure.
 */
#define CC_PalMemRealloc(aBuffer, aNewSize) CC_PalMemReallocPlat(aBuffer, aNewSize)

/*!
  @brief This function frees a previously-allocated buffer.
  @param aBuffer Target buffer.

  @return void.
 */
#define CC_PalMemFree(aBuffer) CC_PalMemFreePlat(aBuffer)

#ifdef __cplusplus
}
#endif

 /*!
 @}
 */
#endif

