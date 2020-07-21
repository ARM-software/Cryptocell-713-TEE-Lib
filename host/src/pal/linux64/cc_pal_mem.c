/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */



/************* Include Files ****************/
#include "cc_pal_types.h"
#include "cc_pal_error.h"
#include "cc_pal_mem.h"

/************************ Defines ******************************/

/************************ Enums ******************************/


/************************ Typedefs ******************************/


/************************ Global Data ******************************/

/************************ Private Functions ******************************/


/************************ Public Functions ******************************/


int32_t CC_PalMemCmpPlat(  const void* aTarget, /*!< [in] The target buffer to compare. */
                           const void* aSource, /*!< [in] The Source buffer to compare to. */
                           size_t      aSize    /*!< [in] Number of bytes to compare. */)
{
    return memcmp(aTarget, aSource, aSize);

}/* End of CC_PalMemCmp */

void* CC_PalMemCopyPlat(     void* aDestination, /*!< [out] The destination buffer to copy bytes to. */
                               const void* aSource,      /*!< [in] The Source buffer to copy from. */
                               size_t      aSize     /*!< [in] Number of bytes to copy. */ ){
    return memmove( aDestination,  aSource, aSize);
}/* End of CC_PalMemCopy */


/*!
 * @brief This function purpose is to copy aSize bytes from source buffer to destination buffer.
 * This function Supports overlapped buffers.
 *
 * @return void.
 */
void CC_PalMemMovePlat(   void* aDestination, /*!< [out] The destination buffer to copy bytes to. */
                          const void* aSource,      /*!< [in] The Source buffer to copy from. */
                          size_t      aSize     /*!< [in] Number of bytes to copy. */)
{
    memmove(aDestination, aSource, aSize);
}/* End of CC_PalMemMove */


/*!
 * @brief This function purpose is to set aSize bytes in the given buffer with aChar.
 *
 * @return void.
 */
void CC_PalMemSetPlat(   void* aTarget, /*!< [out]  The target buffer to set. */
                         uint8_t aChar, /*!< [in] The char to set into aTarget. */
                         size_t        aSize  /*!< [in] Number of bytes to set. */)
{
    memset(aTarget, aChar, aSize);
}/* End of CC_PalMemSet */

/*!
 * @brief This function purpose is to set aSize bytes in the given buffer with zeroes.
 *
 * @return void.
 */
void CC_PalMemSetZeroPlat(    void* aTarget, /*!< [out]  The target buffer to set. */
                              size_t      aSize    /*!< [in] Number of bytes to set. */)
{
    memset(aTarget, 0x00, aSize);
}/* End of CC_PalMemSetZero */

/*!
 * @brief This function purpose is to allocate a memory buffer according to aSize.
 *
 *
 * @return The function returns a pointer to allocated buffer or NULL if allocation failed.
 */
void* CC_PalMemMallocPlat(size_t  aSize /*!< [in] Number of bytes to allocate. */)
{
    return malloc(aSize);
}/* End of CC_PalMemMalloc */

/*!
 * @brief This function purpose is to reallocate a memory buffer according to aNewSize.
 *        The content of the old buffer is moved to the new location.
 *
 * @return The function returns a pointer to the newly allocated buffer or NULL if allocation failed.
 */
void* CC_PalMemReallocPlat(  void* aBuffer,     /*!< [in] Pointer to allocated buffer. */
                             size_t  aNewSize   /*!< [in] Number of bytes to reallocate. */)
{
    return realloc(aBuffer, aNewSize);
}/* End of CC_PalMemRealloc */

/*!
 * @brief This function purpose is to free allocated buffer.
 *
 *
 * @return void.
 */
void CC_PalMemFreePlat(void* aBuffer /*!< [in] Pointer to allocated buffer.*/)
{
    free(aBuffer);
}/* End of CC_PalMemFree */
