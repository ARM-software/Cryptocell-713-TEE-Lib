/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm’s non-OSI source license
 *
 */

#ifndef TEST_PAL_MEM_H_
#define TEST_PAL_MEM_H_

/*!
 @file
 @brief This file contains PAL memory integration tests.
 */

/*!
 @addtogroup pal_memory_test
 @{
 */

#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/
/*!
 * @brief This function allocates size bytes.
 * When TZM is supported, it is used only for Non-secure memory allocations.
 *
 *
 * @return Pointer to the allocated memory.
 * @return NULL on failure.
 */
void *Test_PalMalloc(
/*! Size in bytes. */
size_t size
);

/******************************************************************************/
/*!
 * @brief This function frees allocated memory pointed by pvAddress.
 * When TZM is supported, it is used only for Non-secure memory blocks.
 *
 * @return Void.
 */
void Test_PalFree(
 /*! Pointer to the allocated memory. */
 void *pvAddress
);

/******************************************************************************/
/*!
 * @brief This function changes the size of the memory block pointed by
 * pvAddress.
 * If the function fails to allocate the requested block of memory:
 * <ul><li> A null pointer is returned.</li>
 * <li>The memory block pointed by argument pvAddress is not
 * deallocated.</li></ul>
 * When TZM is supported, it is used only for Non-secure memory blocks.
 *
 *
 * @return A pointer to the new allocated memory on success.
 * @return NULL on failure.
 */
void *Test_PalRealloc(
 /*! Pointer to the allocated memory. */
 void *pvAddress,
 /*! New size. */
 size_t newSize
);

/******************************************************************************/
/*!
 * @brief  This function allocates a DMA-contiguous buffer and returns its
 * address.
 * When TZM is supported, it is used only for Non-secure buffer allocations.
 *
 *
 * @return Address of the allocated buffer.
 * @return NULL on failure.
 */
void *Test_PalDMAContigBufferAlloc(
 /*! Buffer size in bytes. */
 size_t size
);

/******************************************************************************/
/*!
 * @brief This function frees resources previously allocated by
 * Test_PalDMAContigBufferAlloc.
 * When TZM is supported, it is used only for Non-secure buffers.
 *
 *
 * @return Void.
 */
void Test_PalDMAContigBufferFree(
 /*! Address of the allocated buffer. */
 void *pvAddress
);

/******************************************************************************/
/*!
 * @brief This function changes the size of the memory block pointed by
 * pvAddress.
 * If the function fails to allocate the requested block of memory:
 * <ul>
 * <li> A null pointer is returned.</li>
 * <li> The memory block pointed by argument \c pvAddress
 * is not deallocated.</li></ul>
 * When TZM is supported, it is used only for Non-secure buffers.
 *
 *
 * @return A pointer to the new allocated memory.
 */
void *Test_PalDMAContigBufferRealloc(
 /*! Pointer to the allocated memory. */
 void *pvAddress,
 /*! New size in bytes. */
 size_t newSize
);

/******************************************************************************/
/*!
 * @brief This function returns DMA base address, that is, the start address
 * of the DMA region.
 * When TZM is supported, it returns the Non-secure DMA base address.
 *
 *
 * @return DMA base address.
 */
unsigned long Test_PalGetDMABaseAddr(void);

/******************************************************************************/
/*!
 * @brief This function returns the unmanaged base address.
 * When TZM is supported, it returns the Non-secure unmanaged base address.
 *
 * @return Unmanaged base address.
 */
unsigned long Test_PalGetUnmanagedBaseAddr(void);

/******************************************************************************/
/*!
 * @brief This function initializes DMA memory management.
 * When TZM is supported, it initializes the Non-secure DMA memory management.
 *
 *
 *
 * @return 0 on success.
 * @return 1 on failure.
 */
uint32_t Test_PalMemInit(
 /*! New DMA start address. */
 unsigned long newDMABaseAddr,
 /*! New unmanaged start address. */
 unsigned long newUnmanagedBaseAddr,
 /*! DMA region size. */
 size_t DMAsize
);

/******************************************************************************/
/*!
 * @brief This function sets this driver to its initial state.
 * When TZM is supported, it sets the Non-secure management to its initial
 * state.
 *
 *
 * @return 0 on success.
 * @return 1 on failure.
 */
uint32_t Test_PalMemFin(void);

#ifdef __cplusplus
}
#endif
/*!
 @}
 */
#endif /* TEST_PAL_MEM_H_ */
