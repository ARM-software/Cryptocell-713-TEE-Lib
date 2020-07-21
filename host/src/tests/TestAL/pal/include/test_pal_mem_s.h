/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm’s non-OSI source license
 *
 */

#ifndef TEST_PAL_MEM_S_H_
#define TEST_PAL_MEM_S_H_

/*!
  @file
  @brief This file contains SECURE memory APIs used by tests.
  USE ONLY WHEN TRUSTZONE-M IS SUPPORTED.
  Otherwise, please use only test_pal_mem API.
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
 * @brief This function allocates SECURE "size" bytes.
 *
 *
 * @return Pointer to the allocated memory.
 * @return NULL on failure.
 */
void *Test_PalMalloc_s(size_t size /*!< Size in bytes.*/
);

/******************************************************************************/
/*!
 * @brief This function frees SECURE allocated memory pointed by pvAddress.
 *
 *
 * @return void
 */
void Test_PalFree_s(void *pvAddress /*!< Pointer to the allocated memory.*/
);

/******************************************************************************/
/*!
 * @brief This function changes the size of a SECURE memory block pointed by
 * pvAddress.
 * If the function fails to allocate the requested block of memory:<ol>
 * <li>A null pointer is returned.</li>
 * <li>The memory block pointed by argument pvAddress is NOT
 * deallocated.</li></ol>
 *
 *
 * @return Pointer to the new allocated memory.
 * @return NULL on failure.
 */
void *Test_PalRealloc_s(void *pvAddress, /*!< Pointer to the allocated memory.*/
 size_t newSize /*!< New size.*/
);

/******************************************************************************/
/*!
 * @brief This function allocates a DMA-contiguous buffer in a SECURE memory
 * region and returns its address.
 *
 *
 * @return Address of the secure allocated buffer.
 * @return NULL on failure.
 */
void *Test_PalDMAContigBufferAlloc_s(size_t size /*!< Buffer size in bytes.*/
);

/******************************************************************************/
/*!
 * @brief This function frees resources in a SECURE region previously allocated
 * by Test_PalDMAContigBufferAlloc_s.
 *
 *
 * @return void
 */
void Test_PalDMAContigBufferFree_s(
 void *pvAddress /*!< Address of the secure allocated buffer.*/
);

/******************************************************************************/
/*!
 * @brief This function changes the size of the SECURE memory block pointed by
 * pvAddress.
 * If the function fails to allocate the requested block of memory:<ol>
 * <li>A null pointer is returned.</li>
 * <li>The memory block pointed by argument pvAddress is NOT deallocated.</li></ol>
 *
 *
 * @return Pointer to the new secure allocated memory.
 */
void *Test_PalDMAContigBufferRealloc_s(
 void *pvAddress /*!< Pointer to the secure allocated memory.*/,
 size_t newSize /*!< New size in bytes.*/
);

/******************************************************************************/
/*!
 * @brief This function returns the SECURE DMA base address, i.e. the start
 * address of the SECURE DMA region.
 *
 *
 * @return Secure DMA base address.
 */
unsigned long Test_PalGetDMABaseAddr_s(void);

/******************************************************************************/
/*!
 * @brief  This function returns the SECURE unmanaged base address.
 *
 * @param[in]  void
 *
 * @return  Secure unmanaged base address.
 */
unsigned long Test_PalGetUnmanagedBaseAddr_s(void);

/******************************************************************************/
/*!
 * @brief This function initializes the SECURE DMA memory management.
 *
 *
 * @return 0 on success.
 * @return 1 on failure.
 */
uint32_t Test_PalMemInit_s(
 unsigned long newDMABaseAddr_s, /*!< New secure DMA start address.*/
 unsigned long newUnmanagedBaseAddr_s,/*!< New secure unmanaged start address.*/
 size_t SDMAsize /*!< region size.*/
);

/******************************************************************************/
/*
 * @brief This function sets the SECURE memory management driver to its
 * initial state.
 *
 *
 * @return 0 on success.
 * @return 1 on failure.
 */
uint32_t Test_PalMemFin_s(void);

#ifdef __cplusplus
}
#endif
/*!
 @}
 */
#endif /* TEST_PAL_MEM_S_H_ */
