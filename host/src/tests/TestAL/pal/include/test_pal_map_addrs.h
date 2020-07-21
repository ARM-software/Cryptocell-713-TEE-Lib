/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm’s non-OSI source license
 *
 */

#ifndef TEST_PAL_MAP_ADDRS_H_
#define TEST_PAL_MAP_ADDRS_H_

/*!
 @file
 @brief This file contains PAL map address integration tests.
 */

/*!
 @addtogroup pal_address_test
 @{
 */

#ifdef __cplusplus
extern "C" {
#endif

/*! Validates mapped address. */
#define VALID_MAPPED_ADDR(addr) ((addr != 0) && (addr != 0xFFFFFFFF))

/* Bit Masks - Used by Linux */
/*! Pages can be read. */
#define BM_READ        0x01
/*! Pages can be written. */
#define BM_WRITE    0x02
/*! Pages can be executed. */
#define BM_EXEC        0x04
/*! Pages cannot be accessed. */
#define BM_NONE        0x08
/*! Share this mapping. */
#define BM_SHARED    0x10
/*! Create a private copy-on-write mapping. */
#define BM_PRIVATE    0x20
/*! The mapping must be placed at this fixed address. */
#define BM_FIXED    0x40

/******************************************************************************/
/*!
 * @brief This function maps IO physical address to OS accessible address.
 *
 *
 * @return A valid virtual address.
 * @return Null on failure.
 */
void *Test_PalIOMap(
 /*! Physical address. */
 void *physAddr,
 /*! Size in bytes. */
 size_t size
);

/******************************************************************************/
/*!
 * @brief This function maps a physical address to a virtual address.
 *
 *
 * @return A valid virtual address
 * @return Null on failure.
 */
void *Test_PalMapAddr(
 /*! A physical address. */
 void *physAddr,
 /*! Preferred static address for mapping. */
 void *startingAddr,
 /*! File name.*/
 const char *filename,
 /*! Size in bytes. */
 size_t size,
 /*! Protection and update visibility bit mask. */
 uint8_t protAndFlagsBitMask
);

/******************************************************************************/
/*!
 * @brief This function unmaps a virtual address.
 *
 * @return
 */
void Test_PalUnmapAddr(
 /*! Virtual address. */
 void *virtAddr,
 /*! Size in bytes. */
 size_t size
);

#ifdef __cplusplus
}
#endif
/*!
 @}
 */
#endif /* TEST_PAL_MAP_ADDRS_H_ */
