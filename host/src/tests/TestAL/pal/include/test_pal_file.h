/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm’s non-OSI source license
 *
 */

#ifndef TEST_PAL_FILE_H_
#define TEST_PAL_FILE_H_

/*!
 @file
 @brief This file contains file APIs used by tests.
 */

/*!
 @addtogroup pal_file_test
 @{
 */

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/
/*!
 * @brief This function reads dump data from given file in CryptoRef
 * (this test dump) format (comma seperated hex byte values) and put in
 * allocated buffer.
 *
 *
 * @return Data size in bytes.
 */
size_t Test_PalFetchDataFromFile(
 /*! File name.*/
 const char *data_fname,
 /*! A pointer to the allocated data buffer.*/
 uint8_t **data_pp
);

#ifdef __cplusplus
}
#endif
/*!
 @}
 */
#endif /* TEST_PAL_FILE_H_ */
