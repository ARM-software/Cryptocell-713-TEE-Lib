/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


#ifndef TESTS_FILE_H_
#define TESTS_FILE_H_

#ifdef __cplusplus
extern "C" {
#endif


/******************************************************************************/
/*
 * @brief This function writes data to a binary file.
 * @param[in]
 * data_fname - File name.
 *
 * @param[in]
 * inBuff - A pointer to the data buffer.
 *
 * @param[out]
 * inBuffLen - data length.
 *
 * @return - int
 */
int Tests_CopyDataToBinFile (unsigned char *fileName, unsigned char *inBuff, unsigned int inBuffLen);

/******************************************************************************/
/*
 * @brief This function reads data from a binary file.
 * @param[in]
 * data_fname - File name.
 *
 * @param[in]
 * outBuff - A pointer to the data buffer.
 *
 * @param[out]
 * outBuffLen - data length.
 *
 * @return - int
 */
int Tests_CopyDataFromBinFile (unsigned char *fileName, unsigned char *outBuff, unsigned int *outBuffLen);

int Tests_BinFileSize(char *fileName, size_t *outBuffLen);

int Tests_CopyDataFromTextCommaSepFile (unsigned char *fileName, unsigned char *outBuff, unsigned int *outBuffLen);



#ifdef __cplusplus
}
#endif

#endif /* TESTS_FILE_H_ */
