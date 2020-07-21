/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include <stdlib.h>
#include <string.h>

#include "test_pal_log.h"

#define NUM_OF_CHARS_FOR_BYTE 4
#define INT_MIN   (~0x7fffffff)  /* -2147483648 and 0x80000000 are unsigned */
    /* minimum value for an object of type int */
#define INT_MAX   0x7fffffff
    /* maximum value for an object of type int */

/******************************************************************************/

int Tests_CopyDataToBinFile (unsigned char *fileName, unsigned char *inBuff, unsigned int inBuffLen)
{
    int rc = 0;
    size_t actualWriten = 0;
    FILE *fd;


    if ((NULL == fileName) ||
        (NULL == inBuff) ||
        (0 == inBuffLen)) {
        TEST_PRINTF_ERROR( "ilegal parameters for %s\n", __func__);
        return 1;
    }
    fd = fopen((char *)fileName, "wb");
    if (NULL == fd) {
        TEST_PRINTF_ERROR( "failed to open file %s for writing\n", fileName);
        return 2;
    }

    actualWriten = fwrite(inBuff, 1, inBuffLen, fd);
    if (actualWriten != inBuffLen) {
        TEST_PRINTF_ERROR( "failed to write data to file actual written %lu, expected %d\n", (unsigned long)actualWriten, inBuffLen);
        rc = 2;
    }

    fclose(fd);
    return rc;
}

int Tests_CopyDataFromBinFile (unsigned char *fileName, unsigned char *outBuff,
                                 unsigned int *outBuffLen)
{
    FILE *fd;
    int actualRead = 0;
    int maxBytesToRead = 0;
    unsigned int actualFileLen = 0;
    int ch;

    if ((NULL == fileName) ||
        (NULL == outBuff) ||
        (0 == *outBuffLen)) {
        TEST_PRINTF_ERROR( "ilegal parameters for %s\n", __func__);
        return 1;
    }
    fd = fopen((char *)fileName, "rb");
    if (NULL == fd) {
        TEST_PRINTF_ERROR( "failed to open file %s for reading\n", fileName);
        return 2;
    }

    /* Get file length */
    fseek(fd, 0, SEEK_END);
    actualFileLen=ftell(fd);
    fseek(fd, 0, SEEK_SET);

    /* calculate max bytes to read. should be the min of bytes in file and buffer size*/
    maxBytesToRead = (actualFileLen > *outBuffLen)?*outBuffLen:actualFileLen;
    if ( 0 == maxBytesToRead) {
        TEST_PRINTF_ERROR( "ilegal case: maxBytesToRead = 0\n");
        fclose(fd);
        return 2;
    }
    if ( actualFileLen > (unsigned int)(*outBuffLen) ){
        TEST_PRINTF_ERROR( "ilegal case: actualFileLen (%d) > *outBuffLen (%d)\n", actualFileLen, *outBuffLen);
        fclose(fd);
        return 2;
    }

    /* read file content */
    actualRead = fread(outBuff, 1, maxBytesToRead, fd);
    ch = (int)outBuff[actualRead-1];
    if (EOF == ch) {
        actualRead--;
    }
    *outBuffLen = actualRead;

    fclose(fd);
    return 0;
}

int Tests_BinFileSize(char *fileName, size_t *outBuffLen)
{
    FILE *fd;
    unsigned int actualFileLen = 0;

    if ((NULL == fileName) || (NULL == outBuffLen)) {
        TEST_PRINTF_ERROR("illegal parameters for %s\n", __func__);
        return 1;
    }
    fd = fopen((char *) fileName, "rb");
    if (NULL == fd) {
        TEST_PRINTF_ERROR("failed to open file %s for reading\n", fileName);
        return 2;
    }

    /* Get file length */
    fseek(fd, 0, SEEK_END);
    actualFileLen = ftell(fd);
    fseek(fd, 0, SEEK_SET);

    *outBuffLen = actualFileLen;

    fclose(fd);
    return 0;
}

int Tests_CopyDataFromTextCommaSepFile (unsigned char *fileName, unsigned char *outBuff,
                                           unsigned int *outBuffLen)
{
    int status = 0;
    FILE *fd;
    int i = 0, j=0, k=0;
    unsigned int actualFileLen=0;
    int tempNum=0;
    int actualRead=0;
    int maxBytesToRead = 0;
    char *filebufptr = NULL;
    char str[NUM_OF_CHARS_FOR_BYTE+1];


    if ((NULL == fileName) ||
        (NULL == outBuff) ||
        (NULL == outBuffLen)) {
        TEST_PRINTF_ERROR( "ilegal parameters for %s\n", __func__);
        return 1;
    }
    if (0 == *outBuffLen) {
        TEST_PRINTF_ERROR( "ilegal outBuffLen \n");
        return 1;
    }
    fd = fopen((char *)fileName, "rt");
    if (NULL == fd) {
        TEST_PRINTF_ERROR( "failed to open file %s for reading\n", fileName);
        return 1;
    }
    memset(outBuff, 0, *outBuffLen);

    /* Get file length */
    fseek(fd, 0, SEEK_END);
    actualFileLen = ftell(fd);
    fseek(fd, 0, SEEK_SET);

    /* calculate max bytes to read. should be the min of bytes in file and buffer size*/
    maxBytesToRead = (actualFileLen > (*outBuffLen*5))?(*outBuffLen*5):actualFileLen;
    if (0 == maxBytesToRead) {
        TEST_PRINTF_ERROR( "ilegal maxBytesToRead == 0\n");
        status = 1;
        goto EXIT;
    }


    /* allocate buffer for data from file */
    filebufptr = (char*)malloc(maxBytesToRead+1);
    if (filebufptr == NULL) {
        TEST_PRINTF_ERROR( "failed to allocate memory\n");
        status = 1;
        goto EXIT;
    }

    /* NULL terminated string to avoid buffer overflow of the sscanf that is used later */
    filebufptr[maxBytesToRead] = '\0';

    /* read file content */
    actualRead = fread(filebufptr, 1, maxBytesToRead, fd);
    j=0;
    k=0;
    for (i=0; i<actualRead; i++) {
        if ((((filebufptr[i] >= '0') && (filebufptr[i] <= '9')) ||
             ((filebufptr[i] >= 'a') && (filebufptr[i] <= 'f')) ||
             ((filebufptr[i] >= 'A') && (filebufptr[i] <= 'a')) ||
             (filebufptr[i] == 'x') || (filebufptr[i] == 'X')) &&
            (k<NUM_OF_CHARS_FOR_BYTE)) {
            str[k++] = filebufptr[i];
        } else {
            if ((filebufptr[i] == ',') ||
                (filebufptr[i] == '\n') ||
                (filebufptr[i] == '\0')) {
                if (k>0) {
                    str[k] = '\0';
                    tempNum = strtol(str, NULL, 16);
                    if ((INT_MIN == tempNum) ||
                        (INT_MAX == tempNum)) {
                        TEST_PRINTF_ERROR( "strtol failed. check file name %s\n", fileName);
                        status = 1;
                        goto EXIT_AND_FREE;
                    }
                    outBuff[j++] = tempNum;
                    k = 0;
                }
                continue;
            } else {
                TEST_PRINTF_ERROR( "ilegal char in file %c offset %d within file name %s\n", filebufptr[i], i, fileName);
                status = 1;
                goto EXIT_AND_FREE;
            }
        }
    }
    *outBuffLen = j;

EXIT_AND_FREE:
    free(filebufptr);
    EXIT:
    fclose(fd);
    return status;

}



