/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#define CC_PAL_LOG_CUR_COMPONENT CC_LOG_MASK_SECURE_BOOT

/************* Include Files ****************/

#include "util.h"

/************************ Defines ******************************/
/* rotate 32-bits word by 16 bits */
#define UTIL_ROT32(x) ( (x) >> 16 | (x) << 16 )

/* inverse the bytes order in a word */
#define UTIL_REVERSE32(x)  ( ((UTIL_ROT32((x)) & 0xff00ff00UL) >> 8) | ((UTIL_ROT32((x)) & 0x00ff00ffUL) << 8) )

/******************** Private Functions ************************/

/* ------------------------------------------------------------
 **
 * @brief This function executes a reversed bytes copy on a specified buffer.
 *
 *        on a 6 byte buffer:
 *
 *        buff[5] <---> buff[0]
 *        buff[4] <---> buff[1]
 *        buff[3] <---> buff[2]
 *
 * @param[in] dst_ptr - The counter buffer.
 * @param[in] src_ptr - The counter size in bytes.
 *
 */
void UTIL_ReverseBuff( uint8_t *pBuff , uint32_t size )
{
    /* FUNCTION DECLARATIONS */

   /* loop variable */
   uint32_t i;

   /* a temp variable */
   uint32_t temp;

   /* FUNCTION LOGIC */

   /* execute the reverse memcopy */
   for( i = 0 ; i < (size / 2) ; i++ )
   {
           temp = pBuff[i];
           pBuff[i] = pBuff[size - i - 1];
           pBuff[size - i - 1] = temp;
   }

   return;

 }/* END OF UTIL_ReverseBuff */

/* ------------------------------------------------------------
 **
 * @brief This function executes a memory copy from one buffer to enother.
 *
 * Assuming: There no overlapping of the buffers.
 *
 * @param[in] pDst - The first counter buffer.
 * @param[in] pSrc - The second counter buffer.
 * @param[in] size - The counters size in bytes.
 *
 */
void UTIL_MemCopy( uint8_t *pDst , const uint8_t *pSrc , uint32_t size )
{
    /* FUNCTION DECLARATIONS */

    /* loop variable */
    uint32_t i;

    /* FUNCTION LOGIC */

    /* execute memcopy */
    for (i = 0; i < size; i++)
        pDst[i] = pSrc[i];

    return;

}/* END OF UTIL_MemCopy */


/* ------------------------------------------------------------
 **
 * @brief This function executes a reverse bytes copying from one buffer to another buffer.
 *        Overlapping is not allowed, besides in-place operation.
 *
 * @param[in] pDst - The pointer to destination buffer.
 * @param[in] pSrc - The pointer to source buffer.
 * @param[in] size - The size in bytes.
 *
 */
void UTIL_ReverseMemCopy( uint8_t *pDst, uint8_t *pSrc, uint32_t size )
{
    /* FUNCTION DECLARATIONS */

    /* loop variable */
    uint32_t i;
    uint8_t tmp;

    /* buffers position identifiers */
    uint32_t dstPos, srcPos;

    /* FUNCTION LOGIC */

    /* initialize the source and the destination position */
    dstPos = size - 1;
    srcPos = 0;

    /* execute the reverse copy in case of different buffers */
    if (pDst != pSrc) {
        for( i = 0 ; i < size ; i++ )
            pDst[dstPos--] = pSrc[srcPos++];
    } else {
        /* execute the reverse copy in case of in-place reversing */
        for( i = 0 ; i < size/2 ; i++ ) {
            tmp = pDst[dstPos];
            pDst[dstPos--] = pSrc[srcPos];
            pSrc[srcPos++] = tmp;
        }
    }

    return;

}/* END OF UTIL_ReverseMemCopy */


/* ------------------------------------------------------------
 **
 * @brief This function executes a memory set operation on a buffer.
 *
 * @param[in] pBuff - The buffer.
 * @param[in] val   - The value to set the buffer.
 * @param[in] size  - The buffers size.
 *
 */
void UTIL_MemSet( uint8_t *pBuff, uint8_t val, uint32_t size )
{
    /* FUNCTION DECLARATIONS */

    /* loop variable */
    uint32_t i;

    /* FUNCTION LOGIC */

    for (i = 0 ; i < size ; i++)
        pBuff[i] = val;

    return;

}/* END OF UTIL_MemSet */

/* ------------------------------------------------------------ */
/*
 * @brief This function executes a memory secure comparing of 2 buffers.
 *
 * @param [in] pBuff1 - The first counter buffer.
 * @param [in] pBuff2 - The second counter buffer.
 * @param [in] size    - Tthe first counter size in bytes.
 * @return 1 - if buffers are equalled, 0 - otherwaise.
 */

/* Trust in Soft annotations - __TRUSTINSOFT_ANALYZER__ */
/*@ requires \initialized(pBuff1 + (0 .. size -1));
    requires \initialized(pBuff2 + (0 .. size -1));
*/
uint32_t UTIL_MemCmp( uint8_t *pBuff1 , uint8_t *pBuff2 , uint32_t size )
{
    /* FUNCTION DECLARATIONS */

    /* loop variable */
    uint32_t i;
    uint32_t stat = 0;

    /* FUNCTION LOGIC */

    for( i = 0; i < size; i++ ) {
        stat |= (pBuff1[i] ^ pBuff2[i]);
    }

    if(stat == 0)
        return CC_TRUE;
    else
        return CC_FALSE;

}/* END OF UTIL_MemCmp */
