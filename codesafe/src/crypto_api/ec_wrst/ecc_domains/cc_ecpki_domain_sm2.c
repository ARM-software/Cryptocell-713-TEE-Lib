/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


#include "cc_pal_types.h"
#include "cc_ecpki_types.h"



/***********************************************************************************
 *   Data base of CC_ECPKI_DomainID_Sm2: structure of type  CCEcpkiDomain_t        *
 *       All data is given in little endian order of words in arrays               *
 ***********************************************************************************/
static const CCEcpkiDomain_t ecpki_domain_sm2 = {

    /* Field modulus :  GF_Modulus =  FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFF - big end*/
    {0xFFFFFFFF,0xFFFFFFFF,0x00000000,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFE},

    /* EC equation parameters a, b  */
    /* a = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFC  - big end  from SM2 */
    {0xFFFFFFFC,0xFFFFFFFF,0x00000000,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFE},
    /* b = 28E9FA9E 9D9F5E34 4D5A9E4B CF6509A7 F39789F5 15AB8F92 DDBCBD41 4D940E93  - big end  from SM2 */
    {0x4D940E93,0xDDBCBD41,0x15AB8F92,0xF39789F5,0xCF6509A7,0x4D5A9E4B,0x9D9F5E34,0x28E9FA9E},

    /* Order of generator: FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 7203DF6B 21C6052B 53BBF409 39D54123 big end  from SM2 */
    {0x39D54123,0x53BBF409,0x21C6052B,0x7203DF6B,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFE},

    /* Generator  coordinates in affine form: EC_Gener_X, EC_Gener_Y (in ordinary representation) */
    /* 32C4AE2C 1F198119 5F990446 6A39C994 8FE30BBF F2660BE1 715A4589 334C74C7   X - big end  from SM2 */
    {0x334C74C7,0x715A4589,0xF2660BE1,0x8FE30BBF,0x6A39C994,0x5F990446,0x1F198119,0x32C4AE2C},
    /* BC3736A2 F4F6779C 59BDCEE3 6B692153 D0A9877C C62A4740 02DF32E5 2139F0A0   Y - big end  from SEC2 */
    {0x2139F0A0,0x02DF32E5,0xC62A4740,0xD0A9877C,0x6B692153,0x59BDCEE3,0xF4F6779C,0xBC3736A2},

    1, /* EC cofactor K */

     /* Barrett tags NP,RP */
#ifdef CC_SUPPORT_PKA_128_32
    {0x00000080, 0x00000080, 0x00000080, 0x00000080, 0x00000080,
     0x000000C6,0x00000080, 0x00000080, 0x00000080, 0x00000080},
#else  // CC_SUPPORT_PKA_64_16
    {0x2BB5DCCE, 0xE4AB1E30, 0x000000F5, 0x00000000, 0x00000000,
    0x2BB5DCCE, 0xE4AB1E30, 0x000000F5, 0x00000000, 0x00000000},
#endif
    256, /* Size of field modulus in bits */
    256, /* Size of order of generator in bits */
    5,   /* Size of each inserted Barret tag in words; 0 - if not inserted */

    CC_ECPKI_DomainID_sm2,	/* EC Domain identifier - enum */
    "SM2_PRIME_256" /*SM2*/

};




/**************************************************************************
 *                CC_EcpkiGetSm2Domain
 **************************************************************************/
/*!
 @brief    the function returns the domain pointer id the domain is supported for the product;
		otherwise return NULL
 @return   return domain pointer or NULL

*/
const CCEcpkiDomain_t *CC_EcpkiGetSm2Domain(void)
{
    return &ecpki_domain_sm2;
}

