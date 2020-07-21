/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

/*
 * All the includes that are needed for code usin1g this module to
 * compile correctly should be #included here.
 */
#include "cc_pal_types.h"
#include "cc_ecpki_types.h"


/**************** The domain structure describing *************/
/**
// The structure containing EC domain parameters in little-endian form.
// Elliptic curve: Y^2 = X^3 + A*X + B over prime fild GFp

typedef  struct {

	// Field modulus:  GF_Modulus = P
	uint32_t	ecP [CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
	// EC equation parameters a, b
	uint32_t	ecA [CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
	uint32_t	ecB [CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
	// Order of generator: EC_GenerOrder
	uint32_t	ecOrd [CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 1];
	// Generator (EC base point) coordinates in projective form
	uint32_t	ecGx [CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
	uint32_t	ecGy [CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
	// EC cofactor EC_Cofactor_K
	uint32_t  	ecH;
	// include the specific fields that are used by the low level
	uint32_t      barrTagBuff[CC_PKA_DOMAIN_BUFF_SIZE_IN_WORDS];
	// Size of fields in bits
	uint32_t  	modSizeInBits;
	uint32_t  	ordSizeInBits;
	// Size of each inserted Barret tag in words; 0 - if not inserted
	uint32_t 	barrTagSizeInWords;
	CCEcpkiDomainID_t	DomainID;
	int8_t  name[20];

} CCEcpkiDomain_t;

*/


/***********************************************************************************
 *   Data base of CC_ECPKI_DomainID_secp256r1: structure of type  CCEcpkiDomain_t    *
 *       All data is given in little endian order of words in arrays               *
 ***********************************************************************************/

static const CCEcpkiDomain_t ecpki_domain_bp256r1 = {
        /* Field modulus :  GF_Modulus =  A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377 - big end*/
    {0x1f6e5377, 0x2013481d, 0xd5262028, 0x6e3bf623, 0x9d838d72, 0x3e660a90, 0xa1eea9bc, 0xa9fb57db,},
    /* EC equation parameters a, b  */
    /* a = 7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9  - big end  from SEC2 */
    {0xf330b5d9, 0xe94a4b44, 0x26dc5c6c, 0xfb8055c1, 0x417affe7, 0xeef67530, 0xfc2c3057, 0x7d5a0975, },
    /* b = 26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6 - big end  from SEC2 */
    {0xff8c07b6, 0x6bccdc18, 0x5cf7e1ce, 0x95841629, 0xbbd77cbf, 0xf330b5d9, 0xe94a4b44, 0x26dc5c6c, },
    /* Order of generator: 8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262 big end  from SEC2 */
    /* A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7  Y - big end  from SEC2 */
    {0x974856a7, 0x901e0e82, 0xb561a6f7, 0x8c397aa3, 0x9d838d71, 0x3e660a90, 0xa1eea9bc, 0xa9fb57db, },
    /* Generator  coordinates in affine form: EC_Gener_X, EC_Gener_Y (in ordinary representation) */
    {0x9ace3262, 0x3a4453bd, 0xe3bd23c2, 0xb9de27e1, 0xfc81b7af, 0x2c4b482f, 0xcb7e57cb, 0x8bd2aeb9, },
    /* 547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997   X - big end  from SEC2 */
    {0x2f046997, 0x5c1d54c7, 0x2ded8e54, 0xc2774513, 0x14611dc9, 0x97f8461a, 0xc3dac4fd, 0x547ef835, },

    1, /* EC cofactor K */

/* Barrett tags NP,RP */
#ifdef CC_SUPPORT_PKA_128_32
//  mod tag :c0c60898d0e2adbf5db9d5d419153df94d
    { 0x153df94d,0xb9d5d419,0xe2adbf5d,0xc60898d0,0x000000c0,
//  ord tag:  c0c60898d0e2adbf5db9d5d419153dfa4d
      0x153dfa4d,0xb9d5d419,0xe2adbf5d,0xc60898d0,0x000000c0},
#else  // CC_SUPPORT_PKA_64_16
//      c0c60898d0e2adbf5d
     {
      0xe2adbf5d, 0xc60898d0, 0x000000c0, 0x00000000, 0x00000000,
      0xe2adbf5d, 0xc60898d0, 0x000000c0, 0x00000000, 0x00000000},
#endif

	256, /* Size of field modulus in bits */
	256, /* Size of order of generator in bits */
	5,   /* Size of each inserted Barret tag in words; 0 - if not inserted */

	CC_ECPKI_DomainID_bp256r1,	/* EC Domain identifier - enum */
	"BP_PRIME_256R1" /*NIST_P256*/

};




/**
 @brief    the function returns the domain pointer id the domain is supported for the product;
		otherwise return NULL
 @return   return domain pointer or NULL

*/
const CCEcpkiDomain_t *CC_EcpkiGetBp256r1DomainP(void)
{
	return &ecpki_domain_bp256r1;
}

