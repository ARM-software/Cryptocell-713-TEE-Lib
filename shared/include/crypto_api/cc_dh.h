/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


#ifndef _CC_DH_H
#define _CC_DH_H

#include "cc_rsa_types.h"
#include "cc_kdf.h"
#include "cc_rnd_common.h"

#ifdef __cplusplus
extern "C"
{
#endif


/*!
@file
@brief This file defines the API that supports Diffie-Hellman key exchange, as defined in Public-Key Cryptography Standards (PKCS) #3:
       Diffie-Hellman Key Agreement Standard and in ANSI X9.42-2003: Public Key Cryptography for the Financial Services Industry:
       Agreement of Symmetric Keys Using Discrete Logarithm Cryptography (key lengths 1024 and 2048 bits).
 */
/*!
 @addtogroup cc_dh
  @{
*/


/************************ Defines ******************************/
/*! Definition for DH public key.*/
#define CCDhPubKey_t  CCRsaPubKey_t

/*! Maximal valid key size in bits.*/
#define CC_DH_MAX_VALID_KEY_SIZE_VALUE_IN_BITS  CC_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BITS /*!< \internal restrict to 2048 */
/*! Minimal valid key size in bits.*/
#define CC_DH_MIN_VALID_KEY_SIZE_VALUE_IN_BITS  1024 /*!< Size limitation according to ANSI standard */
/*! Key size used for FIPS tests.*/
#define CC_DH_FIPS_KEY_SIZE_VALUE_IN_BITS       2048
/*! Maximal modulus size in bytes.*/
#define CC_DH_MAX_MOD_SIZE_IN_BYTES   (CC_DH_MAX_VALID_KEY_SIZE_VALUE_IN_BITS / 8)
/*! Maximal modulus size in words.*/
#define CC_DH_MAX_MOD_SIZE_IN_WORDS   (CC_DH_MAX_MOD_SIZE_IN_BYTES/sizeof(uint32_t))
/*! Modulus buffer size in words.*/
#define CC_DH_MAX_MOD_BUFFER_SIZE_IN_WORDS (CC_DH_MAX_MOD_SIZE_IN_WORDS + 2)
/*! Maximal domain generation size in bits.*/
#define CC_DH_DOMAIN_GENERATION_MAX_SIZE_BITS   CC_RSA_MAX_KEY_GENERATION_SIZE_BITS /*!< \internal restrict to 2048 */

/*! Definition for DH primitives data.*/
#define CCDhPrimeData_t   CCRsaPrimeData_t
/*! Definition for DH public key.*/
#define CCDhUserPubKey_t  CCRsaUserPubKey_t
/*! Definition for DH other information.*/
#define CCDhOtherInfo_t  CCKdfOtherInfo_t
/*! Number of other information entries.*/
#define CC_DH_COUNT_OF_OTHER_INFO_ENTRIES  CC_KDF_COUNT_OF_OTHER_INFO_ENTRIES
/*! Maximal size of other information entry.*/
#define CC_DH_MAX_SIZE_OF_OTHER_INFO_ENTRY  CC_KDF_MAX_SIZE_OF_OTHER_INFO_ENTRY /*!< Size is in bytes */
/*! Keying data size is in bytes.*/
#define CC_DH_MAX_SIZE_OF_KEYING_DATA  CC_KDF_MAX_SIZE_OF_KEYING_DATA /*!< Size is in bytes*/

/************************ Enums ********************************/

/*! DH operations mode. */
typedef enum
{
   /*! PKCS3 operation mode. */
   CC_DH_PKCS3_mode  = 0,
   /*! ANSI X942 operation mode. */
   CC_DH_ANSI_X942_mode = 1,
   /*! Total number of operation modes. */
   CC_DH_NumOfModes,
   /*! Reserved. */
   CC_DH_OpModeLast    = 0x7FFFFFFF,

}CCDhOpMode_t;

/*! HASH operation modes. */
typedef enum
{
	/*! SHA1 operation mode. */
	CC_DH_HASH_SHA1_mode		= CC_HASH_SHA1_mode,
	/*! SHA224 operation mode. */
	CC_DH_HASH_SHA224_mode		= CC_HASH_SHA224_mode,
	/*! SHA256 operation mode. */
	CC_DH_HASH_SHA256_mode		= CC_HASH_SHA256_mode,
	/*! SHA384 operation mode. */
	CC_DH_HASH_SHA384_mode		= CC_HASH_SHA384_mode,
	/*! SHA512 operation mode. */
	CC_DH_HASH_SHA512_mode		= CC_HASH_SHA512_mode,
	/*! MD5 operation mode (not used in DH). */
	CC_DH_HASH_MD5_mode	        = CC_HASH_MD5_mode, /*!< \internal not used in DH */
	/*! Total number of HASH modes. */
	CC_DH_HASH_NumOfModes		= CC_HASH_MD5_mode,
	/*! Reserved. */
	CC_DH_HASH_OperationModeLast  = 0x7FFFFFFF,

}CCDhHashOpMode_t;

/*! Key derivation modes. */
typedef enum
{
	/*! ASN1 derivation mode.*/
	CC_DH_ASN1_Der_mode    = CC_KDF_ASN1_DerivMode,
	/*! Concatenation derivation mode.*/
	CC_DH_Concat_Der_mode  = CC_KDF_ConcatDerivMode,
	/*! X963 derivation mode.*/
	CC_DH_X963_DerMode     = CC_KDF_ConcatDerivMode,
	/*! Reserved. */
	CC_DH_DerivationFunc_ModeLast= 0x7FFFFFFF,

}CCDhDerivationFuncMode_t;


/************************ Typedefs  *************************************/
/*! Temporary buffer structure for internal usage.*/
typedef struct
{
	/*! Temporary primitives data */
	CCDhPrimeData_t PrimeData;
	/*! Public key. */
	CCDhPubKey_t    PubKey;
	/*! Temporary buffer for internal usage. */
	uint32_t TempBuff[CC_DH_MAX_MOD_BUFFER_SIZE_IN_WORDS];
} CCDhExpTemp_t;

/*! Temporary buffer structure for internal usage. */
typedef struct
{
	/*! Temporary primitives data */
	CCDhPrimeData_t PrimeData;
	/*! User's public key. */
	CCDhUserPubKey_t    UserPubKey;
	/*! Temporary buffer for internal usage. */
	uint32_t TempBuff[CC_DH_MAX_MOD_BUFFER_SIZE_IN_WORDS];
} CCDhTemp_t;

/*! Temporary buffer structure for internal usage. */
typedef struct
{
	/*! Temporary primitives data */
	CCDhPrimeData_t PrimeData;
	/*! User's public key. */
	CCDhUserPubKey_t    UserPubKey;
	/*! Temporary buffer for internal usage. */
	uint32_t TempBuff[2*CC_DH_MAX_MOD_BUFFER_SIZE_IN_WORDS];
} CCDhHybrTemp_t;

/*! Definition of buffer used for FIPS Known Answer Tests. */
typedef struct
{
	/*! Public key. */
	CCDhUserPubKey_t pubKey;
	/*! Temporary primitives data */
	CCDhPrimeData_t  primeData;
	/*! Buffer for the secret value.*/
        uint8_t secretBuff[CC_DH_FIPS_KEY_SIZE_VALUE_IN_BITS / CC_BITS_IN_BYTE];  // KAT tests uses 2048 bit key
} CCDhFipsKat_t;


/************************ Structs  **************************************/

/************************ Public Variables ******************************/

/************************ Public Functions ******************************/

/*******************************************************************************************/

/*!
@brief This function has two purposes:
<ol><li>Randomly generate the client private key according to the chosen version Public-Key Cryptography Standards (PKCS) #3: Diffie-Hellman Key
Agreement Standard or ANSI X9.42-2003: Public Key Cryptography for the Financial Services Industry: Agreement of Symmetric Keys Using Discrete
Logarithm Cryptography standard.</li>
<li>Computes the client public key as follows:	ClientPub = Generator^Prv mod Prime, where '^' is the symbol of exponentiation.</li></ol>
This function should not be called directly. Instead, use the macros ::CC_DhPkcs3GeneratePubPrv and ::CC_DhAnsiX942GeneratePubPrv.
\note All buffer parameters should be in big-endian form.

@return \c CC_OK on success.
@return A non-zero value on failure as defined cc_dh_error.h, cc_rnd_error.h or cc_rsa_error.h.
 */
CIMPORT_C CCError_t CC_DhGeneratePubPrv(
                    CCRndGenerateVectWorkFunc_t f_rng, /*!< [in] - Pointer to DRBG function*/
                    void *p_rng,                          /*!< [in/out]  - Pointer to the random context - the input to f_rng. */
                    uint8_t *Generator_ptr,               /*!< [in]  Pointer to the Generator octet string. */
                    size_t GeneratorSize,                 /*!< [in]  The size of the Generator string (in bytes). */
                    uint8_t *Prime_ptr,                   /*!< [in]  Pointer to the Prime octet string P (used as modulus in the algorithm). */
                    size_t PrimeSize,                     /*!< [in]  The size of the Prime string in bytes. */
                    uint16_t L,                           /*!< [in]  Exact size in bits of the Prime to be generated (relevant only for Public-Key
								     Cryptography Standards (PKCS) #3: Diffie-Hellman Key Agreement Standard):
                                                                     <ul><li> If L!=0, force the private key to be [2^(L-1) ? Prv < 2^L], where '^'
									      indicates exponentiation.</li>
                                                                     <li> If L = 0 then [0 < Prv < P-1].</li></ul> */
                    uint8_t *Q_ptr,                       /*!< [in]  Relevant only for ANSI X9.42-2003: Public Key Cryptography for the Financial Services Industry:
								     Agreement of Symmetric Keys Using Discrete Logarithm Cryptography standard -
								     Pointer to the Q octet string in the range: 1 <= Prv <= Q-1 or 1 < Prv < Q-1. */
                    size_t QSize,                         /*!< [in]  Relevant only for ANSI X9.42-2003: Public Key Cryptography for the Financial Services Industry:
								     Agreement of Symmetric Keys Using Discrete Logarithm Cryptography standard - Size of the Q string (in bytes). */
                    CCDhOpMode_t DH_mode,                 /*!< [in]  An enumerator declaring whether this is Public-Key Cryptography Standards (PKCS) #3: Diffie-Hellman Key
								     Agreement Standard or ANSI X9.42-2003: Public Key Cryptography for the Financial Services Industry:
								     Agreement of Symmetric Keys Using Discrete Logarithm Cryptography mode standard. */
                    CCDhUserPubKey_t *tmpPubKey_ptr,      /*!< [in]  Pointer to a temporary buffer for public key structure. Used for the
							             exponentiation function. */
                    CCDhPrimeData_t  *tmpPrimeData_ptr,   /*!< [in]  Pointer to a structure holding internal temporary buffers. */
                    uint8_t *ClientPrvKey_ptr,            /*!< [out] Pointer to the Private key Prv. This buffer should be at least the following
								     size (in bytes):
                                                                     <ul><li> If L is provided: (L+7)/8.</li>
                                                                     <li> If L is NULL: \p PrimeSize. </li></ul> */
                    size_t *ClientPrvKeySize_ptr,         /*!< [in/out] Pointer to the Private key size:
                                                                       <ul><li> Input - size of the given buffer.</li>
                                                                       <li> Output - actual size of the generated private key.</li></ul> */
                    uint8_t *ClientPub1_ptr,              /*!< [out] Pointer to the Public key. This buffer should be at least \p PrimeSize bytes. */
                    size_t *ClientPubSize_ptr             /*!< [in/out] Pointer to the Public key size:
                                                                       <ul><li> Input - size of the given buffer.</li>
                                                                       <li> Output - actual size of the generated public key.</li></ul> */
);


/* macro for calling the GeneratePubPrv function on PKCS#3 mode:  Q is irrelevant */
/*--------------------------------------------------------------------------------*/
/*!
This macro is used to generate the public and private DH keys according to Public-Key Cryptography Standards (PKCS) #3: Diffie-Hellman Key
Agreement Standard. For a description of the parameters see ::CC_DhGeneratePubPrv.
*/
#define CC_DhPkcs3GeneratePubPrv(f_rng, p_rng, Generator_ptr,GeneratorSize, Prime_ptr,PrimeSize,L,tmpPubKey_ptr,tmpPrimeData_ptr, ClientPrvKey_ptr,ClientPrvKeySize_ptr,ClientPub_ptr,ClientPubSize_ptr)\
	CC_DhGeneratePubPrv(f_rng, p_rng, (Generator_ptr),(GeneratorSize),(Prime_ptr),(PrimeSize),(L),(uint8_t *)NULL,(uint16_t)0,CC_DH_PKCS3_mode,(tmpPubKey_ptr),(tmpPrimeData_ptr),\
		           (ClientPrvKey_ptr),(ClientPrvKeySize_ptr),(ClientPub_ptr),(ClientPubSize_ptr))

/*!
This macro is used to generate the public and private DH keys according to ANSI X9.42-2003: Public Key Cryptography for the Financial Services
Industry: Agreement of Symmetric Keys Using Discrete Logarithm Cryptography. For a description of the parameters see ::CC_DhGeneratePubPrv.
*/
#define CC_DhAnsiX942GeneratePubPrv(f_rng, p_rng, Generator_ptr,GeneratorSize,Prime_ptr,PrimeSize,Q_ptr,QSize,tmpPubKey_ptr,tmpPrimeData_ptr,	ClientPrvKey_ptr,ClientPrvKeySize_ptr,ClientPub_ptr,ClientPubSize_ptr)\
	CC_DhGeneratePubPrv((f_rng), (p_rng), (Generator_ptr),(GeneratorSize),(Prime_ptr),(PrimeSize),(uint16_t)0,(Q_ptr),(QSize),CC_DH_ANSI_X942_mode,(tmpPubKey_ptr),(tmpPrimeData_ptr),\
   			   (ClientPrvKey_ptr),(ClientPrvKeySize_ptr),(ClientPub_ptr),(ClientPubSize_ptr))


/*******************************************************************************************/
/*!
@brief This function computes the shared secret key (value) according to section 7.5.1 of ANSI X9.42-2003: Public Key Cryptography for the
       Financial Services Industry: Agreement of Symmetric Keys Using Discrete Logarithm Cryptography standard:
       SecretKey = ServerPubKey ^ ClientPrvKey mod Prime.
\note All buffer parameters should be in big-endian form. \par
\note The user must obtain assurance of validity of the public key, using one of methods,
described in section 7.4 of ANSI X9.42-2003: Public Key Cryptography for the Financial Services Industry: Agreement of Symmetric
Keys Using Discrete Logarithm Cryptography. \par
\note The actual size of the private key (in bits) must be not less than 2 and not greater than the actual
size of the Prime (modulus in bits).

@return \c CC_OK on success.
@return A non-zero value on failure as defined in cc_dh_error.h or cc_rsa_error.h.
*/
CIMPORT_C CCError_t CC_DhGetSecretKey(
					uint8_t *ClientPrvKey_ptr,             /*!< [in]  Pointer to the Private key octet string Prv < Prime. */
					size_t ClientPrvKeySize,               /*!< [in]  The Private key Size (in bytes). */
					uint8_t *ServerPubKey_ptr,             /*!< [in]  Pointer to the Server public key octet string. */
					size_t ServerPubKeySize,               /*!< [in]  The Server Public key Size (in bytes). */
					uint8_t *Prime_ptr,                    /*!< [in]  Pointer to the Prime octet string. */
					size_t PrimeSize,                      /*!< [in]  The size of the Prime string. */
					CCDhUserPubKey_t *tmpPubKey_ptr,       /*!< [in]  Pointer to the public key structure. Used for the exponentiation
										          operation function. Need not be initialized. */
					CCDhPrimeData_t  *tmpPrimeData_ptr,    /*!< [in]  Pointer to a structure containing internal temp buffers. */
					uint8_t *SecretKey_ptr,                /*!< [out] Pointer to the secret key octet string. This buffer should be at
										  	  least PrimeSize bytes. */
					size_t *SecretKeySize_ptr              /*!< [in/out] Pointer to the secret key Buffer Size. This buffer should be at
											     least of PrimeSize bytes:
											     <ul><li> Input  - size of the given buffer.</li>
										 	     <li> Output - actual size. </li></ul>*/
);


/******************************************************************************************/
/*!
@brief This function extracts the shared secret keying data from the shared secret value. It should be called by using
macros ::CC_DhX942GetSecretDataAsn1 and ::CC_DhX942GetSecretDataConcat.

\note The "other info" argument and its AlgorithmID entry are mandatory only for ASN1 key derivation, and optional for
the other derivation modes. \par
\note If used, all entries of the structure should be initialized with relevant data and size, prior to calling this function
(entry size of empty fields must be set to 0). \par
\note All buffers arguments are represented in big-endian form.

@return \c CC_OK on success.
@return A non-zero value on failure as defined in cc_dh_error.h, cc_rsa_error.h, cc_kdf_error.h or cc_hash_error.h.
*/
 CIMPORT_C CCError_t CC_DhX942GetSecretData(
                    uint8_t                  *ClientPrvKey_ptr,        /*!< [in] Pointer to the Private key octet string. */
                    size_t                   ClientPrvKeySize,         /*!< [in] The Private key size (in bytes). */
                    uint8_t                  *ServerPubKey_ptr,        /*!< [in] Pointer to the Server public key octet string. */
		    size_t                   ServerPubKeySize,         /*!< [in] The Server Public key size (in bytes). */
                    uint8_t                  *Prime_ptr,               /*!< [in] Pointer to the Prime octet string. */
                    size_t                   PrimeSize,                /*!< [in] The size of the Prime string. */
                    CCDhOtherInfo_t      *otherInfo_ptr,           /*!< [in] Pointer to structure containing other data, shared by two entities
										  sharing the secret keying data.
                                                                                  The Maximal size of each data entry of "other info" is limited - see cc_kdf.h
										  for the defined value. */
                    CCDhHashOpMode_t       hashMode,               /*!< [in] One of the supported SHA-x HASH modes. The supported modes are according to the supported
								        	  HASH modes for the product (and MD5 is not supported). */
                    CCDhDerivationFuncMode_t DerivFunc_mode,        /*!< [in] The enumerator ID of key derivation function mode. ASN1 or Concatenation
										  modes are supported. */
                    CCDhTemp_t           *tmpBuff_ptr,             /*!< [in] A pointer to the DH temp buffer structure. Not initialized. */
                    uint8_t                  *SecretKeyingData_ptr,    /*!< [out] Pointer to the secret key octet string. This buffer should be at least
										   PrimeSize bytes. */
                    size_t                   SecretKeyingDataSize      /*!< [in] The required Secret Keying data size (in bytes). Must be larger than 0,
										  and smaller than the maximal - CC_DH_MAX_SIZE_OF_KEYING_DATA. */
);

/****************************************************************/
/*!
This macro implements the DH ANSI X9.42-2003: Public Key Cryptography for the Financial Services Industry: Agreement of Symmetric Keys Using
Discrete Logarithm Cryptography standard. It derives a secret key using the Derivation function based on ASN.1. For a description of the
parameters see ::CC_DhX942GetSecretData.*/
#define CC_DhX942GetSecretDataAsn1(ClientPrvKey_ptr,ClientPrvKeySize,ServerPubKey_ptr,ServerPubKeySize,Prime_ptr,PrimeSize,otherInfo_ptr,hashMode,tmpBuff_ptr,SecretKeyingData_ptr,SecretKeyingDataSize)\
	CC_DhX942GetSecretData((ClientPrvKey_ptr),(ClientPrvKeySize),(ServerPubKey_ptr),(ServerPubKeySize),(Prime_ptr),(PrimeSize),(otherInfo_ptr),(hashMode),(CC_DH_ASN1_Der_mode),(tmpBuff_ptr),(SecretKeyingData_ptr),(SecretKeyingDataSize))
/*!
This macro implements the DH ANSI X9.42-2003: Public Key Cryptography for the Financial Services Industry: Agreement of Symmetric Keys Using Discrete
Logarithm Cryptography standard. It derives a secret key using the Derivation function based on concatenation of HASHed data. For a description
of the parameters see ::CC_DhX942GetSecretData.*/
#define CC_DhX942GetSecretDataConcat(ClientPrvKey_ptr,ClientPrvKeySize,ServerPubKey_ptr,ServerPubKeySize,Prime_ptr,PrimeSize,otherInfo_ptr,hashMode,tmpBuff_ptr,SecretKeyingData_ptr,SecretKeyingDataSize)\
	CC_DhX942GetSecretData((ClientPrvKey_ptr),(ClientPrvKeySize),(ServerPubKey_ptr),(ServerPubKeySize),(Prime_ptr),(PrimeSize),(otherInfo_ptr),(hashMode),(CC_DH_Concat_Der_mode),(tmpBuff_ptr),(SecretKeyingData_ptr),(SecretKeyingDataSize))


/****************************************************************/
/*!
@brief The function computes shared secret data using two pairs of public and private keys:

<ul><li> SecretKey1 = ServerPubKey1^ClientPrvKey1 mod Prime. </li>
<li> SecretKey2 = ServerPubKey2^ClientPrvKey2 mod Prime. </li></ul>
It uses the Derivation function to derive secret keying data from the two secret keys (values).
This function may be called directly, or by using macros ::CC_DhX942HybridGetSecretDataAsn1 and ::CC_DhX942HybridGetSecretDataConcat
described above.

\note The "other info" argument and its AlgorithmID entry are mandatory only for ASN1 key derivation, and optional for the other derivation modes.
If used, all entries of the structure should be initialized with relevant data and size, prior to calling this function
(entry size of empty fields must be set to 0). \par
\note Both client's key pairs (i.e. private keys) shall be generated randomly in order to be different. \par
\note All buffers arguments are represented in big-endian form.

@return \c CC_OK on success.
@return A non-zero value on failure as defined in cc_dh_error.h, cc_rsa_error.h or cc_hash_error.h.
*/
CIMPORT_C CCError_t CC_DhX942HybridGetSecretData(
                uint8_t            *ClientPrvKey_ptr1,          /*!< [in]  Pointer to the First Private key octet string number. */
                size_t             ClientPrvKeySize1,           /*!< [in]  The First Private key Size (in bytes). */
                uint8_t            *ClientPrvKey_ptr2,          /*!< [in]  Pointer to the Second Private key octet string. */
		size_t             ClientPrvKeySize2,           /*!< [in]  The Second Private key Size (in bytes). */
                uint8_t            *ServerPubKey_ptr1,          /*!< [in]  Pointer to the First Server public key octet string. */
                size_t             ServerPubKeySize1,           /*!< [in]  The First Server Public key Size (in bytes). */
                uint8_t            *ServerPubKey_ptr2,          /*!< [in]  Pointer to the Second Server public key octet string. */
                size_t             ServerPubKeySize2,           /*!< [in]  The Second Server Public key Size (in bytes). */
                uint8_t            *Prime_ptr,                  /*!< [in]  Pointer to the Prime octet string. */
                size_t             PrimeSize,                   /*!< [in]  The size of the Prime string. */
                CCDhOtherInfo_t  *otherInfo_ptr,            /*!< [in]  Pointer to structure containing optional other data, shared by two entities
								 sharing the secret keying data. */
                CCDhHashOpMode_t hashMode,                 /*!< [in]  One of the supported SHA-x HASH modes. The supported modes are according to the supported
								           HASH modes for the product (and MD5 is not supported). */
                CCDhDerivationFuncMode_t DerivFunc_mode,     /*!< [in]  The type of function to use to derive the secret key to the key data.
								 ASN.1 or Concatenation modes are supported. */
                CCDhHybrTemp_t   *tmpDhHybr_ptr,            /*!< [in]  Pointer to a CCDhTemp_t structure that contains temp buffers for
								 internal operations. */
                uint8_t            *SecretKeyingData_ptr,       /*!< [out] Pointer to the secret key octet string. This buffer should be at least
								 of size PrimeSize bytes. */
                size_t             SecretKeyingDataSize         /*!< [in]  The required Secret Keying data size (in bytes). Must be larger than 0,
								 and smaller than CC_DH_MAX_SIZE_OF_KEYING_DATA. */
);


/****************************************************************/
/*!
This macro implements the DH ANSI X9.42-2003: Public Key Cryptography for the Financial Services Industry: Agreement of Symmetric Keys Using Discrete
Logarithm Cryptography standard deriving a hybrid secret key from two public-private pair of keys using the Derivation function based on ASN.1.
For a description of the parameters see ::CC_DhX942HybridGetSecretData.*/
#define CC_DhX942HybridGetSecretDataAsn1(ClientPrvKey_ptr1,ClientPrvKeySize1,ClientPrvKey_ptr2,ClientPrvKeySize2,ServerPubKey_ptr1,ServerPubKeySize1,ServerPubKey_ptr2,ServerPubKeySize2,Prime_ptr,PrimeSize,otherInfo_ptr,hashFunc,tmpDhHybr_ptr,SecretKeyingData_ptr,SecretKeyingDataSize)\
	CC_DhX942HybridGetSecretData((ClientPrvKey_ptr1),(ClientPrvKeySize1),(ClientPrvKey_ptr2),(ClientPrvKeySize2),(ServerPubKey_ptr1),(ServerPubKeySize1),(ServerPubKey_ptr2),(ServerPubKeySize2),(Prime_ptr),(PrimeSize),(otherInfo_ptr),(hashFunc),CC_DH_ASN1_Der_mode,(tmpDhHybr_ptr),(SecretKeyingData_ptr),(SecretKeyingDataSize))

/*!
This macro implements the DH ANSI X9.42-2003: Public Key Cryptography for the Financial Services Industry: Agreement of Symmetric Keys Using Discrete
Logarithm Cryptography standard, deriving a hybrid secret key from two pairs of public-private keys, using the Derivation
function based on concatenation using SHA-x HASH. For a description of the parameters see ::CC_DhX942HybridGetSecretData.
*/
#define CC_DhX942HybridGetSecretDataConcat(ClientPrvKey_ptr1,ClientPrvKeySize1,ClientPrvKey_ptr2,ClientPrvKeySize2,ServerPubKey_ptr1,ServerPubKeySize1,ServerPubKey_ptr2,ServerPubKeySize2,Prime_ptr,PrimeSize,otherInfo_ptr,hashFunc,tmpDhHybr_ptr,SecretKeyingData_ptr,SecretKeyingDataSize)\
	CC_DhX942HybridGetSecretData((ClientPrvKey_ptr1),(ClientPrvKeySize1),(ClientPrvKey_ptr2),(ClientPrvKeySize2),(ServerPubKey_ptr1),(ServerPubKeySize1),(ServerPubKey_ptr2),(ServerPubKeySize2),(Prime_ptr),(PrimeSize),(otherInfo_ptr),(hashFunc),CC_DH_Concat_Der_mode,(tmpDhHybr_ptr),(SecretKeyingData_ptr),(SecretKeyingDataSize))


/******************************************************************************************/
/*!
@brief The function checks the obtained DH public key according to its domain parameters ANSI X9.42-2003: Public Key Cryptography for the
Financial Services Industry: Agreement of Symmetric Keys Using Discrete Logarithm Cryptography.

\note Assuming: The DH domain parameters are valid.

@return \c CC_OK on success.
@return A non-zero value on failure as defined in cc_dh_error.h.
*/
CIMPORT_C CCError_t CC_DhCheckPubKey(
					uint8_t              *modP_ptr,            /*!< [in] The pointer to the modulus (prime) P. */
					size_t               modPsizeBytes,        /*!< [in]  The modulus size in bytes. */
					uint8_t              *orderQ_ptr,          /*!< [in]  The pointer to the prime order Q of generator. */
					size_t               orderQsizeBytes,      /*!< [in]  The size of order of generator in bytes. */
					uint8_t              *pubKey_ptr,          /*!< [in]  The pointer to the public key to be validated. */
					size_t               pubKeySizeBytes,      /*!< [in]  The public key size in bytes. */
					CCDhTemp_t       *tempBuff_ptr         /*!< [in]  The temp buffer for internal calculations. */
);


#ifdef __cplusplus
}
#endif
/**
@}
 */
#endif
