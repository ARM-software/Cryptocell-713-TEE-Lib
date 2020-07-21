
/*
 This file contains the module definitions for CC713 Boot and RT
 */



 /*
  ############################TOP-LEVEL APIs RT###################################
 */
 /*!
 @defgroup cc_sb CryptoCell Runtime Secure Boot
 @brief Contains all Runtime Secure Boot APIs and definitions.
 */

 /*!
  @defgroup cc_hal HAL related APIs and definitions
  @brief Contains the functions that are used for the HAL layer.
  */

  /*!
  @defgroup cc_pal PAL related APIs and definitions
  @brief Contains PAL related APIs and definitions
  */

/*!
 @defgroup cryptocell_api CryptoCell APIs
 @brief Contains CryptoCell APIs
 */


   /*!
   @defgroup cc_gen_defs CryptoCell definitions
   @brief Contains CryptoCell definitions.
   */

   /*!
  @defgroup cc_ecpki CryptoCell ECC APIs
  @brief Contains functions and definitions for handling keys used in Elliptic Curves Cryptography (ECC).
 */


   /*!
  @defgroup ch_crypto Chinese certification cryptographic APIs
  @brief Contains Chinese certification cryptographic APIs and definitions
  */

/*!
  @defgroup drbg_apis DRBG APIs
  @brief Contains DRBG APIs
 */

/*!
  @defgroup cc_aes AES APIs
  @brief Contains AES APIs and definitions
*/

/*!
 @defgroup cc_rsa CryptoCell RSA APIs and definitions
 @brief Contains CryptoCell RSA APIs and definitions.
 */

 /*!
 @defgroup cc_dh CryptoCell Diffie-Hellman APIs
 @brief Contains the APIs that support Diffie-Hellman key exchange.
 */

  /*!
  @defgroup cc_hash CryptoCell Hash APIs
  @brief Contains CryptoCell Hash APIs.
  */

/*!
 @defgroup cc_utils CryptoCell utility APIs
 @brief Contains CryptoCell utility APIs
*/

  /*
  ############################true-random-numberdefinitions and APIs###################################
 */

  /*!
  @defgroup drbg_module Random number generation definitions
  @brief Contains all random number generation definitions
   @ingroup drbg_apis
 */

/*!
 @defgroup cc_rnd CryptoCell random-number generation definitions.
 @brief Contains the CryptoCell random-number generation definitions.
 @ingroup drbg_apis
 */

 /*!
 @defgroup cc_rnd_defines CryptoCell true-random-number generation definitions.
 @brief Contains the CryptoCell true-random-number generation defines.
 @ingroup drbg_apis
 */

 /*!
 @defgroup cc_rnd_error CryptoCell random-number-specific errors
 @brief Contains the definitions of the CryptoCell DRBG errors.
 @ingroup drbg_apis
*/




  /*
  ############################chinese crypto APIs###################################
 */

/*!
  @defgroup cc_sm2 SM2 APIs
  @brief Contains SM2 APIs and definitions
  @ingroup ch_crypto
  */

  /*!
  @defgroup cc_sm3 SM3 APIs
  @brief Contains SM3 APIs and definitions
  @ingroup ch_crypto
  */

  /*!
  @defgroup cc_sm4 SM4 APIs
  @brief Contains SM4  APIs and definitions
  @ingroup ch_crypto
*/

  /*!
 @defgroup ch_cert_defs Chinese certification cryptographic definitions
 @brief Contains definitions and APIs that are used in the CryptoCell Chinese Certification module.
 @ingroup ch_crypto
*/

/*!
 @defgroup ch_cert_errors Chinese certification errors
 @brief Contains Chinese certification error definitions
 @ingroup ch_crypto
 */

 /*!
 @defgroup cc_sm3_defs CryptoCell SM3 type definitions
 @brief Contains CryptoCell SM3 type definitions.
 @ingroup cc_sm3
*/

/*!
@defgroup cc_sm3_error CryptoCell SM3-specific errors
@brief Contains the definitions of the CryptoCell SM3 errors.
@ingroup cc_sm3
*/

/*!
 @defgroup cc_sm4_defs CryptoCell SM4 type definitions
 @brief Contains CryptoCell SM4 type definitions.
 @ingroup cc_sm4
 */

 /*!
 @defgroup cc_sm4_error CryptoCell SM4-specific errors
 @brief Contains the definitions of the CryptoCell SM4 errors.
 @ingroup cc_sm4
*/

 /*
 ################################## AES APIs #######################################
  */

  /*!
 @defgroup cc_aes_defs CryptoCell AES type definitions
 @brief Contains CryptoCell AES type definitions.
 @ingroup cc_aes
 */

 /*!
 @defgroup cc_aes CryptoCell AES APIs
 @brief Contains all the enums and definitions that are used for the
 CryptoCell AES APIs, as well as the APIs themselves.
 */

 /*!
 @defgroup cc_aes_error CryptoCell AES-specific errors
 @brief Contains the definitions of the CryptoCell AES errors.
 @ingroup cc_aes
 */

 /*!
 @defgroup cc_aes_ccm AES CCM APIs, enums and definitions
 @brief Contains all the APIs, enums and definitions for the CryptoCell AES CCM.
 @ingroup cc_aes
 */

 /*!
  @defgroup cc_aes_gcm AES GCM APIs, enums and definitions
  @brief Contains all the APIs, enums and definitions for the CryptoCell AES GCM.
  @ingroup cc_aes
  */

  /*!
   @defgroup cc_aesgcm_error CryptoCell AES-GCM-specific errors
   @brief Contains the definitions of the CryptoCell AES GCM errors.
   @ingroup cc_aes
   */

   /*!
   @defgroup cc_aesccm_error CryptoCell AES-CCM-specific errors
   @brief Contains the definitions of the CryptoCell AES CCM errors.
   @ingroup cc_aes
   */

 /*
 ################################### CryptoCell macros ################################
  */

 /*!
  @defgroup bit_field_apis Bit-field operations macros
  @brief Contains bit-field operation macros.
  @ingroup cc_gen_defs
  */


  /*!
 @defgroup cc_error General base error codes for CryptoCell
 @brief Contains general base-error codes for CryptoCell.
 @ingroup cc_gen_defs
 */

 /*!
  @defgroup cc_cert_defs CryptoCell general certification definitions
  @brief Contains CryptoCell general certification definitions.
  @ingroup cc_gen_defs
  */

/*!
 @defgroup cc_axi_config AXI configuration control definitions
  @brief Contains the AXI configuration control definitions.
  @ingroup cc_gen_defs
  */

  /*!
  @defgroup cc_pka_defs PKA enums and definitions
  @brief Contains all the enums and definitions that are used in the PKA related code.
  @ingroup cc_gen_defs
  */

 /*!
  @defgroup cc_regs CryptoCell register APIs
  @brief Contains macro definitions for accessing CryptoCell registers.
  @ingroup cc_gen_defs
  */

  /*!
  @defgroup cc_lib_apis Library initialize and finish APIs
  @brief Contains all the enums and definitions that are used for the
        CryptoCell Library initialize and finish APIs, as well as the APIs themselves.
  @ingroup cc_gen_defs
  */

  /*!
  @defgroup cc_sec_defs General security definitions
  @brief Contains general security definitions.
  @ingroup cc_gen_defs
  */

  /*!
  @defgroup cc_fips CryptoCell FIPS definitions and APIs
  @brief Contains definitions and APIs that are used in the CryptoCell FIPS module.
  @ingroup cryptocell_api
*/
  /*!
  @defgroup cc_fips_errors Error codes definitions for CryptoCell FIPS module
  @brief Contains error codes definitions for CryptoCell FIPS module.
  @ingroup cc_fips
*/

/*!
 @defgroup cc_secure_clock Secure clock definitions
 @brief Contains definitions for Secure clock.
 @ingroup cryptocell_api
 */

 /*!
  @defgroup power_manage Power management definitions and APIs
  @brief Contains power management definitions and APIs.
  @ingroup cryptocell_api
  */

  /*!
  @defgroup cc_cpp_apis CryptoCell CPP API definitions
  @brief Contains the enums and definitions used for the
        CryptoCell CPP APIs.
  @ingroup cryptocell_api
  */

  /*!
  @defgroup cc_address_defs General CryptoCell address definitions
  @brief Contains general CryptoCell address definitions.
  @ingroup cryptocell_api
  */




  /*
 ##################################### KDF macros ##########################
  */


 /*!
 @defgroup cc_kdf CryptoCell Key Derivation APIs
 @brief Defines the API that supports Key derivation function in modes
       as defined in Public-Key Cryptography Standards (PKCS) #3: Diffie-Hellman Key Agreement Standard,
       ANSI X9.42-2003: Public Key Cryptography for the Financial Services Industry: Agreement of Symmetric Keys Using Discrete Logarithm Cryptography,
       and ANSI X9.63-2011: Public Key Cryptography for the Financial Services Industry - Key Agreement and Key Transport Using Elliptic Curve
       Cryptography.
 @ingroup cryptocell_api
 */

 /*!
 @defgroup cc_kdf_defs CryptoCell Key Derivation definitions
 @brief Contains the CryptoCell Key Derivation definitions.
 @ingroup cc_kdf
 */

  /*!
 @defgroup cc_kdf_error CryptoCell Key Derivation-specific errors
 @brief Contains the definitions of the CryptoCell KDF errors.
 @ingroup cc_kdf
 */



   /*
 ##################################### DES macros ##########################
 */

 /*!
 @defgroup cc_des_apis APIs, enums and definitions of CryptoCell DES APIs
 @brief Contains all the APIs, enums and definitions of CryptoCell DES APIs.
 @ingroup cryptocell_api
 */

 /*!
 @defgroup cc_des_error Definitions of the CryptoCell DES errors
 @brief Contains the definitions of the CryptoCell DES errors.
 @ingroup cc_des_apis
 */

  /*
 ##################################### HMAC macros ##########################
 */

  /*!
 @defgroup cc_hmac CryptoCell HMAC APIs
 @brief Contains all the enums and definitions
 that are used for the CryptoCell HMAC APIs, as well as the APIs themselves.
 @ingroup cryptocell_api
 */

 /*!
  @defgroup cc_hmac_defs CryptoCell HMAC definitions
  @brief Contains CryptoCell HMAC definitions.
  @ingroup cc_hmac
  */

   /*!
 @defgroup cc_hmac_error CryptoCell HMAC-specific errors
 @brief Contains the definitions of the CryptoCell HMAC errors.
 @ingroup cc_hmac
*/

 /*
 ##################################### HKDF macros ##########################
 */

 /*!
 @defgroup cc_hkdf CryptoCell HKDF APIs and definitions.
 @brief Defines the API that supports HMAC Key derivation function as
       defined by RFC5869.
 @ingroup cryptocell_api
 */

 /*!
  @defgroup cc_hkdf_error HMAC Key Derivation-specific errors
  @brief Contains the definitions of the CryptoCell HKDF errors.
  @ingroup cc_hkdf
 */

 /*
 ##################################### Diffie-Hellman macros ##########################
 */

 /*!
 @defgroup cc_dh_kg CryptoCell Diffie-Hellman Key Generation APIs
 @brief Contains the API that supports C domain.
 @ingroup cc_dh
 */


 /*!
 @defgroup cc_dh_error Diffie-Hellman-specific errors
 @brief Contains error codes definitions for CryptoCell Diffie-Hellman module.
 @ingroup cc_dh
*/

  /*
 ################################### Hash macros ################################
 */

 /*!
 @defgroup cc_hash_defs CryptoCell hash type definitions
 @brief Contains CryptoCell hash type definitions.
 @ingroup cc_hash
*/

  /*!
 @defgroup cc_hash_error CryptoCell HASH specific errors
 @brief Contains the definitions of the CryptoCell HASH errors.
 @ingroup cc_hash
*/

 /*
 ################################### RSA macros ################################
 */

 /*!
 @defgroup cc_rsa_types RSA definitions and enums
 @brief Contains CryptoCell RSA used definitions and enums.
 @ingroup cc_rsa
*/

 /*!
 @defgroup cc_rsa_kg CryptoCell RSA key generation APIs
 @brief Generates a RSA pair of public and private keys.
 @ingroup cc_rsa
 */

 /*!
 @defgroup cc_rsa_schemes CryptoCell RSA encryption and signature schemes
 @brief Contains CryptoCell RSA encryption and signature schemes
 @ingroup cc_rsa
*/
 /*!
 @defgroup cc_rsa_prim CryptoCell RSA primitive APIs
 @brief  Contains the API that implements the Public-Key Cryptography Standards (PKCS) #1
 RSA Cryptography Specifications Version 2.1 primitive functions.
 @ingroup cc_rsa
*/

 /*!
 @defgroup cc_rsa_error CryptoCell RSA specific errors
 @brief Contains the definitions of the CryptoCell RSA errors.
 @ingroup cc_rsa
*/

/*!
 @defgroup cc_rsa_build RSA build functions
 @brief Contains utility functions for working with RSA cryptography.
 @ingroup cc_rsa
 */

 /*
 ################################### CC utility APIs ################################
 */

   /*!
 @defgroup cc_utils_errors Specific errors of the CryptoCell utility module APIs
 @brief Contains utility API error definitions.
 @ingroup cc_utils
 */

/*!
  @defgroup cc_utils_defs CryptoCell utility general definitions
 @brief Contains CryptoCell utility general definitions.
 @ingroup cc_utils
 */

/*!
 @defgroup cc_utils_key_derivation CryptoCell utility key derivation APIs
 @brief Contains the API that supports Key derivation function as specified
       in NIST Special Publication 800-108: Recommendation for Key Derivation Using Pseudorandom Functions
       in section "KDF in Counter Mode".
 @ingroup cc_utils
*/

/*!
 @defgroup cc_utils_key_defs CryptoCell utility general key definitions
 @brief Contains the definitions for the key derivation API.
 @ingroup cc_utils
 */


/*!
 @defgroup cc_util_functions CryptoCell utility functions and definitions
 @brief Contains CryptoCell utility functions and definitions.
 @ingroup cc_utils
 */

 /*!
 @defgroup oem_util OEM asset provisioning functions
 @brief Contains the functions and definitions for the OEM Asset provisioning.
 @ingroup cc_utils
 */

 /*!
  @defgroup rpmb_util RPMB functions and definitions
  @brief Contains the functions and definitions for the Replay Protected Memory Block.
  @ingroup cc_utils
  */

  /*!
  @defgroup sec_timer Secure timer functions and definitions
  @brief Contains the functions and definitions for the Secure timer module.
  @ingroup cc_utils
  */

  /*!
   @defgroup backup_restore_util CryptoCell utility backup and restore functions and definitions
   @brief Contains CryptoCell utility backup and restore functions and definitions.
   @ingroup cc_utils
   */

   /*!
  @defgroup icv_oem_provisioning_apis  CryptoCell runtime-library ICV and OEM asset-provisioning APIs and definitions
  @brief Contains CryptoCell runtime-library ICV and OEM asset-provisioning APIs and definitions.
  @ingroup cc_utils
  */

  /*!
  @defgroup cc_hw_key_utils CryptoCell hardware key APIs and their enumerations and definitions
  @brief Contains the CryptoCell hardware key APIs and their enumerations and definitions.
  @ingroup cc_utils
  */



/*
############################################## ECC APIs ############################
*/

 /*!
 @defgroup cc_ecpki_error CryptoCell ECC specific errors
 @brief Contains errors that are specific to ECC.
 @ingroup cc_ecpki
*/

/*!
 @defgroup cc_ecpki_types CryptoCell ECPKI type definitions
 @brief Contains CryptoCell ECPKI type definitions.
 @ingroup cc_ecpki
 */

 /*!
 @defgroup cc_ecpki_kg CryptoCell APIs for generation of ECC private and public keys
 @brief Contains CryptoCell APIs for generation of ECC private and public keys.
 @ingroup cc_ecpki
*/


  /*!
 @defgroup cc_ecpki_ecdsa CryptoCell ECDSA APIs
 @brief Contains the APIs that support the ECDSA functions.
 @ingroup cc_ecpki
 */

 /*!
 @defgroup cc_ecies_apis ECIES APIs
 @brief Contains APIs that support EC Integrated Encryption Scheme.
 @ingroup cc_ecpki
 */

 /*!
 @defgroup cc_ecpki_domain ECPKI build domain APIs
 @brief Contains ECPKI build domain APIs.
 @ingroup cc_ecpki
 */

 /*!
 @defgroup ecpki_domain_defs ECPKI domain definitions
 @brief Contains ECPKI domain definitions.
 @ingroup cc_ecpki
 */


 /*
#################################################### HAL APIs ##############################
*/

 /*!
 @defgroup cc_hal_register CryptoCell HAL register operations
 @brief Contains CryptoCell HAL register operations.
 @ingroup cc_hal
 */

 /*!
 @defgroup cc_hal_defs CryptoCell HAL definitions
 @brief Contains CryptoCell HAL definitions.
 @ingroup cc_hal
 */

/*
#################################################### PAL APIs ##############################
*/

 /*!
 @defgroup cc_pal_abort CryptoCell PAL abort operations
 @brief Contains CryptoCell PAL abort operations.
 @ingroup cc_pal
 */

  /*!
 @defgroup cc_pal_barrier CryptoCell PAL memory Barrier APIs
 @brief Contains memory-barrier implementation definitions and APIs.
 @ingroup cc_pal
*/

/*!
 @defgroup cc_pal_cert CERT definitions
 @brief Contains definitions that are used by the CERT related APIs. The implementation of these functions
 need to be replaced according to the Platform and TEE_OS.
 @ingroup cc_pal
 */

 /*!
 @defgroup cc_pal_compiler CryptoCell PAL platform-dependent compiler-specific definitions
 @brief Contains CryptoCell PAL platform-dependent compiler-related definitions.
 @ingroup cc_pal
 */

 /*!
 @defgroup cc_pal_dma CryptoCell PAL DMA related APIs
 @brief Contains definitions that are used for DMA-related APIs.
 @ingroup cc_pal
 */

 /*!
 @defgroup cc_pal_error Specific errors of the CryptoCell PAL APIs
 @brief Contains platform-dependent PAL-API error definitions.
 @ingroup cc_pal
 */
 /*!
 @defgroup cc_pal_init CryptoCell PAL entry or exit point APIs
 @brief Contains PAL initialization and termination APIs.
 @ingroup cc_pal
 */

 /*!
 @defgroup cc_pal_log CryptoCell PAL logging APIs and definitions
 @brief Contains CryptoCell PAL layer log definitions.
 @ingroup cc_pal
 */

 /*!
 @defgroup cc_pal_mem CryptoCell PAL memory operations
 @brief Contains memory-operation functions.
 @ingroup cc_pal
 */

 /*!
 @defgroup cc_pal_memmap CryptoCell PAL memory mapping APIs
 @brief Contains memory mapping functions.
 @ingroup cc_pal
 */

 /*!
 @defgroup cc_pal_mutex CryptoCell PAL mutex APIs
 @brief Contains resource management functions.
 @ingroup cc_pal
 */

 /*!
 @defgroup cc_pal_pm CryptoCell PAL power-management APIs
 @brief Contains PAL power-management APIs.
 @ingroup cc_pal
 */

 /*!
 @defgroup cc_pal_trng CryptoCell PAL TRNG APIs
 @brief Contains APIs for retrieving TRNG user parameters.
 @ingroup cc_pal
 */

 /*!
 @defgroup cc_pal_types CryptoCell platform-dependent PAL layer definitions and types
  @brief Contains platform-dependent definitions and types of the PAL layer.
 @ingroup cc_pal
*/

  /*!
 @defgroup cc_pal_types CryptoCell platform-dependent PAL layer definitions and types
 @brief Contains platform-dependent definitions and types of the PAL layer.
 @ingroup cc_pal
*/

 /*!
  @defgroup pal_interrupt PAl interrupt functions
  @brief Contains PAL interrupt functions.
  @ingroup cc_pal
 */

  /*!
  @defgroup sb_pal_functions X509 PAL functions and definitions
  @brief contains X509 user-defined functions and related data structures.
  @ingroup cc_pal
  */

 /*!
  @defgroup cc_x509_defs X509 certificate definitions
  @brief Contains definitions used in the X509 certificates.
  @ingroup pal_functions
  */


 /*
 ############################################## Runtime Secure boot APIs ##########################
 */

/*!
 @defgroup cc_sb_defs CryptoCell Secure Boot definitions
 @brief Contains CryptoCell Secure Boot type definitions.
 @ingroup cc_sb
 */

  /*!
  @defgroup cc_sbrom_defs Secure boot definitions
  @brief Contains Secure boot definitions.
  @ingroup cc_sb
 */

 /*!
 @defgroup cc_sb_error CryptoCell Secure Boot error codes
 @brief Contains the error codes that are returned from the Secure Boot code.
 @ingroup cc_sb
 */

 /*!
 @defgroup cc_sb_image_verifier CryptoCell Secure Boot definitions
 @brief Contains definitions used for the Secure Boot and Secure Debug APIs.
 @ingroup cc_sb
 */

 /*!
 @defgroup cc_rt_bsv_api CryptoCell Runtime Secure Boot certificate-chain-processing APIs.
 @brief Contains CryptoCell Runtime Secure Boot certificate-chain-processing APIs.
 @ingroup cc_sb
  */

 /*!
 @defgroup cc_sb_image_verifier CryptoCell Secure Boot and Secure Debug API definitions
 @brief Contains definitions used for the Secure Boot and Secure Debug APIs.
 \n See bootimagesverifier_def.h.
 @ingroup cc_sb
 */


