# Project Makefile for cc713tee full product (complementary to slim Makefile !!!)

# TEE sources
SOURCES_$(TARGET_LIBS) += cc_lib.c

# CC NIST APIs sources
SOURCES_$(TARGET_LIBS) += cc_aes.c cc_hash.c cc_hmac.c cc_des.c cc_aesccm.c cc_aesgcm.c
SOURCES_$(TARGET_LIBS) += cc_hkdf.c

# Symmetric HW driver sources
SOURCES_$(TARGET_LIBS) += hmac.c aead.c cc_hash_info.c

#secure boot internals
SOURCES_$(TARGET_LIBS) += cc_sbrt_crypto_int_api.c
SOURCES_$(TARGET_LIBS) += cc_sbrt_crypto_driver.c
SOURCES_$(TARGET_LIBS) += cc_sbrt_api.c

#util
SOURCES_$(TARGET_LIBS) += cc_util_hw_key.c
SOURCES_$(TARGET_LIBS) += cc_util_cmac.c
SOURCES_$(TARGET_LIBS) += cc_asset_provisioning.c
SOURCES_$(TARGET_LIBS) += cc_util.c
SOURCES_$(TARGET_LIBS) += cc_util_key_derivation.c
SOURCES_$(TARGET_LIBS) += cc_util_stimer.c
SOURCES_$(TARGET_LIBS) += cc_util_rpmb.c
SOURCES_$(TARGET_LIBS) += cc_util_rpmb_adaptor.c
SOURCES_$(TARGET_LIBS) += cc_util_backup_restore.c

CC_SOFT_KEYGEN_SIZE ?= 0

ifeq ($(CC_CONFIG_SUPPORT_FULL_PROJECT), 1)
CFLAGS += -DCC_SUPPORT_FULL_PROJECT
endif

ifeq ($(CC_FIPS_CERTIFICATION),1)
CFLAGS += -DFIPS_CERTIFICATION
INCDIRS_EXTRA += $(SHARED_INCDIR)/tests
endif

ifeq ($(PKA_DEBUG),1)
CFLAGS += -DPKA_DEBUG
SOURCES_$(TARGET_LIBS) += pki_dbg.c
endif

ifeq ($(TEE_OS),optee)
ifndef OPTEE_OS_DIR
$(error OPTEE_OS_DIR is undefined)
#OPTEE_OS_DIR = /home/fw/$(USER)/work/cc_infra/trunk/optee/optee_os
endif
CFLAGS += -DARM64=1
ifeq ($(DEBUG),1)
CFLAGS += -DCFG_TEE_CORE_DEBUG=1
else
CFLAGS += -DCFG_TEE_CORE_DEBUG=0
endif
INCDIRS_EXTRA += $(OPTEE_OS_DIR)/core/include
INCDIRS_EXTRA += $(OPTEE_OS_DIR)/core/include/mm
INCDIRS_EXTRA += $(OPTEE_OS_DIR)/core/include/kernel
INCDIRS_EXTRA += $(OPTEE_OS_DIR)/core/arch/arm/include
INCDIRS_EXTRA += $(OPTEE_OS_DIR)/core/arch/arm/tee
INCDIRS_EXTRA += $(OPTEE_OS_DIR)/lib/libutils/ext/include
INCDIRS_EXTRA += $(OPTEE_OS_DIR)/lib/libutils/isoc/include
INCDIRS_EXTRA += $(OPTEE_OS_DIR)/lib/libutee/include
INCDIRS_EXTRA += $(OPTEE_OS_DIR)/lib/libmpa/include
SOURCES_$(TARGET_LIBS) += tee_cc_provider.c
VPATH += $(HOST_SRCDIR)/optee $(HOST_SRCDIR)/hal/optee
endif #optee

INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/secure_boot_debug/bsv_rsa_driver
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/secure_boot_debug/bsv_rsa_driver/cc7x
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/secure_boot_debug/platform/hal
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/secure_boot_debug/platform/hal/cc7x
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/secure_boot_debug/secure_boot
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/secure_boot_debug/secure_debug
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/secure_boot_debug/cert_parser
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/secure_boot_debug/
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/secure_boot_debug/platform/stage/rt/cc7x
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/secure_boot_debug/platform/pal/cc7x
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/secure_boot_debug/platform/pal

ifeq ($(CC_CONFIG_SB_X509_CERT_SUPPORTED),1)
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/secure_boot_debug/cert_parser/x509
CFLAGS_EXTRA += -DCC_SB_X509_CERT_SUPPORTED
else
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/secure_boot_debug/cert_parser/prop
endif

# no generation in sw => max generation in hw
CFLAGS += -DMEMORY_FRAGMENT_MAX_SIZE_IN_KB=$(MEMORY_FRAGMENT_MAX_SIZE_IN_KB) -DCC_KEYGEN_MAX_SIZE=$(CC_RSA_MAX_KEY_GENERATION_SIZE_BITS)

#RSA
ifeq ($(RSA_KG_NO_RND),1)
CFLAGS+= -DRSA_KG_NO_RND
SOURCES_$(TARGET_LIBS) += rsa_kg_debug_data.c
endif
SOURCES_$(TARGET_LIBS) += cc_rsa_info.c cc_rsa_build.c
SOURCES_$(TARGET_LIBS) += cc_rsa_oaep.c cc_rsa_schemes.c cc_rsa_schemes_priv_enc.c
SOURCES_$(TARGET_LIBS) += cc_rsa_pkcs_ver15_util.c cc_rsa_pss21_util.c cc_rsa_prim.c cc_rsa_verify.c
SOURCES_$(TARGET_LIBS) += cc_rsa_kg.c cc_rsa_sign.c
SOURCES_$(TARGET_LIBS) += cc_rsa_build_priv.c
SOURCES_$(TARGET_LIBS) += rsa_public.c rsa_private.c rsa_genkey.c

#DH
SOURCES_$(TARGET_LIBS) += cc_dh.c cc_dh_kg.c cc_kdf.c cc_kdf_internal.c

#ECC (Canonic)
SOURCES_$(TARGET_LIBS) += cc_ecpki_info.c
SOURCES_$(TARGET_LIBS) += cc_ecdsa_verify.c cc_ecdsa_sign.c
SOURCES_$(TARGET_LIBS) += cc_ecdh.c cc_ecies.c

SOURCES_$(TARGET_LIBS) += ec_wrst_dsa.c cc_ecpki_domain.c
SOURCES_$(TARGET_LIBS) += cc_ecpki_domain_secp192r1.c
SOURCES_$(TARGET_LIBS) += cc_ecpki_domain_secp192k1.c cc_ecpki_domain_secp224r1.c cc_ecpki_domain_secp224k1.c cc_ecpki_domain_secp256r1.c
SOURCES_$(TARGET_LIBS) += cc_ecpki_domain_secp256k1.c cc_ecpki_domain_secp384r1.c cc_ecpki_domain_secp521r1.c cc_ecpki_domain_bp256r1.c
SOURCES_$(TARGET_LIBS) += bsv_crypto_asym_api.c

#secure boot debug
SOURCES_$(TARGET_LIBS) += bsv_rsa_driver.c
SOURCES_$(TARGET_LIBS) += rsa_pki_pka.c
SOURCES_$(TARGET_LIBS) += rsa_pki_pka_calc_np.c
SOURCES_$(TARGET_LIBS) += common_cert_verify.c
SOURCES_$(TARGET_LIBS) += bootimagesverifier_base_single.c
SOURCES_$(TARGET_LIBS) += bootimagesverifier_swcomp.c
SOURCES_$(TARGET_LIBS) += secureboot_base_func.c
SOURCES_$(TARGET_LIBS) += secureboot_base_swimgverify.c
SOURCES_$(TARGET_LIBS) += cert_parser.c
SOURCES_$(TARGET_LIBS) += secureboot_cert_parser.c
SOURCES_$(TARGET_LIBS) += secureboot_stage.c
SOURCES_$(TARGET_LIBS) += util.c
ifeq ($(CC_CONFIG_SB_X509_CERT_SUPPORTED),1)
SOURCES_$(TARGET_LIBS) += x509_cert_parser.c
SOURCES_$(TARGET_LIBS) += util_asn1_parser.c
SOURCES_$(TARGET_LIBS) += x509_extensions_parser.c
SOURCES_$(TARGET_LIBS) += cc_pal_x509_verify.c
VPATH += $(CODESAFE_SRCDIR)/secure_boot_debug/cert_parser/x509
VPATH += $(CODESAFE_SRCDIR)/secure_boot_debug/secure_boot/x509
VPATH += $(CODESAFE_SRCDIR)/secure_boot_debug/secure_debug/x509
else
VPATH += $(CODESAFE_SRCDIR)/secure_boot_debug/cert_parser/prop
VPATH += $(CODESAFE_SRCDIR)/secure_boot_debug/secure_boot/prop
VPATH += $(CODESAFE_SRCDIR)/secure_boot_debug/secure_debug/prop
endif

#FIPS
ifeq ($(CC_CONFIG_SUPPORT_FIPS), 1)
# Chinese Certification (defined in proj.ext.cfg)
ifeq ($(CC_CONFIG_SUPPORT_CHINESE_CERTIFICATION), 1)
$(error illegal Chinese Certification Flag in Full Conf. - while FIPS is ON: CC_CONFIG_SUPPORT_CHINESE_CERTIFICATION=$(CC_CONFIG_SUPPORT_CHINESE_CERTIFICATION))
endif
CFLAGS_EXTRA += -DCC_SUPPORT_FIPS
SOURCES_$(TARGET_LIBS) += cc_fips.c cc_fips_local.c cc_fips_sym.c cc_pal_cert.c
SOURCES_$(TARGET_LIBS) += cc_fips_ecc.c cc_fips_rsa.c cc_fips_dh.c cc_fips_prng.c
endif

# Chinese Certification (defined in proj.ext.cfg) - MUST stay after the above FIPS condition
ifeq ($(CC_CONFIG_SUPPORT_CHINESE_CERTIFICATION), 1)
CFLAGS_EXTRA += -DCC_SUPPORT_CH_CERT
SOURCES_$(TARGET_LIBS) += cc_chinese_cert.c cc_chinese_cert_local.c cc_chinese_cert_sym.c cc_chinese_cert_asym.c
SOURCES_$(TARGET_LIBS) += cc_pal_cert.c
endif

# random files
SOURCES_$(TARGET_LIBS) += cc_rnd.c
ifeq ($(CC_CONFIG_TRNG_MODE),0)
# FE TRNG
$(info FE TRNG: CC_CONFIG_TRNG_MODE=$(CC_CONFIG_TRNG_MODE))
SOURCES_$(TARGET_LIBS) += llf_rnd_fetrng.c
CFLAGS_EXTRA += -DCC_CONFIG_TRNG_MODE=$(CC_CONFIG_TRNG_MODE)
else ifeq ($(CC_CONFIG_TRNG_MODE),1)
# TRNG90B
$(info TRNG90B: CC_CONFIG_TRNG_MODE=$(CC_CONFIG_TRNG_MODE))
SOURCES_$(TARGET_LIBS) += llf_rnd_trng90b.c
CFLAGS_EXTRA += -DCC_CONFIG_TRNG_MODE=$(CC_CONFIG_TRNG_MODE)
else
$(error illegal TRNG: CC_CONFIG_TRNG_MODE=$(CC_CONFIG_TRNG_MODE))
endif

ifeq ($(CC_CONFIG_BSV_RSA_CERT_3K_BIT_KEY_SUPPORTED),1)
    CFLAGS_EXTRA += -DCC_CONFIG_BSV_RSA_CERT_3K_BIT_KEY_SUPPORTED
endif
ifeq ($(CC_CONFIG_BSV_CERT_WITH_USER_ADDITIONAL_DATA),1)
    CFLAGS += -DCC_CONFIG_BSV_CERT_WITH_USER_ADDITIONAL_DATA
endif

ifeq ($(shell test $(CC_CONFIG_SB_IMG_INFO_LIST_SIZE) -lt 2; echo $$?),0)
$(error CC_CONFIG_SB_IMG_INFO_LIST_SIZE must be greater than 1)
endif

ifeq ($(CC_CONFIG_SB_IMG_INFO_LIST_SIZE),)
$(error CC_CONFIG_SB_IMG_INFO_LIST_SIZE must be defined and greater than 1)
endif

CFLAGS_EXTRA += -DCC_SB_INDIRECT_SRAM_ACCESS
CFLAGS_EXTRA += -DCC_SB_IMG_INFO_LIST_SIZE=$(CC_CONFIG_SB_IMG_INFO_LIST_SIZE)
CFLAGS_EXTRA += -DCC_SB_CERT_VERSION_MAJOR=$(CC_CONFIG_SB_CERT_VERSION_MAJOR)
CFLAGS_EXTRA += -DCC_SB_CERT_VERSION_MINOR=$(CC_CONFIG_SB_CERT_VERSION_MINOR)
CFLAGS_EXTRA += -DCC_SB_IMAGES_WORKSPACE_SIZE_IN_BYTES=$(CC_CONFIG_SB_IMAGES_WORKSPACE_SIZE_IN_BYTES)
CFLAGS_EXTRA += -DCC_CONFIG_SB_IMAGES_OPTIMIZED_MEMORY_CHUNK_SIZE_IN_BYTES=$(CC_CONFIG_SB_IMAGES_OPTIMIZED_MEMORY_CHUNK_SIZE_IN_BYTES)

# Include directories
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/crypto_api/rsa
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/crypto_api/ec_wrst
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/crypto_api/ec_wrst/ecc_domains
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/crypto_api/pki/rsa
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/crypto_api/pki/ec_wrst
INCDIRS_EXTRA += $(HOST_SRCDIR)/utils
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/crypto_api/fips
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/crypto_api/chinese_cert
INCDIRS_EXTRA += $(SHARED_INCDIR)/trng
INCDIRS_EXTRA += $(SHARED_INCDIR)/cc_util
INCDIRS_EXTRA += $(SHARED_INCDIR)/boot
INCDIRS_EXTRA += $(SHARED_INCDIR)/boot/$(PROJ_PRD)
INCDIRS_EXTRA += $(HOST_SRCDIR)/cc7x_sbromlib

CFLAGS_EXTRA += -DCC_SUPPORT_PKA_128_32

# We should flatten the components source trees to avoid long search paths...
VPATH += $(HOST_SRCDIR)/cc7x_teelib/full
VPATH += $(CODESAFE_SRCDIR)/crypto_api/rsa $(CODESAFE_SRCDIR)/crypto_api/kdf
VPATH += $(CODESAFE_SRCDIR)/crypto_api/dh  $(CODESAFE_SRCDIR)/crypto_api/ec_wrst
VPATH += $(CODESAFE_SRCDIR)/crypto_api/ec_wrst/ecc_domains $(HOST_SRCDIR)/utils
VPATH += $(CODESAFE_SRCDIR)/crypto_api/pki/rsa $(CODESAFE_SRCDIR)/crypto_api/pki/ec_wrst
VPATH += $(CODESAFE_SRCDIR)/crypto_api/pki/common
VPATH += $(CODESAFE_SRCDIR)/crypto_api/fips
VPATH += $(CODESAFE_SRCDIR)/crypto_api/chinese_cert
VPATH += $(CODESAFE_SRCDIR)/secure_boot_debug/platform/hal/cc7x
VPATH += $(CODESAFE_SRCDIR)/secure_boot_debug/
VPATH += $(CODESAFE_SRCDIR)/secure_boot_debug/secure_boot
VPATH += $(CODESAFE_SRCDIR)/secure_boot_debug/bsv_rsa_driver/cc7x
VPATH += $(CODESAFE_SRCDIR)/secure_boot_debug/bsv_rsa_driver
VPATH += $(CODESAFE_SRCDIR)/secure_boot_debug/secure_debug
VPATH += $(CODESAFE_SRCDIR)/secure_boot_debug/cert_parser
VPATH += $(CODESAFE_SRCDIR)/secure_boot_debug/platform/pal
VPATH += $(CODESAFE_SRCDIR)/secure_boot_debug/platform/pal/cc7x
VPATH += $(CODESAFE_SRCDIR)/secure_boot_debug/platform/pal/cc7x/$(TEE_OS)
VPATH += $(CODESAFE_SRCDIR)/secure_boot_debug/platform/stage/rt/cc7x
VPATH += $(HOST_SRCDIR)/cc7x_sbromlib

PUBLIC_INCLUDES += $(HOST_SRCDIR)/cc7x_teelib/cc_util_hw_key.h
PUBLIC_INCLUDES += $(SHARED_INCDIR)/cc_util/cc_util_key_derivation.h
PUBLIC_INCLUDES += $(SHARED_INCDIR)/cc_util/cc_util_error.h
PUBLIC_INCLUDES += $(SHARED_INCDIR)/cc_util/cc_util_defs.h
PUBLIC_INCLUDES += $(SHARED_INCDIR)/cc_util/cc_util_key_derivation_defs.h
PUBLIC_INCLUDES += $(SHARED_INCDIR)/cc_util/cc_util_backup_restore.h
PUBLIC_INCLUDES += $(SHARED_INCDIR)/cc_util/cc_util_rpmb.h
PUBLIC_INCLUDES += $(SHARED_INCDIR)/cc_util/cc_util_stimer.h
PUBLIC_INCLUDES += $(SHARED_INCDIR)/crypto_api/cc_aes_defs.h
PUBLIC_INCLUDES += $(HOST_SRCDIR)/cc7x_teelib/full/cc_lib.h
PUBLIC_INCLUDES += $(HOST_SRCDIR)/cc7x_teelib/cc_asset_provisioning.h


ifeq ($(CC_CONFIG_BSV_RSA_CERT_3K_BIT_KEY_SUPPORTED),1)
PUBLIC_INCLUDES += $(CODESAFE_SRCDIR)/secure_boot_debug/secure_boot/secureboot_defs.h
PUBLIC_INCLUDES += $(CODESAFE_SRCDIR)/secure_boot_debug/cert_parser/bootimagesverifier_def.h
PUBLIC_INCLUDES += cc_sbrt_api.h
ifeq ($(CC_CONFIG_SB_X509_CERT_SUPPORTED),1)
PUBLIC_INCLUDES += $(CODESAFE_SRCDIR)/secure_boot_debug/platform/pal/cc_pal_x509_defs.h
PUBLIC_INCLUDES += $(SHARED_INCDIR)/boot/cc_crypto_x509_common_defs.h
PUBLIC_INCLUDES += $(SHARED_INCDIR)/boot/cc_crypto_x509_defs.h
endif
endif


