# Project Makefile for cc713tee for both slim and full.

# TEE sources for both slim and full

# TEE sources
SOURCES_$(TARGET_LIBS) += cc_util_pm.c cc_pm_data.c

# HAL, PAL
SOURCES_$(TARGET_LIBS) += cc_hal.c completion_plat.c cc_pal.c cc_pal_dma.c
SOURCES_$(TARGET_LIBS) += cc_pal_memmap.c mlli_plat.c cc_context_relocation.c cc_pal_mutex.c
SOURCES_$(TARGET_LIBS) += cc_pal_mem.c cc_pal_abort_plat.c cc_pal_interrupt_ctrl.c
SOURCES_$(TARGET_LIBS) += cc_pal_barrier.c cc_pal_pm.c
SOURCES_$(TARGET_LIBS) += cc_hal_axi_ctrl.c

SOURCES_$(TARGET_LIBS) += hw_queue.c cc_plat.c hash.c

ifeq ($(DEBUG),1)
SOURCES_$(TARGET_LIBS) += cc_pal_log.c
endif

ifeq ($(TEE_OS),$(filter $(TEE_OS),cc_linux linux64))
SOURCES_$(TARGET_LIBS) += bget.c
endif

ifeq ($(LIB_PERF),1)
VPATH += $(HOST_SRCDIR)/pal
CFLAGS += -DLIB_PERF
SOURCES_$(TARGET_LIBS) += cc_pal_perf_plat.c
endif

CFLAGS += -DCC_HW_VERSION=$(CC_HW_VERSION)

PUBLIC_INCLUDES += $(HOST_SRCDIR)/hal/$(PROJ_PRD)/cc_hal_defs.h
PUBLIC_INCLUDES += $(HOST_SRCDIR)/cc7x_teelib/cc_cpp.h

# Symmetric HW driver sources
SOURCES_$(TARGET_LIBS) +=  sym_adaptor_driver.c sym_adaptor_util.c mlli.c sym_crypto_driver.c bypass.c

# Crypto alg
#SM2
SOURCES_$(TARGET_LIBS) +=  cc_ecpki_domain_sm2.c
SOURCES_$(TARGET_LIBS) +=  cc_sm2_sign.c
SOURCES_$(TARGET_LIBS) +=  cc_sm2_verify.c
SOURCES_$(TARGET_LIBS) +=  cc_sm2_ke.c
SOURCES_$(TARGET_LIBS) +=  cc_sm2_aux.c
SOURCES_$(TARGET_LIBS) +=  cc_sm2_int.c
#pka needed for SM2
SOURCES_$(TARGET_LIBS) +=  pka.c pka_ec_wrst.c
SOURCES_$(TARGET_LIBS) +=  cc_common_conv_endian.c
SOURCES_$(TARGET_LIBS) +=  pka_ec_wrst_dsa_verify.c
SOURCES_$(TARGET_LIBS) +=  cc_common_math.c
SOURCES_$(TARGET_LIBS) +=  pki.c
SOURCES_$(TARGET_LIBS) +=  pki_modular_arithmetic.c
#ec needed for SM2
SOURCES_$(TARGET_LIBS) +=  cc_ecpki_build_priv.c
SOURCES_$(TARGET_LIBS) +=  cc_ecpki_build_publ.c
SOURCES_$(TARGET_LIBS) +=  cc_ecpki_kg.c
SOURCES_$(TARGET_LIBS) +=  ec_wrst.c
SOURCES_$(TARGET_LIBS) +=  ec_wrst_genkey.c
#chineese ciphers
SOURCES_$(TARGET_LIBS) +=  cc_sm3.c cc_sm4.c cipher.c


ifeq ($(CC_CONFIG_SUPPORT_ECC_SCA_SW_PROTECT), 1)
    CFLAGS += -DCC_SUPPORT_SCA_SW_PROTECT
    SOURCES_$(TARGET_LIBS) += pka_ec_wrst_smul_scap.c
else
    SOURCES_$(TARGET_LIBS) += pka_ec_wrst_smul_no_scap.c
endif

# random files
SOURCES_$(TARGET_LIBS) += llf_rnd.c
SOURCES_$(TARGET_LIBS) += cc_rng_plat.c
SOURCES_$(TARGET_LIBS) += cc_pal_trng.c
SOURCES_$(TARGET_LIBS) += cc_rnd_common.c

# cpp files
SOURCES_$(TARGET_LIBS) += cc_cpp.c

#interrupt
SOURCES_$(TARGET_LIBS) += cc_interrupt.c

# Include directories
INCDIRS_EXTRA += $(SHARED_INCDIR)/crypto_api
INCDIRS_EXTRA += $(SHARED_INCDIR)/crypto_api/$(PROJ_PRD)
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/crypto_api/cc7x_sym/driver
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/crypto_api/cc7x_sym/adaptor
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/crypto_api/cc7x_sym/api
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/crypto_api/driver
INCDIRS_EXTRA += $(SHARED_INCDIR)
INCDIRS_EXTRA += $(SHARED_INCDIR)/pal
INCDIRS_EXTRA += $(SHARED_INCDIR)/pal/$(TEE_OS)
INCDIRS_EXTRA += $(HOST_SRCDIR)/hal
INCDIRS_EXTRA += $(HOST_SRCDIR)/hal/$(PROJ_PRD)
INCDIRS_EXTRA += $(HOST_SRCDIR)/pal
INCDIRS_EXTRA += $(HOST_SRCDIR)/pal/$(TEE_OS)
INCDIRS_EXTRA += $(SHARED_DIR)/$(CC_TEE_HW_INC_DIR)
INCDIRS_EXTRA += $(HOST_SRCDIR)/cc7x_teelib
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/crypto_api/pki/common
INCDIRS_EXTRA += $(SHARED_INCDIR)/proj/$(PROJ_PRD)
INCDIRS_EXTRA += $(SHARED_INCDIR)/cc_util
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/crypto_api/rnd_dma
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/crypto_api/rnd_dma/local
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/crypto_api/common
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/crypto_api/ec_wrst
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/crypto_api/ec_wrst/ecc_domains
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/crypto_api/pki/ec_wrst
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/crypto_api/sm2/internal

ifeq ($(TEE_OS),linux64)
INCDIRS_EXTRA += $(HOST_SRCDIR)/pal/$(TEE_OS)/driver
endif

ifeq ($(CROSS_COMPILE),arm-dsm-)
CFLAGS += -DARM_DSM
endif

CFLAGS_EXTRA += -DFW_VER_MAJOR=$(FW_VER_MAJOR) -DFW_VER_MINOR=$(FW_VER_MINOR) -DFW_VER_PATCH=$(FW_VER_PATCH)
CFLAGS_EXTRA += -DCC_TEE -DDX_SEC_TIMER_TEST_ENV
CFLAGS_EXTRA += -DMEMORY_FRAGMENT_MAX_SIZE_IN_KB=$(MEMORY_FRAGMENT_MAX_SIZE_IN_KB) -DCC_SUPPORT_SHA=512
# List of drivers to enable/disable
DRIVERS = AES DES HASH HMAC AEAD ECC RSA BYPASS KDF_DH C2 SM3 SM4 SM2
CFLAGS_EXTRA += $(foreach driver,$(DRIVERS),$(if $(FW_ENABLE_$(driver)_DRIVER),-DENABLE_$(driver)_DRIVER=$(FW_ENABLE_$(driver)_DRIVER)))
ifeq ($(CC_CONFIG_HASH_SHA_512_SUPPORTED),1)
	CFLAGS_EXTRA += -DCC_CONFIG_HASH_SHA_512_SUPPORTED -DCC_CTX_SIZE_LOG2=8
endif

ifeq ($(CC_CONFIG_HASH_MD5_SUPPORTED),1)
	CFLAGS_EXTRA += -DCC_CONFIG_HASH_MD5_SUPPORTED
endif

ifeq ($(CC_CONFIG_TEST_48BIT_DMA_ADDR),1)
CFLAGS_EXTRA += -DCC_DMA_48BIT_SIM
endif

# define flag for non supported RND_DMA
ifeq ($(CC_CONFIG_RND_TEST_MODE),CC_RND_TEST_MODE)
CFLAGS_EXTRA += -DCC_RND_TEST_MODE
endif

# We should flatten the components source trees to avoid long search paths...
VPATH += $(HOST_SRCDIR)/hal/$(PROJ_PRD)
VPATH += $(CODESAFE_SRCDIR)/crypto_api/cc7x_sym/driver
VPATH += $(CODESAFE_SRCDIR)/crypto_api/cc7x_sym/adaptor
VPATH += $(CODESAFE_SRCDIR)/crypto_api/cc7x_sym/api
VPATH += $(CODESAFE_SRCDIR)/crypto_api/common
VPATH += $(CODESAFE_SRCDIR)/crypto_api/pki/common
VPATH += $(CODESAFE_SRCDIR)/crypto_api/pki/ec_wrst
VPATH += $(HOST_SRCDIR)/pal/$(TEE_OS)
VPATH += $(SHARED_SRCDIR)/proj/$(PROJ_PRD)
VPATH += $(HOST_SRCDIR)/pal
VPATH += $(CODESAFE_SRCDIR)/crypto_api/rnd_dma
VPATH += $(HOST_SRCDIR)/cc7x_teelib
VPATH += $(CODESAFE_SRCDIR)/crypto_api/sm2/dsa
VPATH += $(CODESAFE_SRCDIR)/crypto_api/sm2/ke
VPATH += $(CODESAFE_SRCDIR)/crypto_api/sm2/auxiliary
VPATH += $(CODESAFE_SRCDIR)/crypto_api/ec_wrst/ecc_domains
VPATH += $(CODESAFE_SRCDIR)/crypto_api/ec_wrst
VPATH += $(CODESAFE_SRCDIR)/crypto_api/sm2/internal
