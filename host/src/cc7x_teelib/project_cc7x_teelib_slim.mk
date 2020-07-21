# Project Makefile for cc713tee slim product

# TEE sources
SOURCES_$(TARGET_LIBS) += cc_lib.c

# random files
ifeq ($(CC_CONFIG_TRNG_MODE),0)
# FE TRNG
$(info FE TRNG: CC_CONFIG_TRNG_MODE=$(CC_CONFIG_TRNG_MODE))
SOURCES_$(TARGET_LIBS) += cc_trng_fe.c llf_rnd_fetrng.c
CFLAGS_EXTRA += -DCC_CONFIG_TRNG_MODE=$(CC_CONFIG_TRNG_MODE)
else
$(error illegal TRNG: CC_CONFIG_TRNG_MODE=$(CC_CONFIG_TRNG_MODE))
endif

# FIPS (defined in proj.ext.cfg)
ifeq ($(CC_CONFIG_SUPPORT_FIPS), 1)
$(error illegal FIPS Flag in SLIM Conf.: CC_CONFIG_SUPPORT_FIPS=$(CC_CONFIG_SUPPORT_FIPS))
endif

# Chinese Certification (defined in proj.ext.cfg)
ifeq ($(CC_CONFIG_SUPPORT_CHINESE_CERTIFICATION), 1)
CFLAGS_EXTRA += -DCC_SUPPORT_CH_CERT
SOURCES_$(TARGET_LIBS) += cc_chinese_cert.c
SOURCES_$(TARGET_LIBS) += cc_chinese_cert_local.c
SOURCES_$(TARGET_LIBS) += cc_chinese_cert_sym.c
SOURCES_$(TARGET_LIBS) += cc_chinese_cert_asym.c
SOURCES_$(TARGET_LIBS) += cc_pal_cert.c
endif

# Include directories
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/crypto_api/chinese_cert

VPATH += $(CODESAFE_SRCDIR)/crypto_api/chinese_cert

PUBLIC_INCLUDES += $(HOST_SRCDIR)/cc7x_teelib/slim/cc_lib.h

VPATH += $(HOST_SRCDIR)/cc7x_teelib/slim

CFLAGS_EXTRA += -DMEMORY_FRAGMENT_MAX_SIZE_IN_KB=$(MEMORY_FRAGMENT_MAX_SIZE_IN_KB) -DCC_SUPPORT_PKA_128_32


