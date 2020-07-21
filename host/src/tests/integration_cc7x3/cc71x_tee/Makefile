INCDIRS_FLAVOUR += $(HOST_PROJ_ROOT)/../shared/include/crypto_api
INCDIRS_FLAVOUR += $(HOST_PROJ_ROOT)/../shared/include/crypto_api/$(PROJ_PRD)
INCDIRS_FLAVOUR += $(HOST_PROJ_ROOT)/../shared/include/cc_util
INCDIRS_FLAVOUR += $(HOST_PROJ_ROOT)/../shared/include/boot/cc7x_tee
DEPLIBS_EXTRA += cc_713tee

# sbrt only for full
ifeq (,$(findstring slim,$(PROJ_NAME)))
ifeq ($(CC_CONFIG_SB_X509_CERT_SUPPORTED),1)
CERT_FLAVOUR = x509
else
CERT_FLAVOUR = prop
endif

FLAVOUR_SOURCES += te_secure_boot_data_$(CERT_FLAVOUR)_$(TEST_BOARD).c
FLAVOUR_SOURCES += te_flash.c

CFLAGS_EXTRA += -DCC_SB_IMAGES_WORKSPACE_SIZE_IN_BYTES=$(CC_CONFIG_SB_IMAGES_WORKSPACE_SIZE_IN_BYTES)
endif
