
# Makefile for building sbu_crypto library
SH_LIB_NAME = libsbu_crypto.so

LIB_SRC_O = main.o common_rsa_keypair.o  common_crypto_x509.o
LIB_SRC_O += common_crypto_sym.o common_crypto_asym.o common_util_files.o common_rsa_keypair_util.o

UTILS_ROOT := $(shell pwd)/../../..
SHARED_DIR := $(UTILS_ROOT)/../shared
HOST_DIR := $(UTILS_ROOT)/../host
CODESAFE_DIR := $(UTILS_ROOT)/../codesafe
UTILS_COMMON_PATH := $(UTILS_ROOT)/src/common

include $(UTILS_ROOT)/src/Makefile.openssl

UTILS_LIB_PATH = $(UTILS_ROOT)/lib
UTILS_INC_PATH = $(UTILS_ROOT)/include
UTILS_INC_PATH += $(UTILS_COMMON_PATH)
UTILS_INC_PATH += $(SHARED_DIR)/include
UTILS_INC_PATH += $(SHARED_DIR)/include/boot
UTILS_INC_PATH += $(SHARED_DIR)/include/boot/$(PROJ_PRD)
UTILS_INC_PATH += $(SHARED_DIR)/include/proj/$(PROJ_PRD)
UTILS_INC_PATH += $(SHARED_DIR)/include/pal/$(TEE_OS)
UTILS_INC_PATH += $(SHARED_DIR)/include/pal
UTILS_INC_PATH += $(SHARED_DIR)/hw/include
UTILS_INC_PATH += $(CODESAFE_DIR)/src/secure_boot_debug/
UTILS_INC_PATH += $(CODESAFE_DIR)/src/secure_boot_debug/secure_debug
UTILS_INC_PATH += $(CODESAFE_DIR)/src/secure_boot_debug/secure_boot
UTILS_INC_PATH += $(CODESAFE_DIR)/src/secure_boot_debug/platform/hal
UTILS_INC_PATH += $(CODESAFE_DIR)/src/secure_boot_debug/bsv_rsa_driver
UTILS_INC_PATH += $(CODESAFE_DIR)/src/secure_boot_debug/cert_parser
UTILS_INC_PATH += $(CODESAFE_DIR)/src/secure_boot_debug/cert_parser/x509
UTILS_INC_PATH += $(SHARED_DIR)/include/pal
UTILS_INC_PATH += $(SHARED_DIR)/include/pal/$(TEE_OS)
UTILS_INC_PATH += $(OPENSSL_INC_DIR)

ifeq ($(PROJ_PRD),cc3x)
UTILS_INC_PATH += $(HOST_SRCDIR)/$(PROJ_PRD)_sbromlib
UTILS_INC_PATH += $(CODESAFE_SRCDIR)/secure_boot_debug/bsv_rsa_driver/$(PROJ_PRD)
UTILS_INC_PATH += $(CODESAFE_DIR)/src/secure_boot_debug/platform/pal/$(PROJ_PRD)
UTILS_INC_PATH += $(CODESAFE_DIR)/src/secure_boot_debug/platform/stage/boot/$(PROJ_PRD)
else
UTILS_INC_PATH += $(HOST_SRCDIR)/cc7x_sbromlib
UTILS_INC_PATH += $(CODESAFE_SRCDIR)/secure_boot_debug/bsv_rsa_driver/cc7x
UTILS_INC_PATH += $(CODESAFE_DIR)/src/secure_boot_debug/platform/pal/cc7x
UTILS_INC_PATH += $(CODESAFE_DIR)/src/secure_boot_debug/platform/stage/boot/cc7x
endif

CFLAGS += -fPIC $(foreach incdir,$(UTILS_INC_PATH),-I$(incdir)) -c
CFLAGS += -DCC_CONFIG_BSV_RSA_CERT_3K_BIT_KEY_SUPPORTED
ifeq ($(CC_CONFIG_BSV_CERT_WITH_USER_ADDITIONAL_DATA),1)
    CFLAGS += -DCC_CONFIG_BSV_CERT_WITH_USER_ADDITIONAL_DATA
endif

all: $(SH_LIB_NAME)

# Compile and link the sbu_crypto library with hard-coded library run path to utils/lib
# (to assure the private version of openssl libraries are used)
$(SH_LIB_NAME): $(LIB_SRC_O)
	@gcc -shared -o $(SH_LIB_NAME) $(LIB_SRC_O) -Wl,-rpath,$(UTILS_LIB_PATH),-rpath,$(OPENSSL_LIB_DIR) -L $(OPENSSL_LIB_DIR) -lcrypto -lssl

vpath %.c $(UTILS_ROOT)/src/common

%.o: %.c
	gcc $(CFLAGS) $<

clean:
	rm -f $(SH_LIB_NAME) $(LIB_SRC_O)

.PHONY: clean all

