# Makefile for cc_pal_linux_driver - driver for performing DMA opeartions.

MODULE_NAME = cc_linux_drv

obj-$(CONFIG_CRYPTO_PAL_LINUX_DRV) := $(MODULE_NAME).o
$(MODULE_NAME)-objs := cc_pal_linux_drv.o

ifeq ($(DEBUG),1) # Remove optimization flags
EXTRA_CFLAGS += -DCC_DEBUG
define remove_o2
	CFLAGS_REMOVE_$(1) = -O2
endef
$(foreach obj,$(MODULE_NAME)-objs,$(eval $(call remove_o2,$(obj))))
EXTRA_CFLAGS += -DDEBUG -O1
endif


EXTRA_CFLAGS += -Wall

$(info $(if $(DEBUG),DEBUG=$(DEBUG)))
