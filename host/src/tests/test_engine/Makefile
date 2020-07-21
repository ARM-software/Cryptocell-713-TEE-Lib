HOST_PROJ_ROOT ?= $(shell pwd)/../../..
include $(HOST_PROJ_ROOT)/Makefile.defs

TARGET_LIBS = test_engine

SOURCES_test_engine += test_engine.c
SOURCES_test_engine += test_engine_profiler.c

INCDIRS_EXTRA = ./include
INCDIRS_EXTRA += $(SHARED_DIR)/hw/include

ifeq ($(DEBUG),1)
CFLAGS += -DDEBUG -O0 -g
endif

# defines the verbosity level of the logging utility
ifneq (,$(VERBOSE))
CFLAGS += -DVERBOSE=_$(VERBOSE)
endif

include $(HOST_PROJ_ROOT)/Makefile.rules
