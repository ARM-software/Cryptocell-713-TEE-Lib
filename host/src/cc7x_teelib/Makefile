
HOST_PROJ_ROOT ?= $(shell pwd)/../..
include $(HOST_PROJ_ROOT)/Makefile.defs

TARGET_LIBS = cc_713tee

include project_cc7x_teelib.mk

ifeq ($(CC_CONFIG_SUPPORT_FULL_PROJECT), 1)
	include project_cc7x_teelib_full.mk
else
	include project_cc7x_teelib_slim.mk
endif

include $(HOST_PROJ_ROOT)/Makefile.rules

