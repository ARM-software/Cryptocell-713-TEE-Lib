include ./proj_integration_tests.cfg

NO_PAL = 1

include $(HOST_PROJ_ROOT)/Makefile.test_suite
include $(HOST_PROJ_ROOT)/../proj.ext.cfg
include $(HOST_PROJ_ROOT)/global_proj.defs

TEST_DIR = $(CURDIR)/$(INTEG_TESTS)
INTEG_TESTS_NAME = $(shell basename $(TEST_DIR))
TEST_MAKEFILE = $(TEST_DIR)/Makefile
TEST_AL_PATH = $(CURDIR)/../TestAL

include $(TEST_MAKEFILE)

# get all modules that should be compiled
#INTEG_TESTS_CFG variable is defined in host/src/config proj file.
TEST_PUBLIC = $(shell sed '/\#.*/d' $(HOST_PROJ_ROOT)/../$(INTEG_TESTS_CFG))
TEST_PUBLIC_SRC = $(patsubst %, te_%.c, $(TEST_PUBLIC))

TARGET_EXES = $(INTEG_TESTS_NAME)_integration_tests

DEPLIBS = test_engine
DEPLIBS += $(DEPLIBS_EXTRA)
DEPLIBS += tests_hal_lite
DEPLIBS += tests_pal_lite

LIBDIRS += $(HOST_PROJ_ROOT)/lib

# Unit test dependencies
SOURCES_$(TARGET_EXES) = integration_test.c
SOURCES_$(TARGET_EXES) += wrappers.c
SOURCES_$(TARGET_EXES) += menu_engine.c
SOURCES_$(TARGET_EXES) += $(TEST_PUBLIC_SRC)
SOURCES_$(TARGET_EXES) += $(PROJ_SOURCES)
SOURCES_$(TARGET_EXES) += $(FLAVOUR_SOURCES)
SOURCES_$(TARGET_EXES) += $(TESTS_HELPER_SOURCES)

TEST_ALL = $(sort $(TEST_PUBLIC))

CFLAGS += -D'MODULE_NAME="$(INTEG_TESTS)"'

# defines the number of iterations to preform to achieve higher statistics accuracy
ifneq (,$(ITER))
CFLAGS += -D'TE_NUM_OF_ITER=$(ITER)'
else
CFLAGS += -D'TE_NUM_OF_ITER=1'
endif

# start library init struct declaration
# These two flags define the init function of each test library
# These values are planted in main.c
comma:= ,
space:=
LIB_INIT_VALUES_TEMPLATE =  {"FUNC"$(comma)TE_init_FUNC_test}$(comma)$(space)

LIB_INIT_VALUES = $(foreach tests, $(TEST_ALL), $(subst FUNC,$(strip $(patsubst te_%.c, %, $(tests))),$(LIB_INIT_VALUES_TEMPLATE)) )
CFLAGS		+=-D'LIB_INIT_FUNCS=$(LIB_INIT_VALUES)'

LIB_INIT_EXERN_VALUES = $(patsubst %, extern int TE_init_%_test(void); , $(TEST_ALL))
CFLAGS		+=-D'LIB_INIT_EXERNS=$(LIB_INIT_EXERN_VALUES)'
# end  library init struct declaration

INCDIRS_EXTRA += $(PROJ_INCLUDE)
INCDIRS_EXTRA += $(TEST_AL_PATH)/hal/include
INCDIRS_EXTRA += $(TEST_AL_PATH)/pal/include
INCDIRS_EXTRA += $(TEST_AL_PATH)/include
INCDIRS_EXTRA += $(HOST_PROJ_ROOT)/src/tests/test_engine
INCDIRS_EXTRA += $(INCDIRS_FLAVOUR)
INCDIRS_EXTRA += $(SHARED_INCDIR)/pal
INCDIRS_EXTRA += $(SHARED_INCDIR)/pal/$(TEE_OS)
INCDIRS_EXTRA += $(SHARED_DIR)/hw
INCDIRS_EXTRA += $(HOST_PROJ_ROOT)/src/tests/tests_helper/menu_engine
INCDIRS_EXTRA += $(TEST_DIR)

#$(info SOURCES_$(TARGET_EXES) $(SOURCES_$(TARGET_EXES)))
#$(info TEST_PUBLIC $(TEST_PUBLIC))
#$(info LIB_INIT_VALUES $(LIB_INIT_VALUES))
#$(info LIB_INIT_EXERN_VALUES $(LIB_INIT_EXERN_VALUES))
#$(info TEST_ALL $(TEST_ALL))
#$(info INCDIRS_FLAVOUR $(INCDIRS_FLAVOUR))
#$(info TEST_MAKEFILE $(TEST_MAKEFILE))
#$(info VPATH $(VPATH))

VPATH = $(TEST_DIR)
VPATH += $(PROJ_VPATH)
VPATH += $(HOST_PROJ_ROOT)/src/tests/tests_helper/menu_engine

PUBLIC_SCRIPTS += integration_test.sh
PUBLIC_SCRIPTS += $(HOST_PROJ_ROOT)/src/tests/tester_help_func.sh