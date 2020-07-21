# Utils top level Makefile

UTILS_ROOT = $(shell pwd)/..
OPENSSL_ROOT_DIR = $(UTILS_ROOT)/src/openssl

all:

clean_openssl:
	@echo "cleaning openssl"
	@cd $(OPENSSL_ROOT_DIR) && $(MAKE) clean

clean_%:
	@echo "cleaning" $*
	@$(MAKE) -C $* clean

distclean: clean clrconfig
	rm -rf $(UTILS_ROOT)/bin
	rm -rf $(UTILS_ROOT)/lib
	rm -rf $(UTILS_ROOT)/include
	rm -rf $(UTILS_ROOT)/doc

# Generate dependency on existence only (i.e., don't care if newer).
# To be used primarily for directories creation
DEPENDENCY_ON_EXISTENCE_OF = $(filter-out $(wildcard $(1)), $(1))


################################################
### Handle project configuration definitions ###
################################################

PROJ_CFG_FNAME = proj.cfg
PROJ_EXT_CFG_FNAME = proj.ext.cfg
PROJ_CFG_PATH = $(PROJ_CFG_FNAME)
PROJ_EXT_CFG_PATH = $(UTILS_ROOT)/../$(PROJ_EXT_CFG_FNAME)
PROJ_CONFIGS_DIR = configs


############ Special rules for project configuration selection ##############
ifneq ($(wildcard $(PROJ_CFG_PATH)),$(PROJ_CFG_PATH)) # No proj.cfg linked

all: # default in case there is no proj.cfg and setconfig_ was not used
	$(info Invoke 'make setconfig_<config. name>' to select project configuration )
	$(error 'proj.cfg' not found)

setconfig_%: $(PROJ_CONFIGS_DIR)/proj-%.cfg
	@$(info [CFG] $(PROJ_CONFIGS_DIR)/proj-$*.cfg --> proj.cfg)
	@ln -s $(PROJ_CONFIGS_DIR)/proj-$*.cfg $(PROJ_CFG_FNAME)

$(PROJ_CONFIGS_DIR)/proj-%.cfg:
	@$(error Unknown project configuration. $@ does not exist.)

clrconfig:
	$(info [CFG-CLN] No active configuration )

.PHONY: all setconfig_% clrconfig

else
### proj.cfg exists. Include it to get project cofiguration defintions ###
# The includes order is important here:
# External configurations in proj.ext.cfg may be overrided by those in host proj.cfg
include $(PROJ_EXT_CFG_PATH)
include $(PROJ_CFG_PATH)


ifeq ($(CONFIG_SB_SUPPORT_IOT), 1)
    TARGETS = secure_boot_debug_utils cc3x_asset_prov cc3x_asset_prov_rt cc3x_production
else
    TARGETS = secure_boot_debug_utils oem_asset_utils cc7x_production tests cc7x_asset_prov
endif


$(info PROJ_NAME=$(PROJ_NAME))
# Export all definition from proj.cfg to dispatched makefiles
export

all: $(PROJ_TARGETS)

$(PROJ_TARGETS):
	@$(info building $@)
	@$(MAKE) $(CFLAGS) -C $@

openssl:
	@echo "building openssl as shared object"
	@unset CROSS_COMPILE && cd $(OPENSSL_ROOT_DIR) && $(MAKE) clean && ./Configure shared linux-x86_64 && $(MAKE) depend && $(MAKE) build_libs

clean: $(foreach target,$(PROJ_TARGETS),clean_$(target))


# setconfig_/clrconfig are available only if $(PROJ_CONFIGS_DIR) exists
# (i.e., eliminated on release trees)
ifeq ($(wildcard $(PROJ_CONFIGS_DIR)),$(PROJ_CONFIGS_DIR))
# Configuration rules
setconfig_%:
	$(if $(filter $(PROJ_CONFIGS_DIR)/proj-$*.cfg,$(shell readlink $(PROJ_CFG_PATH))),$(info $* configuration is already set.),$(error Before changing configuration invoke 'make clrconfig'))

clrconfig:
	@echo [CFG-CLN] X $(shell readlink $(PROJ_CFG_PATH))
	@rm -f $(PROJ_CFG_PATH)
endif

endif

# Provide lsconfig to list available configurations
configs_list = $(foreach cfg_file,$(wildcard $(PROJ_CONFIGS_DIR)/proj-*.cfg),$(patsubst $(PROJ_CONFIGS_DIR)/proj-%.cfg,%,$(cfg_file)))
lsconfig:
	@$(info Available project configurations:)
	@$(foreach cfg_file,$(configs_list),$(info $(cfg_file)))

.PHONY: all setconfig_% clrconfig lsconfig clean distclean all clean_% $(TARGETS) openssl clean_openssl
