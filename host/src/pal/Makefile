SUB_DIRS = $(TEE_OS)


all: $(foreach sub_dir,$(SUB_DIRS),do_$(sub_dir))

clean: $(foreach sub_dir,$(SUB_DIRS),clean_$(sub_dir))

clean_%:
	@+$(MAKE) -C $* clean

do_%:
	@+$(MAKE) -C $*

.PHONY: all clean clean_% do_%

