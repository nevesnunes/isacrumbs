SRCS := $(shell find "$(RUNNER_DIR)/../src" "$(RUNNER_DIR)/../test" -type f -iname '*.java')

$(GHIDRA_SCRIPTS_BUILD_DIR)/build.timestamp: $(SRCS)
	javac \
		-classpath "$(GHIDRA_SCRIPTS_CLASSPATH)" \
		-d "$(GHIDRA_SCRIPTS_BUILD_DIR)" \
		-g \
		-source 21 \
		-target 21 \
		$^
	touch $@
