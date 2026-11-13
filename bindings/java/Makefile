# Builds the JNI shim and the Java classes for the Java bindings.
#
#   make          # classes + libanubis_jni.so
#   make test     # compiles and runs test/AnubisTest.java
#   make clean
#
# Needs a JDK and the library built at the repository root (`make`).
REPO      ?= ../..
JAVA_HOME ?= $(shell dirname $$(dirname $$(readlink -f $$(command -v javac))))
BUILD     := build
CLASSES   := $(BUILD)/classes
NATIVE    := $(BUILD)/native
SRC       := src/main/java/io/github/celikfana/anubis/Anubis.java
CSRC      := src/main/c/anubis_jni.c
RPATH     := $(abspath $(REPO))

all: $(BUILD)/libanubis_jni.so $(CLASSES)/io/github/celikfana/anubis/Anubis.class \
     $(BUILD)/test/AnubisTest.class

$(CLASSES)/io/github/celikfana/anubis/Anubis.class: $(SRC)
	@mkdir -p $(CLASSES) $(NATIVE)
	javac -h $(NATIVE) -d $(CLASSES) $(SRC)

$(BUILD)/libanubis_jni.so: $(CSRC) $(CLASSES)/io/github/celikfana/anubis/Anubis.class
	$(CC) -shared -fPIC -I$(NATIVE) -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux \
	      -I$(REPO)/include $(CSRC) -o $@ -L$(RPATH) -lanubis_solver -Wl,-rpath,$(RPATH)

$(BUILD)/test/AnubisTest.class: test/AnubisTest.java $(CLASSES)/io/github/celikfana/anubis/Anubis.class
	@mkdir -p $(BUILD)/test
	javac -cp $(CLASSES) -d $(BUILD)/test test/AnubisTest.java

test: all
	java -Djava.library.path=$(BUILD) -cp $(CLASSES):$(BUILD)/test AnubisTest

clean:
	rm -rf $(BUILD)

.PHONY: all test clean
