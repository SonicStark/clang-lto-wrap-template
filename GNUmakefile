#
# american fuzzy lop++ - makefile
# -----------------------------
#
# Originally written by Michal Zalewski
#
# Copyright 2013, 2014, 2015, 2016, 2017 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#   https://www.apache.org/licenses/LICENSE-2.0
#

# For Heiko:
#TEST_MMAP=1
# the hash character is treated differently in different make versions
# so use a variable for '#'
HASH=\#

PREFIX     ?= /usr/local
BIN_PATH    = $(PREFIX)/bin
HELPER_PATH = $(PREFIX)/lib/afl
DOC_PATH    = $(PREFIX)/share/doc/afl
MISC_PATH   = $(PREFIX)/share/afl
MAN_PATH    = $(PREFIX)/share/man/man8

PROGNAME    = afl
VERSION     = $(shell grep '^$(HASH)define VERSION ' ../config.h | cut -d '"' -f2)

ASAN_OPTIONS=detect_leaks=0

SYS = $(shell uname -s)
ARCH = $(shell uname -m)

$(info [*] Compiling AFL++ for OS $(SYS) on ARCH $(ARCH))

ifdef NO_SPLICING
  override CFLAGS_OPT += -DNO_SPLICING
endif

ifdef NO_UTF
  override CFLAGS_OPT += -DFANCY_BOXES_NO_UTF
endif

ifdef ASAN_BUILD
  $(info Compiling ASAN version of binaries)
  override CFLAGS += $(ASAN_CFLAGS)
  override LDFLAGS += $(ASAN_LDFLAGS)
endif
ifdef UBSAN_BUILD
  $(info Compiling UBSAN version of binaries)
  override CFLAGS += -fsanitize=undefined -fno-omit-frame-pointer
  override LDFLAGS += -fsanitize=undefined
endif
ifdef MSAN_BUILD
  $(info Compiling MSAN version of binaries)
  CC := clang
  override CFLAGS += -fsanitize=memory -fno-omit-frame-pointer
  override LDFLAGS += -fsanitize=memory
endif

ifdef CODE_COVERAGE
  override CFLAGS += -D__AFL_CODE_COVERAGE=1
endif

ifeq "$(findstring android, $(shell $(CC) --version 2>/dev/null))" ""
ifeq "$(shell echo 'int main() {return 0; }' | $(CC) $(CFLAGS) -Werror -x c - -flto=full -o .test 2>/dev/null && echo 1 || echo 0 ; rm -f .test )" "1"
	CFLAGS_FLTO ?= -flto=full
else
 ifeq "$(shell echo 'int main() {return 0; }' | $(CC) $(CFLAGS) -Werror -x c - -flto=thin -o .test 2>/dev/null && echo 1 || echo 0 ; rm -f .test )" "1"
	CFLAGS_FLTO ?= -flto=thin
 else
  ifeq "$(shell echo 'int main() {return 0; }' | $(CC) $(CFLAGS) -Werror -x c - -flto -o .test 2>/dev/null && echo 1 || echo 0 ; rm -f .test )" "1"
	CFLAGS_FLTO ?= -flto
  endif
 endif
endif
endif

ifdef PERFORMANCE
  SPECIAL_PERFORMANCE := -D_AFL_SPECIAL_PERFORMANCE
  ifeq "$(SYS)" "Linux"
    ifeq "$(shell grep avx2 /proc/cpuinfo)" ""
    else
  	SPECIAL_PERFORMANCE += -mavx2 -D_HAVE_AVX2
    endif
  endif
  ifeq "$(shell echo 'int main() {return 0; }' | $(CC) $(CFLAGS) -Werror -x c - -march=native -o .test 2>/dev/null && echo 1 || echo 0 ; rm -f .test )" "1"
	HAVE_MARCHNATIVE = 1
	SPECIAL_PERFORMANCE += -march=native
  endif
  $(info SPECIAL_PERFORMANCE=$(SPECIAL_PERFORMANCE))
else
  SPECIAL_PERFORMANCE :=
endif

ifneq "$(SYS)" "Darwin"
 #ifeq "$(HAVE_MARCHNATIVE)" "1"
 #  SPECIAL_PERFORMANCE += -march=native
 #endif
 #ifndef DEBUG
 #  override CFLAGS_OPT += -D_FORTIFY_SOURCE=1
 #endif
else
  # On some odd MacOS system configurations, the Xcode sdk path is not set correctly
  SDK_LD = -L$(shell xcrun --show-sdk-path)/usr/lib
  override LDFLAGS += $(SDK_LD)
endif

COMPILER_TYPE=$(shell $(CC) --version|grep "Free Software Foundation")
ifneq "$(COMPILER_TYPE)" ""
  #$(info gcc is being used)
  override CFLAGS_OPT += -Wno-error=format-truncation -Wno-format-truncation
endif

ifeq "$(SYS)" "SunOS"
  override LDFLAGS = -lkstat -lrt -lsocket -lnsl
endif

ifdef STATIC
  $(info Compiling static version of binaries, disabling python though)
  # Disable python for static compilation to simplify things
  PYTHON_OK = 0
  PYFLAGS=
  PYTHON_INCLUDE = /

  override CFLAGS_OPT += -static
  override LDFLAGS += -lm -lpthread -lz -lutil
endif

ifdef PROFILING
  $(info Compiling with profiling information, for analysis: gprof ./afl-fuzz gmon.out > prof.txt)
  override CFLAGS_OPT += -pg -DPROFILING=1
  override LDFLAGS += -pg
endif

ifdef INTROSPECTION
  $(info Compiling with introspection documentation)
  override CFLAGS_OPT += -DINTROSPECTION=1
endif

ifneq "$(ARCH)" "x86_64"
 ifneq "$(patsubst i%86,i386,$(ARCH))" "i386"
  ifneq "$(ARCH)" "amd64"
   ifneq "$(ARCH)" "i86pc"
	AFL_NO_X86=1
   endif
  endif
 endif
endif

ifdef DEBUG
  $(info Compiling DEBUG version of binaries)
  override CFLAGS += -ggdb3 -O0 -Wall -Wextra -Werror $(CFLAGS_OPT)
else
  CFLAGS ?= -O2 $(CFLAGS_OPT) # -funroll-loops is slower on modern compilers
endif

override CFLAGS += -g -Wno-pointer-sign -Wno-variadic-macros -Wall -Wextra -Wno-pointer-arith \
			-fPIC -I include/ -DAFL_PATH=\"$(HELPER_PATH)\"  \
			-DBIN_PATH=\"$(BIN_PATH)\" -DDOC_PATH=\"$(DOC_PATH)\"
# -fstack-protector

ifeq "$(SYS)" "FreeBSD"
  override CFLAGS  += -I /usr/local/include/
  override LDFLAGS += -L /usr/local/lib/
endif

ifeq "$(SYS)" "DragonFly"
  override CFLAGS  += -I /usr/local/include/
  override LDFLAGS += -L /usr/local/lib/
endif

ifeq "$(SYS)" "OpenBSD"
  override CFLAGS  += -I /usr/local/include/ -mno-retpoline
  override LDFLAGS += -Wl,-z,notext -L /usr/local/lib/
endif

ifeq "$(SYS)" "NetBSD"
  override CFLAGS  += -I /usr/pkg/include/
  override LDFLAGS += -L /usr/pkg/lib/
endif

ifeq "$(SYS)" "Haiku"
  SHMAT_OK=0
  override CFLAGS  += -DUSEMMAP=1 -Wno-error=format
  override LDFLAGS += -Wno-deprecated-declarations -lgnu -lnetwork
  #SPECIAL_PERFORMANCE += -DUSEMMAP=1
endif

AFL_FUZZ_FILES = $(wildcard src/afl-fuzz*.c)

ifneq "$(shell command -v python3m 2>/dev/null)" ""
  ifneq "$(shell command -v python3m-config 2>/dev/null)" ""
    PYTHON_INCLUDE  := $(shell python3m-config --includes)
    PYTHON_VERSION  := $(strip $(shell python3m --version 2>&1))
    # Starting with python3.8, we need to pass the `embed` flag. Earlier versions didn't know this flag.
    ifeq "$(shell python3m-config --embed --libs 2>/dev/null | grep -q lpython && echo 1 )" "1"
      PYTHON_LIB      := $(shell python3m-config --libs --embed --ldflags)
    else
      PYTHON_LIB      := $(shell python3m-config --ldflags)
    endif
  endif
endif

ifeq "$(PYTHON_INCLUDE)" ""
  ifneq "$(shell command -v python3 2>/dev/null)" ""
    ifneq "$(shell command -v python3-config 2>/dev/null)" ""
      PYTHON_INCLUDE  := $(shell python3-config --includes)
      PYTHON_VERSION  := $(strip $(shell python3 --version 2>&1))
      # Starting with python3.8, we need to pass the `embed` flag. Earlier versions didn't know this flag.
      ifeq "$(shell python3-config --embed --libs 2>/dev/null | grep -q lpython && echo 1 )" "1"
        PYTHON_LIB      := $(shell python3-config --libs --embed --ldflags)
      else
        PYTHON_LIB      := $(shell python3-config --ldflags)
      endif
    endif
  endif
endif

ifeq "$(PYTHON_INCLUDE)" ""
  ifneq "$(shell command -v python 2>/dev/null)" ""
    ifneq "$(shell command -v python-config 2>/dev/null)" ""
      PYTHON_INCLUDE  := $(shell python-config --includes)
      PYTHON_LIB      := $(shell python-config --ldflags)
      PYTHON_VERSION  := $(strip $(shell python --version 2>&1))
    endif
  endif
endif

# Old Ubuntu and others dont have python/python3-config so we hardcode 3.7
ifeq "$(PYTHON_INCLUDE)" ""
  ifneq "$(shell command -v python3.7 2>/dev/null)" ""
    ifneq "$(shell command -v python3.7-config 2>/dev/null)" ""
      PYTHON_INCLUDE  := $(shell python3.7-config --includes)
      PYTHON_LIB      := $(shell python3.7-config --ldflags)
      PYTHON_VERSION  := $(strip $(shell python3.7 --version 2>&1))
    endif
  endif
endif

# Old Ubuntu and others dont have python/python2-config so we hardcode 2.7
ifeq "$(PYTHON_INCLUDE)" ""
  ifneq "$(shell command -v python2.7 2>/dev/null)" ""
    ifneq "$(shell command -v python2.7-config 2>/dev/null)" ""
      PYTHON_INCLUDE  := $(shell python2.7-config --includes)
      PYTHON_LIB      := $(shell python2.7-config --ldflags)
      PYTHON_VERSION  := $(strip $(shell python2.7 --version 2>&1))
    endif
  endif
endif

ifdef SOURCE_DATE_EPOCH
    BUILD_DATE ?= $(shell date -u -d "@$(SOURCE_DATE_EPOCH)" "+%Y-%m-%d" 2>/dev/null || date -u -r "$(SOURCE_DATE_EPOCH)" "+%Y-%m-%d" 2>/dev/null || date -u "+%Y-%m-%d")
else
    BUILD_DATE ?= $(shell date "+%Y-%m-%d")
endif

ifneq "$(filter Linux GNU%,$(SYS))" ""
  override LDFLAGS += -ldl -lrt -lm
endif

ifneq "$(findstring FreeBSD, $(SYS))" ""
  override CFLAGS  += -pthread
  override LDFLAGS += -lpthread -lm
endif

ifneq "$(findstring NetBSD, $(SYS))" ""
  override CFLAGS  += -pthread
  override LDFLAGS += -lpthread -lm
endif

ifneq "$(findstring OpenBSD, $(SYS))" ""
  override CFLAGS  += -pthread
  override LDFLAGS += -lpthread -lm
endif

COMM_HDR    = include/alloc-inl.h include/config.h include/debug.h include/types.h

ifeq "$(shell echo '$(HASH)include <Python.h>@int main() {return 0; }' | tr @ '\n' | $(CC) $(CFLAGS) -x c - -o .test $(PYTHON_INCLUDE) $(LDFLAGS) $(PYTHON_LIB) 2>/dev/null && echo 1 || echo 0 ; rm -f .test )" "1"
	PYTHON_OK=1
	PYFLAGS=-DUSE_PYTHON $(PYTHON_INCLUDE) $(LDFLAGS) $(PYTHON_LIB) -DPYTHON_VERSION="\"$(PYTHON_VERSION)\""
else
	PYTHON_OK=0
	PYFLAGS=
endif

ifdef NO_PYTHON
	PYTHON_OK=0
	PYFLAGS=
endif

IN_REPO=0
ifeq "$(shell command -v git >/dev/null && git status >/dev/null 2>&1 && echo 1 || echo 0)" "1"
  IN_REPO=1
endif
ifeq "$(shell command -v svn >/dev/null && svn proplist . 2>/dev/null && echo 1 || echo 0)" "1"
  IN_REPO=1
endif

ifeq "$(shell echo 'int main() { return 0;}' | $(CC) $(CFLAGS) -fsanitize=address -x c - -o .test2 2>/dev/null && echo 1 || echo 0 ; rm -f .test2 )" "1"
	ASAN_CFLAGS=-fsanitize=address -fstack-protector-all -fno-omit-frame-pointer -DASAN_BUILD
	ASAN_LDFLAGS=-fsanitize=address -fstack-protector-all -fno-omit-frame-pointer
endif

ifeq "$(shell echo '$(HASH)include <sys/ipc.h>@$(HASH)include <sys/shm.h>@int main() { int _id = shmget(IPC_PRIVATE, 65536, IPC_CREAT | IPC_EXCL | 0600); shmctl(_id, IPC_RMID, 0); return 0;}' | tr @ '\n' | $(CC) $(CFLAGS) -x c - -o .test2 2>/dev/null && echo 1 || echo 0 ; rm -f .test2 )" "1"
	SHMAT_OK=1
else
	SHMAT_OK=0
	override CFLAGS+=-DUSEMMAP=1
	LDFLAGS += -Wno-deprecated-declarations
endif

ifdef TEST_MMAP
	SHMAT_OK=0
	override CFLAGS += -DUSEMMAP=1
	LDFLAGS += -Wno-deprecated-declarations
endif

.PHONY: all
all:	test_x86 test_shm test_python ready afl-cc llvm
	@echo
	@echo
	@echo Build Summary:
	@test -e SanitizerCoverageLTO.so && echo "[+] LLVM LTO mode successfully built" || echo "[-] LLVM LTO mode could not be built!!!"
	@echo

.PHONY: llvm
llvm:
	-$(MAKE) -j$(nproc) -f GNUmakefile.llvm
	@test -e afl-cc || { echo "[-] Compiling afl-cc failed. You seem not to have a working compiler." ; exit 1; }

# hint: make targets are also listed in the top level README.md
.PHONY: help
help:
	@echo "HELP --- the following make targets exist:"
	@echo "=========================================="
	@echo "all: the main binaries for instrumentation"
	@echo "clean: cleans everything compiled"
	@echo "code-format: format the code, do this before you commit and send a PR please!"
	@echo "help: shows these build options :-)"
	@echo "=========================================="
	@echo "Recommended: \"distrib\" or \"source-only\", then \"install\""
	@echo
	@echo Known build environment options:
	@echo "=========================================="
	@echo "PERFORMANCE - compile with performance options that make the binary not transferable to other systems. Recommended!"
	@echo STATIC - compile AFL++ static
	@echo ASAN_BUILD - compiles AFL++ with memory sanitizer for debug purposes
	@echo UBSAN_BUILD - compiles AFL++ tools with undefined behaviour sanitizer for debug purposes
	@echo DEBUG - no optimization, -ggdb3, all warnings and -Werror
	@echo LLVM_DEBUG - shows llvm deprecation warnings
	@echo AFL_NO_X86 - if compiling on non-intel/amd platforms
	@echo "LLVM_CONFIG - if your distro doesn't use the standard name for llvm-config (e.g., Debian)"
	@echo "=========================================="
	@echo e.g.: make LLVM_CONFIG=llvm-config-16

.PHONY: test_x86
ifndef AFL_NO_X86
test_x86:
	@echo "[*] Checking for the default compiler cc..."
	@type $(CC) >/dev/null || ( echo; echo "Oops, looks like there is no compiler '"$(CC)"' in your path."; echo; echo "Don't panic! You can restart with '"$(_)" CC=<yourCcompiler>'."; echo; exit 1 )
	@echo "[*] Testing the PATH environment variable..."
	@test "$${PATH}" != "$${PATH#.:}" && { echo "Please remove current directory '.' from PATH to avoid recursion of 'as', thanks!"; echo; exit 1; } || :
	@echo "[*] Checking for the ability to compile x86 code..."
	@echo 'int main() { __asm__("xorb %al, %al"); }' | $(CC) $(CFLAGS) $(LDFLAGS) -w -x c - -o .test1 || ( echo; echo "Oops, looks like your compiler can't generate x86 code."; echo; echo "Don't panic! You can use the LLVM or QEMU mode, but see docs/INSTALL first."; echo "(To ignore this error, set AFL_NO_X86=1 and try again.)"; echo; exit 1 )
	@rm -f .test1
else
test_x86:
	@echo "[!] Note: skipping x86 compilation checks (AFL_NO_X86 set)."
endif

.PHONY: test_shm
ifeq "$(SHMAT_OK)" "1"
test_shm:
	@echo "[+] shmat seems to be working."
	@rm -f .test2
else
test_shm:
	@echo "[-] shmat seems not to be working, switching to mmap implementation"
endif

ifeq "$(shell echo '$(HASH)include <zlib.h>@int main() {return 0; }' | tr @ '\n' | $(CC) $(CFLAGS) -Werror -x c - -lz -o .test 2>/dev/null && echo 1 || echo 0 ; rm -f .test )" "1"
  override SPECIAL_PERFORMANCE += -DHAVE_ZLIB
  override LDFLAGS += -lz
  $(info [+] ZLIB detected)
else
  $(info [!] Warning: no ZLIB detected)
endif

.PHONY: test_python
ifeq "$(PYTHON_OK)" "1"
test_python:
	@rm -f .test 2> /dev/null
	@echo "[+] $(PYTHON_VERSION) support seems to be working."
else
test_python:
	@echo "[-] You seem to need to install the package python3-dev or python-dev (and perhaps python[3]-apt), but it is optional so we continue"
endif

.PHONY: ready
ready:
	@echo "[+] Everything seems to be working, ready to compile. ($(shell $(CC) --version 2>&1|head -n 1))"

.PHONY: code-format
code-format:
	./.custom-format.py -i src/*.c
	./.custom-format.py -i include/*.h
	./.custom-format.py -i instrumentation/*.h
	./.custom-format.py -i instrumentation/*.cc
	./.custom-format.py -i instrumentation/*.c

.NOTPARALLEL: clean all

.PHONY: clean
clean:
	rm -rf $(PROGS) afl-fuzz-document afl-as as afl-g++ afl-clang afl-clang++ *.o src/*.o *~ a.out core core.[1-9][0-9]* *.stackdump .test .test1 .test2 test-instr .test-instr0 .test-instr1 afl-cs-proxy afl-qemu-trace afl-gcc-fast afl-g++-fast ld *.so *.8 test/unittests/*.o test/unittests/unit_maybe_alloc test/unittests/preallocable .afl-* afl-gcc afl-g++ afl-clang afl-clang++ test/unittests/unit_hash test/unittests/unit_rand *.dSYM lib*.a
	-$(MAKE) -f GNUmakefile.llvm clean
