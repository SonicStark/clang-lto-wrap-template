#
# american fuzzy lop - LLVM instrumentation
# -----------------------------------------
#
# Written by Laszlo Szekeres <lszekeres@google.com> and
#            Michal Zalewski <lcamtuf@google.com>
#
# LLVM integration design comes from Laszlo Szekeres.
#
# Copyright 2015, 2016 Google LLC All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#   http://www.apache.org/licenses/LICENSE-2.0
#

PREFIX      ?= /usr/local
HELPER_PATH  = $(PREFIX)/lib/afl
BIN_PATH     = $(PREFIX)/bin

VERSION     = $(shell grep '^\#define VERSION ' ../config.h | cut -d '"' -f2)

override LLVM_TOO_NEW_DEFAULT := 18
override LLVM_TOO_OLD_DEFAULT := 6

LLVM_CONFIG ?= llvm-config

override LLVM_RAW_VER := $(shell $(LLVM_CONFIG) --version 2>/dev/null)
LLVMVER               := $(subst svn,,$(subst git,,$(LLVM_RAW_VER)))
ifeq "$(LLVMVER)" ""
  $(error [X] llvm_mode needs llvm-config, which was not found. Set LLVM_CONFIG to its path and retry.)
endif

LLVM_BINDIR           := $(shell $(LLVM_CONFIG) --bindir 2>/dev/null)
LLVM_LIBDIR           := $(shell $(LLVM_CONFIG) --libdir 2>/dev/null)
LLVM_MAJOR            := $(firstword $(subst ., ,$(LLVMVER)))
LLVM_MINOR            := $(firstword $(subst ., ,$(subst $(LLVM_MAJOR).,,$(LLVMVER))))
LLVM_TOO_NEW          := $(shell test $(LLVM_MAJOR) -gt $(LLVM_TOO_NEW_DEFAULT) && echo 1 || echo 0)
LLVM_TOO_OLD          := $(shell test $(LLVM_MAJOR) -lt $(LLVM_TOO_OLD_DEFAULT) && echo 1 || echo 0)

ifeq "$(LLVM_TOO_NEW)" "1"
  $(error [X] You are using an in-development llvm version - this might break llvm_mode!)
endif

ifeq "$(LLVM_TOO_OLD)" "1"
  $(error [X] You are using an outdated LLVM version!)
endif

CC         = $(LLVM_BINDIR)/clang
CXX        = $(LLVM_BINDIR)/clang++

# llvm-config --bindir may not providing a valid path, so ...
ifeq "$(shell test -e $(CC) || echo 1 )" "1"
  # however we must ensure that this is not a "CC=gcc make"
  ifeq "$(shell command -v $(CC) 2> /dev/null)" ""
    # we do not have a valid CC variable so we try alternatives
    ifeq "$(shell test -e '$(BIN_DIR)/clang' && echo 1)" "1"
      # we found one in the local install directory, lets use these
      CC         = $(BIN_DIR)/clang
    else
      # hope for the best
      $(warning we have trouble finding clang - llvm-config is not helping us)
      CC         = clang
    endif
  endif
endif
# llvm-config --bindir may not providing a valid path, so ...
ifeq "$(shell test -e $(CXX) || echo 1 )" "1"
  # however we must ensure that this is not a "CXX=g++ make"
  ifeq "$(shell command -v $(CXX) 2> /dev/null)" ""
    # we do not have a valid CXX variable so we try alternatives
    ifeq "$(shell test -e '$(BIN_DIR)/clang++' && echo 1)" "1"
      # we found one in the local install directory, lets use these
      CXX        = $(BIN_DIR)/clang++
    else
      # hope for the best
      $(warning we have trouble finding clang++ - llvm-config is not helping us)
      CXX        = clang++
    endif
  endif
endif

ifeq "$(shell echo 'int main() {return 0; }' | $(CC) -x c - -flto=full -o .test 2>/dev/null && echo 1 || echo 0 ; rm -f .test )" "1"
        AFL_CLANG_FLTO ?= -flto=full
else
 ifeq "$(shell echo 'int main() {return 0; }' | $(CC) -x c - -flto=thin -o .test 2>/dev/null && echo 1 || echo 0 ; rm -f .test )" "1"
        AFL_CLANG_FLTO ?= -flto=thin
 else
  ifeq "$(shell echo 'int main() {return 0; }' | $(CC) -x c - -flto -o .test 2>/dev/null && echo 1 || echo 0 ; rm -f .test )" "1"
        AFL_CLANG_FLTO ?= -flto
  endif
 endif
endif

ifneq "$(AFL_CLANG_FLTO)" ""
  ifeq "$(AFL_REAL_LD)" ""
    ifneq "$(shell readlink $(LLVM_BINDIR)/ld.lld 2>&1)" ""
      AFL_REAL_LD = $(LLVM_BINDIR)/ld.lld
    else ifneq "$(shell command -v ld.lld 2>/dev/null)" ""
      AFL_REAL_LD = $(shell command -v ld.lld)
      TMP_LDLDD_VERSION = $(shell $(AFL_REAL_LD) --version | awk '{ print $$2 }')
      ifeq "$(LLVMVER)" "$(TMP_LDLDD_VERSION)"
        $(warning ld.lld found in a weird location ($(AFL_REAL_LD)), but its the same version as LLVM so we will allow it)
      else
        $(error ld.lld found in a weird location ($(AFL_REAL_LD)) and its of a different version than LLVM ($(TMP_LDLDD_VERSION) vs. $(LLVMVER)) - cannot enable LTO mode)
      endif
      undefine TMP_LDLDD_VERSION
    else
      $(error ld.lld not found, cannot enable LTO mode)
    endif
  endif
else
  $(error clang option -flto is not working - maybe LLVMgold.so not found - cannot enable LTO mode)
endif

ifeq "$(shell echo 'int main() {return 0; }' | $(CLANG_BIN) -x c - -fuse-ld=$$(command -v ld) -o .test 2>/dev/null && echo 1 || echo 0 ; rm -f .test )" "1"
  AFL_CLANG_FUSELD=1
  ifeq "$(shell echo 'int main() {return 0; }' | $(CLANG_BIN) -x c - -fuse-ld=ld.lld --ld-path=$(AFL_REAL_LD) -o .test 2>/dev/null && echo 1 || echo 0 ; rm -f .test )" "1"
    AFL_CLANG_LDPATH=1
  endif
else
  $(error -fuse-ld is not working, cannot enable LTO mode)
endif

ifeq "$(shell echo 'int main() {return 0; }' | $(CLANG_BIN) -x c - -fdebug-prefix-map=$(CURDIR)=llvm_mode -o .test 2>/dev/null && echo 1 || echo 0 ; rm -f .test )" "1"
        AFL_CLANG_DEBUG_PREFIX = -fdebug-prefix-map="$(CURDIR)=llvm_mode"
else
        AFL_CLANG_DEBUG_PREFIX =
endif

CFLAGS      ?= -O3 -funroll-loops
CFLAGS      += -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign \
               -DAFL_PATH=\"$(HELPER_PATH)\" -DBIN_PATH=\"$(BIN_PATH)\" \
               -DVERSION=\"$(VERSION)\" \
               -DAFL_CLANG_FLTO=\"$(AFL_CLANG_FLTO)\" -DAFL_REAL_LD=\"$(AFL_REAL_LD)\" \
               -DAFL_CLANG_LDPATH=\"$(AFL_CLANG_LDPATH)\" -DAFL_CLANG_FUSELD=\"$(AFL_CLANG_FUSELD)\" \
               $(AFL_CLANG_DEBUG_PREFIX)

CXXFLAGS    ?= -O3 -funroll-loops
CXXFLAGS    += -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign \
               -DVERSION=\"$(VERSION)\" -Wno-variadic-macros \
			   $(AFL_CLANG_DEBUG_PREFIX)

# Mark nodelete to work around unload bug in upstream LLVM 5.0+
CLANG_CFL    = `$(LLVM_CONFIG) --cxxflags` -Wl,-znodelete -fno-rtti -fno-exceptions -fpic $(CXXFLAGS)
CLANG_LFL    = `$(LLVM_CONFIG) --ldflags` $(LDFLAGS)

# User teor2345 reports that this is required to make things work on MacOS X.

ifeq "$(shell uname)" "Darwin"
  CLANG_LFL += -Wl,-flat_namespace -Wl,-undefined,suppress
endif

PROGS      = ../afl-clang-fast ../afl-llvm-pass.so ../afl-llvm-rt.o ../afl-llvm-rt-32.o ../afl-llvm-rt-64.o

all: $(PROGS) all_done

../afl-clang-fast: afl-clang-fast.c | test_deps
	$(CC) $(CFLAGS) $< -o $@ -DLLVM_MINOR=$(LLVM_MINOR) -DLLVM_MAJOR=$(LLVM_MAJOR) $(LDFLAGS)
	ln -sf afl-clang-fast ../afl-clang-fast++

../afl-llvm-pass.so: afl-llvm-pass.so.cc | test_deps
	$(CXX) $(CLANG_CFL) -shared $< -o $@ $(CLANG_LFL)

../afl-llvm-rt.o: afl-llvm-rt.o.c | test_deps
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

../afl-llvm-rt-32.o: afl-llvm-rt.o.c | test_deps
	@printf "[*] Building 32-bit variant of the runtime (-m32)... "
	@$(CC) $(CFLAGS) -m32 -fPIC -c $< -o $@ 2>/dev/null; if [ "$$?" = "0" ]; then echo "success!"; else echo "failed (that's fine)"; fi

../afl-llvm-rt-64.o: afl-llvm-rt.o.c | test_deps
	@printf "[*] Building 64-bit variant of the runtime (-m64)... "
	@$(CC) $(CFLAGS) -m64 -fPIC -c $< -o $@ 2>/dev/null; if [ "$$?" = "0" ]; then echo "success!"; else echo "failed (that's fine)"; fi

all_done: $(PROGS)
	@echo "[+] All done! You can now use '../afl-clang-fast' to compile programs."

.NOTPARALLEL: clean

clean:
	rm -f *.o *.so *~ a.out core core.[1-9][0-9]* test-instr .test-instr0 .test-instr1 
	rm -f $(PROGS) ../afl-clang-fast++
