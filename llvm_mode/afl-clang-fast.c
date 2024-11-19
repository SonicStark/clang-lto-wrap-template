/*
  Copyright 2015 Google LLC All rights reserved.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

/*
   american fuzzy lop - LLVM-mode wrapper for clang
   ------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   LLVM integration design comes from Laszlo Szekeres.

   This program is a drop-in replacement for clang, similar in most respects
   to ../afl-gcc. It tries to figure out compilation mode, adds a bunch
   of flags, and then calls the real compiler.
*/

#define AFL_MAIN

#include "../config.h"
#include "../types.h"
#include "../debug.h"
#include "../alloc-inl.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

static u8*  obj_path;               /* Path to runtime libraries         */
static u8** cc_params;              /* Parameters passed to the real CC  */
static u32  cc_par_cnt = 1;         /* Param count, including argv0      */

static u8  *lto_flag;
static u8   lto_mode = 0;           /* If LTO mode used                  */
static u8   lto_save_temps = 0;     /* If use --save-temps in LTO mode   */

/* Try to set output name when "-o" detected, to help AFL_DUMP_BC */

static void set_output_name(u8 *this_argv, u8 *next_argv) {

  u8 *mn = this_argv + 2;

  if (*mn == '\0') {

    if (!next_argv) { return; }

    mn = next_argv;

  }

  u8 *mn_tmp = getenv("AFL_DUMP_BC");

  // AFL_DUMP_BC=""
  if (mn_tmp && (*mn_tmp == '\0')) {

    setenv("AFL_OUTPUT_NAME", mn, 0);
    return;

  }

  if ((mn_tmp = strrchr(mn, '/')) != NULL) {

    ++mn_tmp;
  
  } else {

    mn_tmp = mn;

  }

  if (*mn_tmp == '\0') { return; }

  setenv("AFL_OUTPUT_NAME", mn_tmp, 1);

}

/* Try to find the runtime libraries. If that fails, abort. */

static void find_obj(u8* argv0) {

  u8 *afl_path = getenv("AFL_PATH");
  u8 *slash, *tmp;

  if (afl_path) {

    tmp = alloc_printf("%s/afl-llvm-rt.o", afl_path);

    if (!access(tmp, R_OK)) {
      obj_path = afl_path;
      ck_free(tmp);
      return;
    }

    ck_free(tmp);

  }

  slash = strrchr(argv0, '/');

  if (slash) {

    u8 *dir;

    *slash = 0;
    dir = ck_strdup(argv0);
    *slash = '/';

    tmp = alloc_printf("%s/afl-llvm-rt.o", dir);

    if (!access(tmp, R_OK)) {
      obj_path = dir;
      ck_free(tmp);
      return;
    }

    ck_free(tmp);
    ck_free(dir);

  }

  if (!access(AFL_PATH "/afl-llvm-rt.o", R_OK)) {
    obj_path = AFL_PATH;
    return;
  }

  FATAL("Unable to find 'afl-llvm-rt.o' or 'afl-llvm-pass.so'. Please set AFL_PATH");

}


/* Copy argv to cc_params, making the necessary edits. */

static void edit_params(u32 argc, char** argv) {

  u8 have_c = 0, have_e = 0, non_dash = 0;
  u8 shared_linking = 0, partial_linking = 0;
  u8 fortify_set = 0, asan_set = 0, x_set = 0, bit_mode = 0;
  u8 *name;

  cc_params = ck_alloc((argc + 128) * sizeof(u8*));

  name = strrchr(argv[0], '/');
  if (!name) name = argv[0]; else name++;

  if (!strcmp(name, "afl-clang-fast++")) {
    u8* alt_cxx = getenv("AFL_CXX");
    cc_params[0] = alt_cxx ? alt_cxx : (u8*)"clang++";
  } else {
    u8* alt_cc = getenv("AFL_CC");
    cc_params[0] = alt_cc ? alt_cc : (u8*)"clang";
  }

  u32 argc_cp = argc;
  char **argv_cp = argv;

  while (--argc_cp) {
    u8* cur = *(++argv_cp);

    if (!strcmp(cur, "-m32")) bit_mode = 32;
    if (!strcmp(cur, "armv7a-linux-androideabi")) bit_mode = 32;
    if (!strcmp(cur, "-m64")) bit_mode = 64;

    if (!strcmp(cur, "-x")) x_set = 1;

    if (!strcmp(cur, "-E")) have_e = 1;
    if (!strcmp(cur, "-c")) have_c = 1;
    if (cur[0] != '-')      non_dash = 1;

    if (!strcmp(cur, "-shared") || !strcmp(cur, "-dynamiclib"))
      shared_linking = 1;
  
    if (!strcmp(cur, "-Wl,-r") || !strcmp(cur, "-Wl,-i") ||
        !strcmp(cur, "-Wl,--relocatable") ||
        !strcmp(cur, "-r") || !strcmp(cur, "--relocatable"))
      partial_linking = 1;

    if (!strcmp(cur, "-fsanitize=address") ||
        !strcmp(cur, "-fsanitize=memory")) asan_set = 1;

    if (strstr(cur, "FORTIFY_SOURCE")) fortify_set = 1;

    if (lto_mode && !strncmp(cur, "-o", 2)) {
      set_output_name(cur, (argv_cp+1) ? *(argv_cp+1) : "");
    }

  }

  if (lto_mode) {

    cc_params[cc_par_cnt++] = lto_flag;

    if (!have_c) {

      /* linker flags for LTO */

      //TODO: compat with afl-ld-lto from AFL++
      unsetenv("AFL_LD");
      unsetenv("AFL_LD_CALLER");

      u8 *ld_path = NULL;
      if (getenv("AFL_REAL_LD")) {

        ld_path = ck_strdup(getenv("AFL_REAL_LD"));

      } else {

        ld_path = ck_strdup(AFL_REAL_LD);

      }

      if (!*ld_path) {

        ck_free(ld_path);
        ld_path = ck_strdup("ld.lld");

      }

#if defined(AFL_CLANG_LDPATH) && LLVM_MAJOR >= 12
      cc_params[cc_par_cnt++] = alloc_printf("--ld-path=%s", ld_path);
#else
      cc_params[cc_par_cnt++] = alloc_printf("-fuse-ld=%s", ld_path);
#endif
      ck_free(ld_path);

      /* load passes for LTO */

#if defined(AFL_CLANG_LDPATH) && LLVM_MAJOR >= 15
      // The NewPM implementation only works fully since LLVM 15.
      cc_params[cc_par_cnt++] = alloc_printf("-Wl,--load-pass-plugin=%s/afl-llvm-pass.so", obj_path);
#elif defined(AFL_CLANG_LDPATH) && LLVM_MAJOR >= 13
      cc_params[cc_par_cnt++] = "-Wl,--lto-legacy-pass-manager";
      cc_params[cc_par_cnt++] = alloc_printf("-Wl,-mllvm=-load=%s/afl-llvm-pass.so", obj_path);
#else
      cc_params[cc_par_cnt++] = "-fno-experimental-new-pass-manager";
      cc_params[cc_par_cnt++] = alloc_printf("-Wl,-mllvm=-load=%s/afl-llvm-pass.so", obj_path);
#endif
      cc_params[cc_par_cnt++] = "-Wl,--allow-multiple-definition";

      /* AFL_LTO_SAVE_TEMPS */

      if (lto_save_temps)
        cc_params[cc_par_cnt++] = "-Wl,--save-temps";

    }

  } else {

#if LLVM_MAJOR >= 11                                /* use new pass manager */
  #if LLVM_MAJOR < 16
    cc_params[cc_par_cnt++] = "-fexperimental-new-pass-manager";
  #endif
    cc_params[cc_par_cnt++] = alloc_printf("-fpass-plugin=%s/afl-llvm-pass.so", obj_path);
#else
    cc_params[cc_par_cnt++] = "-Xclang";
    cc_params[cc_par_cnt++] = "-load";
    cc_params[cc_par_cnt++] = "-Xclang";
    cc_params[cc_par_cnt++] = alloc_printf("%s/afl-llvm-pass.so", obj_path);
#endif

  }

  cc_params[cc_par_cnt++] = "-Qunused-arguments";
  cc_params[cc_par_cnt++] = "-Wno-unused-command-line-argument";

  while (--argc) {
    u8* cur = *(++argv);

    if (!strcmp(cur, "-Wl,-z,defs") ||
        !strcmp(cur, "-Wl,--no-undefined") ||
        !strcmp(cur, "-Wl,-no-undefined") ||
        !strcmp(cur, "--no-undefined")) continue;

    if (!strncmp(cur, "-fuse-ld=", 9) ||
        !strncmp(cur, "--ld-path=", 10)) continue;

    if (lto_mode && !strncmp(cur, "-flto=thin", 10))
      FATAL("LTO mode cannot work with -flto=thin.");

    cc_params[cc_par_cnt++] = cur;

  }

  if (getenv("AFL_HARDEN")) {

    cc_params[cc_par_cnt++] = "-fstack-protector-all";

    if (!fortify_set)
      cc_params[cc_par_cnt++] = "-D_FORTIFY_SOURCE=2";

  }

  if (!asan_set) {

    if (getenv("AFL_USE_ASAN")) {

      if (getenv("AFL_USE_MSAN"))
        FATAL("ASAN and MSAN are mutually exclusive");

      if (getenv("AFL_HARDEN"))
        FATAL("ASAN and AFL_HARDEN are mutually exclusive");

      cc_params[cc_par_cnt++] = "-U_FORTIFY_SOURCE";
      cc_params[cc_par_cnt++] = "-fsanitize=address";

    } else if (getenv("AFL_USE_MSAN")) {

      if (getenv("AFL_USE_ASAN"))
        FATAL("ASAN and MSAN are mutually exclusive");

      if (getenv("AFL_HARDEN"))
        FATAL("MSAN and AFL_HARDEN are mutually exclusive");

      cc_params[cc_par_cnt++] = "-U_FORTIFY_SOURCE";
      cc_params[cc_par_cnt++] = "-fsanitize=memory";

    }

  }

  if (!getenv("AFL_DONT_OPTIMIZE")) {

    cc_params[cc_par_cnt++] = "-g";
    cc_params[cc_par_cnt++] = "-O3";
    cc_params[cc_par_cnt++] = "-funroll-loops";

  }

  if (getenv("AFL_NO_BUILTIN")) {

    cc_params[cc_par_cnt++] = "-fno-builtin-strcmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strncmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strcasecmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strncasecmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-memcmp";

  }

  cc_params[cc_par_cnt++] = "-D__AFL_HAVE_MANUAL_CONTROL=1";
  cc_params[cc_par_cnt++] = "-D__AFL_COMPILER=1";
  cc_params[cc_par_cnt++] = "-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1";

  /* When the user tries to use persistent or deferred forkserver modes by
     appending a single line to the program, we want to reliably inject a
     signature into the binary (to be picked up by afl-fuzz) and we want
     to call a function from the runtime .o file. This is unnecessarily
     painful for three reasons:

     1) We need to convince the compiler not to optimize out the signature.
        This is done with __attribute__((used)).

     2) We need to convince the linker, when called with -Wl,--gc-sections,
        not to do the same. This is done by forcing an assignment to a
        'volatile' pointer.

     3) We need to declare __afl_persistent_loop() in the global namespace,
        but doing this within a method in a class is hard - :: and extern "C"
        are forbidden and __attribute__((alias(...))) doesn't work. Hence the
        __asm__ aliasing trick.

   */

  cc_params[cc_par_cnt++] = "-D__AFL_LOOP(_A)="
    "({ static volatile char *_B __attribute__((used)); "
    " _B = (char*)\"" PERSIST_SIG "\"; "
#ifdef __APPLE__
    "__attribute__((visibility(\"default\"))) "
    "int _L(unsigned int) __asm__(\"___afl_persistent_loop\"); "
#else
    "__attribute__((visibility(\"default\"))) "
    "int _L(unsigned int) __asm__(\"__afl_persistent_loop\"); "
#endif /* ^__APPLE__ */
    "_L(_A); })";

  cc_params[cc_par_cnt++] = "-D__AFL_INIT()="
    "do { static volatile char *_A __attribute__((used)); "
    " _A = (char*)\"" DEFER_SIG "\"; "
#ifdef __APPLE__
    "__attribute__((visibility(\"default\"))) "
    "void _I(void) __asm__(\"___afl_manual_init\"); "
#else
    "__attribute__((visibility(\"default\"))) "
    "void _I(void) __asm__(\"__afl_manual_init\"); "
#endif /* ^__APPLE__ */
    "_I(); } while (0)";

  if (x_set) {
    cc_params[cc_par_cnt++] = "-x";
    cc_params[cc_par_cnt++] = "none";
  }

  if (have_e || have_c || !non_dash || 
      shared_linking || partial_linking) {

    cc_params[cc_par_cnt] = NULL;
    return;

  }

#ifndef __ANDROID__
  switch (bit_mode) {

    case 0:
      cc_params[cc_par_cnt++] = alloc_printf("%s/afl-llvm-rt.o", obj_path);
      break;

    case 32:
      cc_params[cc_par_cnt++] = alloc_printf("%s/afl-llvm-rt-32.o", obj_path);

      if (access(cc_params[cc_par_cnt - 1], R_OK))
        FATAL("-m32 is not supported by your compiler");

      break;

    case 64:
      cc_params[cc_par_cnt++] = alloc_printf("%s/afl-llvm-rt-64.o", obj_path);

      if (access(cc_params[cc_par_cnt - 1], R_OK))
        FATAL("-m64 is not supported by your compiler");

      break;

  }
#endif

  cc_params[cc_par_cnt] = NULL;

}


/* Main entry point */

int main(int argc, char** argv) {

  if (isatty(2) && !getenv("AFL_QUIET")) {

    SAYF(cCYA "afl-clang-fast " cBRI VERSION  cRST " by <lszekeres@google.com>\n");

  }

  if (argc < 2) {

    SAYF("\n"
         "This serves as a drop-in replacement\n"
         "for clang, letting you recompile third-party code with the required runtime\n"
         "instrumentation.\n\n"

         "You can specify custom next-stage toolchain via AFL_CC and AFL_CXX. Setting\n"
         "AFL_HARDEN enables hardening optimizations in the compiled code.\n\n");

    exit(1);

  }

  if (getenv("AFL_LTO_ENABLE")) {

    lto_mode = 1;
    lto_flag = AFL_CLANG_FLTO;
  
    if (lto_flag[0] != '-')
      FATAL(
        "Using LTO mode is not possible because Makefile magic did not "
        "identify the correct -flto flag");

    if (getenv("AFL_LTO_SAVE_TEMPS")) { 

      lto_save_temps = 1; 

    }

  }

#ifndef __ANDROID__
  find_obj(argv[0]);
#endif

  edit_params(argc, argv);

  execvp(cc_params[0], (char**)cc_params);

  FATAL("Oops, failed to execute '%s' - check your PATH", cc_params[0]);

  return 0;

}
