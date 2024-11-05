/*
   american fuzzy lop++ - compiler instrumentation wrapper
   -------------------------------------------------------

   Written by Michal Zalewski, Laszlo Szekeres and Marc Heuse

   Copyright 2015, 2016 Google Inc. All rights reserved.
   Copyright 2019-2024 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

 */

#define AFL_MAIN

#ifndef _GNU_SOURCE
  #define _GNU_SOURCE 1
#endif

#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"
#include "llvm-alternative-coverage.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <limits.h>
#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>

#if (LLVM_MAJOR - 0 == 0)
  #undef LLVM_MAJOR
#endif
#if !defined(LLVM_MAJOR)
  #define LLVM_MAJOR 0
#endif
#if (LLVM_MINOR - 0 == 0)
  #undef LLVM_MINOR
#endif
#if !defined(LLVM_MINOR)
  #define LLVM_MINOR 0
#endif

#ifndef MAX_PARAMS_NUM
  #define MAX_PARAMS_NUM 2048
#endif

/** Global declarations -----BEGIN----- **/

typedef enum {

  PARAM_MISS,  // not matched
  PARAM_SCAN,  // scan only
  PARAM_KEEP,  // kept as-is
  PARAM_DROP,  // ignored

} param_st;

typedef enum {

  INSTRUMENT_DEFAULT = 0,
  INSTRUMENT_CLASSIC = 1,
  INSTRUMENT_AFL = 1,
  INSTRUMENT_PCGUARD = 2,
  INSTRUMENT_CFG = 3,
  INSTRUMENT_LTO = 4,
  INSTRUMENT_LLVMNATIVE = 5,
  INSTRUMENT_GCC = 6,
  INSTRUMENT_CLANG = 7,
  INSTRUMENT_OPT_CTX = 8,
  INSTRUMENT_OPT_NGRAM = 16,
  INSTRUMENT_OPT_CALLER = 32,
  INSTRUMENT_OPT_CTX_K = 64,
  INSTRUMENT_OPT_CODECOV = 128,

} instrument_mode_id;

typedef enum {

  UNSET = 0,
  LTO = 1,
  LLVM = 2,
  GCC_PLUGIN = 3,
  GCC = 4,
  CLANG = 5

} compiler_mode_id;

static u8   cwd[4096];
static char opt_level = '3';
static u8   be_quiet = 0;

char instrument_mode_string[18][18] = {

    "DEFAULT",
    "CLASSIC",
    "PCGUARD",
    "CFG",
    "LTO",
    "PCGUARD-NATIVE",
    "GCC",
    "CLANG",
    "CTX",
    "CALLER",
    "",
    "",
    "",
    "",
    "",
    "",
    "NGRAM",
    ""

};

char compiler_mode_string[7][12] = {

    "AUTOSELECT", "LLVM-LTO", "LLVM", "GCC_PLUGIN",
    "GCC",        "CLANG",    ""

};

u8 *instrument_mode_2str(instrument_mode_id i) {

  return instrument_mode_string[i];

}

u8 *compiler_mode_2str(compiler_mode_id i) {

  return compiler_mode_string[i];

}

u8 *getthecwd() {

  if (getcwd(cwd, sizeof(cwd)) == NULL) {

    static u8 fail[] = "";
    return fail;

  }

  return cwd;

}

typedef struct aflcc_state {

  u8 **cc_params;                      /* Parameters passed to the real CC  */
  u32  cc_par_cnt;                     /* Param count, including argv0      */

  u8 *argv0;                           /* Original argv0 (by strdup)        */
  u8 *callname;                        /* Executable file argv0 indicated   */

  u8 debug;

  u8 compiler_mode, plusplus_mode, lto_mode;

  u8 *lto_flag;

  u8 instrument_mode, instrument_opt_mode, ngram_size, ctx_k;

  u8 cmplog_mode;

  u8 have_instr_env, have_gcc, have_clang, have_llvm, have_gcc_plugin, have_lto,
      have_optimized_pcguard, have_instr_list;

  u8 fortify_set, x_set, bit_mode, preprocessor_only, have_unroll, have_o,
      have_pic, have_c, shared_linking, partial_linking, non_dash, have_fp,
      have_flto, have_hidden, have_fortify, have_fcf, have_staticasan,
      have_rust_asanrt, have_asan, have_msan, have_ubsan, have_lsan, have_tsan,
      have_cfisan;

  // u8 *march_opt;
  u8  need_aflpplib;
  int passthrough;

  u8  use_stdin;                                                   /* dummy */
  u8 *argvnull;                                                    /* dummy */

} aflcc_state_t;

void aflcc_state_init(aflcc_state_t *, u8 *argv0);

u8 *find_object(aflcc_state_t *, u8 *obj);

void find_built_deps(aflcc_state_t *);

/* Insert param into the new argv, raise error if MAX_PARAMS_NUM exceeded. */
static inline void insert_param(aflcc_state_t *aflcc, u8 *param) {

  if (unlikely(aflcc->cc_par_cnt + 1 >= MAX_PARAMS_NUM))
    FATAL("Too many command line parameters, please increase MAX_PARAMS_NUM.");

  aflcc->cc_params[aflcc->cc_par_cnt++] = param;

}

/*
  Insert a param which contains path to the object file. It uses find_object to
  get the path based on the name `obj`, and then uses a sprintf like method to
  format it with `fmt`. If `fmt` is NULL, the inserted arg is same as the path.
  If `msg` provided, it should be an error msg raised if the path can't be
  found. `obj` must not be NULL.
*/
static inline void insert_object(aflcc_state_t *aflcc, u8 *obj, u8 *fmt,
                                 u8 *msg) {

  u8 *_obj_path = find_object(aflcc, obj);
  if (!_obj_path) {

    if (msg)
      FATAL("%s", msg);
    else
      FATAL("Unable to find '%s'", obj);

  } else {

    if (fmt) {

      u8 *_obj_path_fmt = alloc_printf(fmt, _obj_path);
      ck_free(_obj_path);
      aflcc->cc_params[aflcc->cc_par_cnt++] = _obj_path_fmt;

    } else {

      aflcc->cc_params[aflcc->cc_par_cnt++] = _obj_path;

    }

  }

}

/* Insert params into the new argv, make clang load the pass. */
static inline void load_llvm_pass(aflcc_state_t *aflcc, u8 *pass) {

#if LLVM_MAJOR >= 11                                /* use new pass manager */
  #if LLVM_MAJOR < 16
  insert_param(aflcc, "-fexperimental-new-pass-manager");
  #endif
  insert_object(aflcc, pass, "-fpass-plugin=%s", 0);
#else
  insert_param(aflcc, "-Xclang");
  insert_param(aflcc, "-load");
  insert_param(aflcc, "-Xclang");
  insert_object(aflcc, pass, 0, 0);
#endif

}

static inline void debugf_args(int argc, char **argv) {

  DEBUGF("cd '%s';", getthecwd());
  for (int i = 0; i < argc; i++)
    SAYF(" '%s'", argv[i]);
  SAYF("\n");
  fflush(stdout);
  fflush(stderr);

}

void mode_setting(aflcc_state_t *);
void mode_notification(aflcc_state_t *);

void add_real_argv0(aflcc_state_t *);

void add_defs_common(aflcc_state_t *);
void add_defs_fortify(aflcc_state_t *, u8);
void add_defs_lsan_ctrl(aflcc_state_t *);

param_st parse_fsanitize(aflcc_state_t *, u8 *, u8);
void     add_sanitizers(aflcc_state_t *, char **envp);

param_st parse_misc_params(aflcc_state_t *, u8 *, u8);
void     add_misc_params(aflcc_state_t *);

param_st parse_linking_params(aflcc_state_t *, u8 *, u8, u8 *skip_next,
                              char **argv);

void add_lto_linker(aflcc_state_t *);
void add_lto_passes(aflcc_state_t *);
void add_runtime(aflcc_state_t *);

/** Global declarations -----END----- **/

/*
  Init global state struct. We also extract the callname,
  check debug options and if in C++ mode here.
*/
void aflcc_state_init(aflcc_state_t *aflcc, u8 *argv0) {

  // Default NULL/0 is a good start
  memset(aflcc, 0, sizeof(aflcc_state_t));

  aflcc->cc_params = ck_alloc(MAX_PARAMS_NUM * sizeof(u8 *));
  aflcc->cc_par_cnt = 1;

  aflcc->lto_flag = AFL_CLANG_FLTO;

  // aflcc->march_opt = CFLAGS_OPT;

  /* callname & if C++ mode */

  aflcc->argv0 = ck_strdup(argv0);

  char *cname = NULL;

  if ((cname = strrchr(aflcc->argv0, '/')) != NULL) {

    cname++;

  } else {

    cname = aflcc->argv0;

  }

  aflcc->callname = cname;

  if (strlen(cname) > 2 && (strncmp(cname + strlen(cname) - 2, "++", 2) == 0 ||
                            strstr(cname, "-g++") != NULL)) {

    aflcc->plusplus_mode = 1;

  }

  /* debug */

  if (getenv("AFL_DEBUG")) {

    aflcc->debug = 1;
    if (strcmp(getenv("AFL_DEBUG"), "0") == 0) unsetenv("AFL_DEBUG");

  } else if (getenv("AFL_QUIET")) {

    be_quiet = 1;

  }

  if ((getenv("AFL_PASSTHROUGH") || getenv("AFL_NOOPT")) && (!aflcc->debug)) {

    be_quiet = 1;

  }

}

/*
  Try to find a specific runtime we need, in here:

  1. firstly we check the $AFL_PATH environment variable location if set
  2. next we check argv[0] if it has path information and use it
    a) we also check ../lib/afl
  3. if 2. failed we check /proc (only Linux, Android, NetBSD, DragonFly, and
     FreeBSD with procfs)
    a) and check here in ../lib/afl too
  4. we look into the AFL_PATH define (usually /usr/local/lib/afl)
  5. we finally try the current directory

  if all these attempts fail - we return NULL and the caller has to decide
  what to do. Otherwise the path to obj would be allocated and returned.
*/
u8 *find_object(aflcc_state_t *aflcc, u8 *obj) {

  u8 *argv0 = aflcc->argv0;

  u8 *afl_path = getenv("AFL_PATH");
  u8 *slash = NULL, *tmp;

  if (afl_path) {

    tmp = alloc_printf("%s/%s", afl_path, obj);

    if (aflcc->debug) DEBUGF("Trying %s\n", tmp);

    if (!access(tmp, R_OK)) { return tmp; }

    ck_free(tmp);

  }

  if (argv0) {

    slash = strrchr(argv0, '/');

    if (slash) {

      u8 *dir = ck_strdup(argv0);

      slash = strrchr(dir, '/');
      *slash = 0;

      tmp = alloc_printf("%s/%s", dir, obj);

      if (aflcc->debug) DEBUGF("Trying %s\n", tmp);

      if (!access(tmp, R_OK)) {

        ck_free(dir);
        return tmp;

      }

      ck_free(tmp);
      tmp = alloc_printf("%s/../lib/afl/%s", dir, obj);

      if (aflcc->debug) DEBUGF("Trying %s\n", tmp);

      if (!access(tmp, R_OK)) {

        ck_free(dir);
        return tmp;

      }

      ck_free(tmp);
      ck_free(dir);

    }

#if defined(__FreeBSD__) || defined(__DragonFly__) || defined(__linux__) || \
    defined(__ANDROID__) || defined(__NetBSD__)
  #define HAS_PROC_FS 1
#endif
#ifdef HAS_PROC_FS
    else {

      char *procname = NULL;
  #if defined(__FreeBSD__) || defined(__DragonFly__)
      procname = "/proc/curproc/file";
  #elif defined(__linux__) || defined(__ANDROID__)
      procname = "/proc/self/exe";
  #elif defined(__NetBSD__)
      procname = "/proc/curproc/exe";
  #endif
      if (procname) {

        char    exepath[PATH_MAX];
        ssize_t exepath_len = readlink(procname, exepath, sizeof(exepath));
        if (exepath_len > 0 && exepath_len < PATH_MAX) {

          exepath[exepath_len] = 0;
          slash = strrchr(exepath, '/');

          if (slash) {

            *slash = 0;
            tmp = alloc_printf("%s/%s", exepath, obj);

            if (aflcc->debug) DEBUGF("Trying %s\n", tmp);

            if (!access(tmp, R_OK)) { return tmp; }

            ck_free(tmp);
            tmp = alloc_printf("%s/../lib/afl/%s", exepath, obj);

            if (aflcc->debug) DEBUGF("Trying %s\n", tmp);

            if (!access(tmp, R_OK)) { return tmp; }

            ck_free(tmp);

          }

        }

      }

    }

#endif
#undef HAS_PROC_FS

  }

  tmp = alloc_printf("%s/%s", AFL_PATH, obj);

  if (aflcc->debug) DEBUGF("Trying %s\n", tmp);

  if (!access(tmp, R_OK)) { return tmp; }

  ck_free(tmp);
  tmp = alloc_printf("./%s", obj);

  if (aflcc->debug) DEBUGF("Trying %s\n", tmp);

  if (!access(tmp, R_OK)) { return tmp; }

  ck_free(tmp);

  if (aflcc->debug) DEBUGF("Trying ... giving up\n");

  return NULL;

}

/*
  Deduce some info about compiler toolchains in current system,
  from the building results of AFL++
*/
void find_built_deps(aflcc_state_t *aflcc) {

  char *ptr = NULL;

#if defined(__x86_64__) || defined(__i386__)
  if ((ptr = find_object(aflcc, "afl-as")) != NULL) {

  #ifndef __APPLE__
    // on OSX clang masquerades as GCC
    aflcc->have_gcc = 1;
  #endif
    aflcc->have_clang = 1;
    ck_free(ptr);

  }

#endif

  if ((ptr = find_object(aflcc, "SanitizerCoveragePCGUARD.so")) != NULL) {

    aflcc->have_optimized_pcguard = 1;
    ck_free(ptr);

  }

#if (LLVM_MAJOR >= 3)

  if ((ptr = find_object(aflcc, "SanitizerCoverageLTO.so")) != NULL) {

    aflcc->have_lto = 1;
    ck_free(ptr);

  }

  if ((ptr = find_object(aflcc, "cmplog-routines-pass.so")) != NULL) {

    aflcc->have_llvm = 1;
    ck_free(ptr);

  }

#endif

#ifdef __ANDROID__
  aflcc->have_llvm = 1;
#endif

  if ((ptr = find_object(aflcc, "afl-gcc-pass.so")) != NULL) {

    aflcc->have_gcc_plugin = 1;
    ck_free(ptr);

  }

#if !defined(__ANDROID__) && !defined(ANDROID)
  ptr = find_object(aflcc, "afl-compiler-rt.o");

  if (!ptr) {

    FATAL(
        "Unable to find 'afl-compiler-rt.o'. Please set the AFL_PATH "
        "environment variable.");

  }

  if (aflcc->debug) { DEBUGF("rt=%s\n", ptr); }

  ck_free(ptr);
#endif

}

/** compiler_mode & instrument_mode selecting -----BEGIN----- **/

void mode_setting(aflcc_state_t *aflcc) {

#if (LLVM_MAJOR >= 3)
  aflcc->compiler_mode = LTO;
  aflcc->instrument_mode = INSTRUMENT_PCGUARD;
  aflcc->lto_mode = 1;
#else
  #error LTO MODE NOT SUPPORTED
#endif

#ifndef AFL_CLANG_FLTO
  FATAL(
      "instrumentation mode LTO specified but LLVM support not available "
      "(requires LLVM 13 or higher)");
#endif

  if (!aflcc->have_lto)
    FATAL(
        "LTO mode is not available, please install LLVM 13+ and lld of the "
        "same version and recompile AFL++");

  if (aflcc->lto_flag[0] != '-')
    FATAL(
        "Using afl-clang-lto is not possible because Makefile magic did not "
        "identify the correct -flto flag");

  if (getenv("AFL_PASSTHROUGH") || getenv("AFL_NOOPT")) {

    aflcc->passthrough = 1;

  }

  if (getenv("AFL_LLVM_INSTRUMENT_FILE") || getenv("AFL_LLVM_WHITELIST") ||
      getenv("AFL_LLVM_ALLOWLIST") || getenv("AFL_LLVM_DENYLIST") ||
      getenv("AFL_LLVM_BLOCKLIST")) {

    aflcc->have_instr_env = 1;

  }

  if (aflcc->have_instr_env && getenv("AFL_DONT_OPTIMIZE") && !be_quiet) {

    WARNF(
        "AFL_LLVM_ALLOWLIST/DENYLIST and AFL_DONT_OPTIMIZE cannot be combined "
        "for file matching, only function matching!");

  }

}

/*
  Print welcome message on screen, giving brief notes about
  compiler_mode and instrument_mode.
*/
void mode_notification(aflcc_state_t *aflcc) {

  if ((isatty(2) && !be_quiet) || aflcc->debug) {

    SAYF(cCYA
         "afl-cc" VERSION cRST
         " by Michal Zalewski, Laszlo Szekeres, Marc Heuse - mode: %s-%s\n",
         compiler_mode_2str(aflcc->compiler_mode), 
         instrument_mode_2str(aflcc->instrument_mode));

  }

}

/*
  Set argv[0] required by execvp. It can be
  - specified by env AFL_CXX
  - CLANGPP_BIN or LLVM_BINDIR/clang++
  when in C++ mode, or
  - specified by env AFL_CC
  - CLANG_BIN or LLVM_BINDIR/clang
  otherwise.
*/
void add_real_argv0(aflcc_state_t *aflcc) {

  static u8 llvm_fullpath[PATH_MAX];

  if (aflcc->plusplus_mode) {

    u8 *alt_cxx = getenv("AFL_CXX");

    if (!alt_cxx) {

      if (USE_BINDIR)
        snprintf(llvm_fullpath, sizeof(llvm_fullpath), "%s/clang++",
                  LLVM_BINDIR);
      else
        snprintf(llvm_fullpath, sizeof(llvm_fullpath), CLANGPP_BIN);
      alt_cxx = llvm_fullpath;

    }

    aflcc->cc_params[0] = alt_cxx;

  } else {

    u8 *alt_cc = getenv("AFL_CC");

    if (!alt_cc) {

      if (USE_BINDIR)
        snprintf(llvm_fullpath, sizeof(llvm_fullpath), "%s/clang",
                  LLVM_BINDIR);
      else
        snprintf(llvm_fullpath, sizeof(llvm_fullpath), CLANG_BIN);
      alt_cc = llvm_fullpath;

    }

    aflcc->cc_params[0] = alt_cc;

  }

}

/** compiler_mode & instrument_mode selecting -----END----- **/

/** Macro defs for the preprocessor -----BEGIN----- **/

void add_defs_common(aflcc_state_t *aflcc) {

  insert_param(aflcc, "-D__AFL_COMPILER=1");
  insert_param(aflcc, "-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1");

}

/*
  Control macro def of _FORTIFY_SOURCE. It will do nothing
  if we detect this routine has been called previously, or
  the macro already here in these existing args.
*/
void add_defs_fortify(aflcc_state_t *aflcc, u8 action) {

  if (aflcc->have_fortify) { return; }

  switch (action) {

    case 1:
      insert_param(aflcc, "-D_FORTIFY_SOURCE=1");
      break;

    case 2:
      insert_param(aflcc, "-D_FORTIFY_SOURCE=2");
      break;

    default:  // OFF
      insert_param(aflcc, "-U_FORTIFY_SOURCE");
      break;

  }

  aflcc->have_fortify = 1;

}

/* Macro defs of __AFL_LEAK_CHECK, __AFL_LSAN_ON and __AFL_LSAN_OFF */
void add_defs_lsan_ctrl(aflcc_state_t *aflcc) {

  insert_param(aflcc, "-includesanitizer/lsan_interface.h");
  insert_param(
      aflcc,
      "-D__AFL_LEAK_CHECK()={if(__lsan_do_recoverable_leak_check() > 0) "
      "_exit(23); }");
  insert_param(aflcc, "-D__AFL_LSAN_OFF()=__lsan_disable();");
  insert_param(aflcc, "-D__AFL_LSAN_ON()=__lsan_enable();");

}

/** Macro defs for the preprocessor -----END----- **/

/** About -fsanitize -----BEGIN----- **/

/* For input "-fsanitize=...", it:

  1. may have various OOB traps :) if ... doesn't contain ',' or
    the input has bad syntax such as "-fsantiz=,"
  2. strips any fuzzer* in ... and writes back (may result in "-fsanitize=")
  3. rets 1 if exactly "fuzzer" found, otherwise rets 0
*/
static u8 fsanitize_fuzzer_comma(char *string) {

  u8 detect_single_fuzzer = 0;

  char *p, *ptr = string + strlen("-fsanitize=");
  // ck_alloc will check alloc failure
  char *new = ck_alloc(strlen(string) + 1);
  char *tmp = ck_alloc(strlen(ptr) + 1);
  u32   count = 0, len, ende = 0;

  strcpy(new, "-fsanitize=");

  do {

    p = strchr(ptr, ',');
    if (!p) {

      p = ptr + strlen(ptr) + 1;
      ende = 1;

    }

    len = p - ptr;
    if (len) {

      strncpy(tmp, ptr, len);
      tmp[len] = 0;
      // fprintf(stderr, "Found: %s\n", tmp);
      ptr += len + 1;
      if (*tmp) {

        u32 copy = 1;
        if (!strcmp(tmp, "fuzzer")) {

          detect_single_fuzzer = 1;
          copy = 0;

        } else if (!strncmp(tmp, "fuzzer", 6)) {

          copy = 0;

        }

        if (copy) {

          if (count) { strcat(new, ","); }
          strcat(new, tmp);
          ++count;

        }

      }

    } else {

      ptr++;

    }

  } while (!ende);

  strcpy(string, new);

  ck_free(tmp);
  ck_free(new);

  return detect_single_fuzzer;

}

/*
  Parse and process possible -fsanitize related args, return PARAM_MISS
  if nothing matched. We have 3 main tasks here for these args:
  - Check which one of those sanitizers present here.
  - Check if libfuzzer present. We need to block the request of enable
    libfuzzer, and link harness with our libAFLDriver.a later.
  - Check if SanCov allow/denylist options present. We need to try switching
    to LLVMNATIVE instead of using our optimized PCGUARD anyway. If we
    can't make it finally for various reasons, just drop these options.
*/
param_st parse_fsanitize(aflcc_state_t *aflcc, u8 *cur_argv, u8 scan) {

  param_st final_ = PARAM_MISS;

// MACRO START
#define HAVE_SANITIZER_SCAN_KEEP(v, k)        \
  do {                                        \
                                              \
    if (strstr(cur_argv, "=" STRINGIFY(k)) || \
        strstr(cur_argv, "," STRINGIFY(k))) { \
                                              \
      if (scan) {                             \
                                              \
        aflcc->have_##v = 1;                  \
        final_ = PARAM_SCAN;                  \
                                              \
      } else {                                \
                                              \
        final_ = PARAM_KEEP;                  \
                                              \
      }                                       \
                                              \
    }                                         \
                                              \
  } while (0)

  // MACRO END

  if (!strncmp(cur_argv, "-fsanitize=", strlen("-fsanitize="))) {

    HAVE_SANITIZER_SCAN_KEEP(asan, address);
    HAVE_SANITIZER_SCAN_KEEP(msan, memory);
    HAVE_SANITIZER_SCAN_KEEP(ubsan, undefined);
    HAVE_SANITIZER_SCAN_KEEP(tsan, thread);
    HAVE_SANITIZER_SCAN_KEEP(lsan, leak);
    HAVE_SANITIZER_SCAN_KEEP(cfisan, cfi);

  }

#undef HAVE_SANITIZER_SCAN_KEEP

  // We can't use a "else if" there, because some of the following
  // matching rules overlap with those in the if-statement above.
  if (!strcmp(cur_argv, "-fsanitize=fuzzer")) {

    if (scan) {

      aflcc->need_aflpplib = 1;
      final_ = PARAM_SCAN;

    } else {

      final_ = PARAM_DROP;

    }

  } else if (!strncmp(cur_argv, "-fsanitize=", strlen("-fsanitize=")) &&

             strchr(cur_argv, ',') &&
             !strstr(cur_argv, "=,")) {  // avoid OOB errors

    if (scan) {

      u8 *cur_argv_ = ck_strdup(cur_argv);

      if (fsanitize_fuzzer_comma(cur_argv_)) {

        aflcc->need_aflpplib = 1;
        final_ = PARAM_SCAN;

      }

      ck_free(cur_argv_);

    } else {

      fsanitize_fuzzer_comma(cur_argv);
      if (!cur_argv || strlen(cur_argv) <= strlen("-fsanitize="))
        final_ = PARAM_DROP;  // this means it only has "fuzzer" previously.

    }

  } else if (!strncmp(cur_argv, "-fsanitize-coverage-", 20) &&

             strstr(cur_argv, "list=")) {

    if (scan) {

      aflcc->have_instr_list = 1;
      final_ = PARAM_SCAN;

    } else {

      if (aflcc->instrument_mode != INSTRUMENT_LLVMNATIVE) {

        if (!be_quiet) { WARNF("Found '%s' - stripping!", cur_argv); }
        final_ = PARAM_DROP;

      } else {

        final_ = PARAM_KEEP;

      }

    }

  }

  if (final_ == PARAM_KEEP) insert_param(aflcc, cur_argv);

  return final_;

}

/*
  Add params for sanitizers. Here we need to consider:
  - Use static runtime for asan, as much as possible.
  - ASAN, MSAN, AFL_HARDEN are mutually exclusive.
  - Add options if not found there, on request of AFL_USE_ASAN, AFL_USE_MSAN,
  etc.
  - Update have_* so that functions called after this can have correct context.
    However this also means any functions called before should NOT depend on
  these have_*, otherwise they may not work as expected.
*/
void add_sanitizers(aflcc_state_t *aflcc, char **envp) {

  if (getenv("AFL_USE_ASAN") || aflcc->have_asan) {

    if (getenv("AFL_USE_MSAN") || aflcc->have_msan)
      FATAL("ASAN and MSAN are mutually exclusive");

    if (getenv("AFL_HARDEN"))
      FATAL("ASAN and AFL_HARDEN are mutually exclusive");

    if (aflcc->compiler_mode == GCC_PLUGIN && !aflcc->have_staticasan) {

      insert_param(aflcc, "-static-libasan");

    }

    add_defs_fortify(aflcc, 0);
    if (!aflcc->have_asan) {

      insert_param(aflcc, "-fsanitize=address");
      insert_param(aflcc, "-fno-common");

    }

    aflcc->have_asan = 1;

  } else if (getenv("AFL_USE_MSAN") || aflcc->have_msan) {

    if (getenv("AFL_USE_ASAN") || aflcc->have_asan)
      FATAL("ASAN and MSAN are mutually exclusive");

    if (getenv("AFL_HARDEN"))
      FATAL("MSAN and AFL_HARDEN are mutually exclusive");

    add_defs_fortify(aflcc, 0);
    if (!aflcc->have_msan) { insert_param(aflcc, "-fsanitize=memory"); }
    aflcc->have_msan = 1;

  }

  if (getenv("AFL_USE_UBSAN") || aflcc->have_ubsan) {

    if (!aflcc->have_ubsan) {

      insert_param(aflcc, "-fsanitize=undefined");
      insert_param(aflcc, "-fsanitize-undefined-trap-on-error");
      insert_param(aflcc, "-fno-sanitize-recover=all");

    }

    if (!aflcc->have_fp) {

      insert_param(aflcc, "-fno-omit-frame-pointer");
      aflcc->have_fp = 1;

    }

    aflcc->have_ubsan = 1;

  }

  if (getenv("AFL_USE_TSAN") || aflcc->have_tsan) {

    if (!aflcc->have_fp) {

      insert_param(aflcc, "-fno-omit-frame-pointer");
      aflcc->have_fp = 1;

    }

    if (!aflcc->have_tsan) { insert_param(aflcc, "-fsanitize=thread"); }
    aflcc->have_tsan = 1;

  }

  if (getenv("AFL_USE_LSAN") && !aflcc->have_lsan) {

    insert_param(aflcc, "-fsanitize=leak");
    add_defs_lsan_ctrl(aflcc);
    aflcc->have_lsan = 1;

  }

  if (getenv("AFL_USE_CFISAN") || aflcc->have_cfisan) {

    if (aflcc->compiler_mode == GCC_PLUGIN || aflcc->compiler_mode == GCC) {

      if (!aflcc->have_fcf) { insert_param(aflcc, "-fcf-protection=full"); }

    } else {

      if (!aflcc->lto_mode && !aflcc->have_flto) {

        uint32_t i = 0, found = 0;
        while (envp[i] != NULL && !found) {

          if (strncmp("-flto", envp[i++], 5) == 0) found = 1;

        }

        if (!found) { insert_param(aflcc, "-flto"); }
        aflcc->have_flto = 1;

      }

      if (!aflcc->have_cfisan) { insert_param(aflcc, "-fsanitize=cfi"); }

      if (!aflcc->have_hidden) {

        insert_param(aflcc, "-fvisibility=hidden");
        aflcc->have_hidden = 1;

      }

      aflcc->have_cfisan = 1;

    }

  }

}

/* Add params to enable LLVM SanCov, the native PCGUARD */
void add_native_pcguard(aflcc_state_t *aflcc) {

  /* If there is a rust ASan runtime on the command line, it is likely we're
   * linking from rust and adding native flags requiring the sanitizer runtime
   * will trigger native clang to add yet another runtime, causing linker
   * errors. For now we shouldn't add instrumentation here, we're linking
   * anyway.
   */
  if (aflcc->have_rust_asanrt) { return; }

  /* If llvm-config doesn't figure out LLVM_MAJOR, just
   go on anyway and let compiler complain if doesn't work. */

#if LLVM_MAJOR > 0 && LLVM_MAJOR < 6
  FATAL("pcguard instrumentation with pc-table requires LLVM 6.0.1+");
#else
  #if LLVM_MAJOR == 0
  WARNF(
      "pcguard instrumentation with pc-table requires LLVM 6.0.1+"
      " otherwise the compiler will fail");
  #endif
  if (aflcc->instrument_opt_mode & INSTRUMENT_OPT_CODECOV) {

    insert_param(aflcc,
                 "-fsanitize-coverage=trace-pc-guard,bb,no-prune,pc-table");

  } else {

    insert_param(aflcc, "-fsanitize-coverage=trace-pc-guard,pc-table");

  }

#endif

}

/** About -fsanitize -----END----- **/

/** Linking behaviors -----BEGIN----- **/

/*
  Parse and process possible linking stage related args,
  return PARAM_MISS if nothing matched.
*/
param_st parse_linking_params(aflcc_state_t *aflcc, u8 *cur_argv, u8 scan,
                              u8 *skip_next, char **argv) {

  if (aflcc->lto_mode && !strncmp(cur_argv, "-flto=thin", 10)) {

    FATAL(
        "afl-clang-lto cannot work with -flto=thin. Switch to -flto=full or "
        "use afl-clang-fast!");

  }

  param_st final_ = PARAM_MISS;

  if (!strcmp(cur_argv, "-shared") || !strcmp(cur_argv, "-dynamiclib")) {

    if (scan) {

      aflcc->shared_linking = 1;
      final_ = PARAM_SCAN;

    } else {

      final_ = PARAM_KEEP;

    }

  } else if (!strcmp(cur_argv, "-Wl,-r") || !strcmp(cur_argv, "-Wl,-i") ||

             !strcmp(cur_argv, "-Wl,--relocatable") ||
             !strcmp(cur_argv, "-r") || !strcmp(cur_argv, "--relocatable")) {

    if (scan) {

      aflcc->partial_linking = 1;
      final_ = PARAM_SCAN;

    } else {

      final_ = PARAM_KEEP;

    }

  } else if (!strncmp(cur_argv, "-fuse-ld=", 9) ||

             !strncmp(cur_argv, "--ld-path=", 10)) {

    if (scan) {

      final_ = PARAM_SCAN;

    } else {

      if (aflcc->lto_mode)
        final_ = PARAM_DROP;
      else
        final_ = PARAM_KEEP;

    }

  } else if (!strcmp(cur_argv, "-Wl,-z,defs") ||

             !strcmp(cur_argv, "-Wl,--no-undefined") ||
             !strcmp(cur_argv, "-Wl,-no-undefined") ||
             !strcmp(cur_argv, "--no-undefined") ||
             strstr(cur_argv, "afl-compiler-rt") ||
             strstr(cur_argv, "afl-llvm-rt")) {

    if (scan) {

      final_ = PARAM_SCAN;

    } else {

      final_ = PARAM_DROP;

    }

  } else if (!strcmp(cur_argv, "-z") || !strcmp(cur_argv, "-Wl,-z")) {

    u8 *param = *(argv + 1);
    if (param && (!strcmp(param, "defs") || !strcmp(param, "-Wl,defs"))) {

      *skip_next = 1;

      if (scan) {

        final_ = PARAM_SCAN;

      } else {

        final_ = PARAM_DROP;

      }

    }

  }

  // Try to warn user for some unsupported cases
  if (scan && final_ == PARAM_MISS) {

    u8 *ptr_ = NULL;

    if (!strcmp(cur_argv, "-Xlinker") && (ptr_ = *(argv + 1))) {

      if (!strcmp(ptr_, "defs")) {

        WARNF("'-Xlinker' 'defs' detected. This may result in a bad link.");

      } else if (strstr(ptr_, "-no-undefined")) {

        WARNF(
            "'-Xlinker' '%s' detected. The latter option may be dropped and "
            "result in a bad link.",
            ptr_);

      }

    } else if (!strncmp(cur_argv, "-Wl,", 4) &&

               (u8 *)strrchr(cur_argv, ',') != (cur_argv + 3)) {

      ptr_ = cur_argv + 4;

      if (strstr(ptr_, "-shared") || strstr(ptr_, "-dynamiclib")) {

        WARNF(
            "'%s': multiple link options after '-Wl,' may break shared "
            "linking.",
            ptr_);

      }

      if (strstr(ptr_, "-r,") || strstr(ptr_, "-i,") || strstr(ptr_, ",-r") ||
          strstr(ptr_, ",-i") || strstr(ptr_, "--relocatable")) {

        WARNF(
            "'%s': multiple link options after '-Wl,' may break partial "
            "linking.",
            ptr_);

      }

      if (strstr(ptr_, "defs") || strstr(ptr_, "no-undefined")) {

        WARNF(
            "'%s': multiple link options after '-Wl,' may enable report "
            "unresolved symbol references and result in a bad link.",
            ptr_);

      }

    }

  }

  if (final_ == PARAM_KEEP) insert_param(aflcc, cur_argv);

  return final_;

}

/* Add params to specify the linker used in LTO */
void add_lto_linker(aflcc_state_t *aflcc) {

  unsetenv("AFL_LD");
  unsetenv("AFL_LD_CALLER");

  u8 *ld_path = NULL;
  if (getenv("AFL_REAL_LD")) {

    ld_path = strdup(getenv("AFL_REAL_LD"));

  } else {

    ld_path = strdup(AFL_REAL_LD);

  }

  if (!ld_path || !*ld_path) {

    if (ld_path) {

      // Freeing empty string
      free(ld_path);

    }

    ld_path = strdup("ld.lld");

  }

  if (!ld_path) { PFATAL("Could not allocate mem for ld_path"); }
#if defined(AFL_CLANG_LDPATH) && LLVM_MAJOR >= 12
  insert_param(aflcc, alloc_printf("--ld-path=%s", ld_path));
#else
  insert_param(aflcc, alloc_printf("-fuse-ld=%s", ld_path));
#endif
  free(ld_path);

}

/* Add params to launch SanitizerCoverageLTO.so when linking  */
void add_lto_passes(aflcc_state_t *aflcc) {

#if defined(AFL_CLANG_LDPATH) && LLVM_MAJOR >= 15
  // The NewPM implementation only works fully since LLVM 15.
  insert_object(aflcc, "SanitizerCoverageLTO.so", "-Wl,--load-pass-plugin=%s",
                0);
#elif defined(AFL_CLANG_LDPATH) && LLVM_MAJOR >= 13
  insert_param(aflcc, "-Wl,--lto-legacy-pass-manager");
  insert_object(aflcc, "SanitizerCoverageLTO.so", "-Wl,-mllvm=-load=%s", 0);
#else
  insert_param(aflcc, "-fno-experimental-new-pass-manager");
  insert_object(aflcc, "SanitizerCoverageLTO.so", "-Wl,-mllvm=-load=%s", 0);
#endif

  insert_param(aflcc, "-Wl,--allow-multiple-definition");

}

/* Add params to link with libAFLDriver.a on request */
static void add_aflpplib(aflcc_state_t *aflcc) {

  if (!aflcc->need_aflpplib) return;

  u8 *afllib = find_object(aflcc, "libAFLDriver.a");

  if (!be_quiet) {

    OKF("Found '-fsanitize=fuzzer', replacing with libAFLDriver.a");

  }

  if (!afllib) {

    if (!be_quiet) {

      WARNF(
          "Cannot find 'libAFLDriver.a' to replace '-fsanitize=fuzzer' in "
          "the flags - this will fail!");

    }

  } else {

    insert_param(aflcc, afllib);

#ifdef __APPLE__
    insert_param(aflcc, "-Wl,-undefined,dynamic_lookup");
#endif

  }

}

/* Add params to link with runtimes depended by our instrumentation */
void add_runtime(aflcc_state_t *aflcc) {

  if (aflcc->preprocessor_only || aflcc->have_c || !aflcc->non_dash) {

    /* In the preprocessor_only case (-E), we are not actually compiling at
       all but requesting the compiler to output preprocessed sources only.
       We must not add the runtime in this case because the compiler will
       simply output its binary content back on stdout, breaking any build
       systems that rely on a separate source preprocessing step. */
    return;

  }

  if (aflcc->compiler_mode != GCC_PLUGIN && aflcc->compiler_mode != GCC &&
      !getenv("AFL_LLVM_NO_RPATH")) {

    // in case LLVM is installed not via a package manager or "make install"
    // e.g. compiled download or compiled from github then its ./lib directory
    // might not be in the search path. Add it if so.
    const char *libdir = LLVM_LIBDIR;
    if (aflcc->plusplus_mode && strlen(libdir) && strncmp(libdir, "/usr", 4) &&
        strncmp(libdir, "/lib", 4)) {

#ifdef __APPLE__
      u8 *libdir_opt = strdup("-Wl,-rpath," LLVM_LIBDIR);
#else
      u8 *libdir_opt = strdup("-Wl,-rpath=" LLVM_LIBDIR);
#endif
      insert_param(aflcc, libdir_opt);

    }

  }

#ifndef __ANDROID__

  #define M32_ERR_MSG "-m32 is not supported by your compiler"
  #define M64_ERR_MSG "-m64 is not supported by your compiler"

  if (aflcc->compiler_mode != GCC && aflcc->compiler_mode != CLANG) {

    switch (aflcc->bit_mode) {

      case 0:
        if (!aflcc->shared_linking && !aflcc->partial_linking)
          insert_object(aflcc, "afl-compiler-rt.o", 0, 0);
        if (aflcc->lto_mode) insert_object(aflcc, "afl-llvm-rt-lto.o", 0, 0);
        break;

      case 32:
        if (!aflcc->shared_linking && !aflcc->partial_linking)
          insert_object(aflcc, "afl-compiler-rt-32.o", 0, M32_ERR_MSG);
        if (aflcc->lto_mode)
          insert_object(aflcc, "afl-llvm-rt-lto-32.o", 0, M32_ERR_MSG);
        break;

      case 64:
        if (!aflcc->shared_linking && !aflcc->partial_linking)
          insert_object(aflcc, "afl-compiler-rt-64.o", 0, M64_ERR_MSG);
        if (aflcc->lto_mode)
          insert_object(aflcc, "afl-llvm-rt-lto-64.o", 0, M64_ERR_MSG);
        break;

    }

  #if !defined(__APPLE__) && !defined(__sun)
    if (!aflcc->shared_linking && !aflcc->partial_linking)
      insert_object(aflcc, "dynamic_list.txt", "-Wl,--dynamic-list=%s", 0);
  #endif

  #if defined(__APPLE__)
    if (aflcc->shared_linking || aflcc->partial_linking) {

      insert_param(aflcc, "-Wl,-U");
      insert_param(aflcc, "-Wl,___afl_area_ptr");
      insert_param(aflcc, "-Wl,-U");
      insert_param(aflcc, "-Wl,___sanitizer_cov_trace_pc_guard_init");

    }

  #endif

  }

#endif

  add_aflpplib(aflcc);

#if defined(USEMMAP) && !defined(__HAIKU__) && !__APPLE__
  insert_param(aflcc, "-Wl,-lrt");
#endif

}

/** Linking behaviors -----END----- **/

/** Miscellaneous routines -----BEGIN----- **/

char *get_opt_level() {

  static char levels[8][8] = {"-O0", "-O1", "-O2",    "-O3",
                              "-Oz", "-Os", "-Ofast", "-Og"};
  switch (opt_level) {

    case '0':
      return levels[0];
    case '1':
      return levels[1];
    case '2':
      return levels[2];
    case 'z':
      return levels[4];
    case 's':
      return levels[5];
    case 'f':
      return levels[6];
    case 'g':
      return levels[7];
    default:
      return levels[3];

  }

}

/* Add some miscellaneous params required by our instrumentation. */
void add_misc_params(aflcc_state_t *aflcc) {

  if (getenv("AFL_NO_BUILTIN") || getenv("AFL_LLVM_LAF_TRANSFORM_COMPARES") ||
      getenv("AFL_LLVM_LAF_ALL") || getenv("AFL_LLVM_CMPLOG") ||
      aflcc->lto_mode) {

    insert_param(aflcc, "-fno-builtin-strcmp");
    insert_param(aflcc, "-fno-builtin-strncmp");
    insert_param(aflcc, "-fno-builtin-strcasecmp");
    insert_param(aflcc, "-fno-builtin-strncasecmp");
    insert_param(aflcc, "-fno-builtin-memcmp");
    insert_param(aflcc, "-fno-builtin-bcmp");
    insert_param(aflcc, "-fno-builtin-strstr");
    insert_param(aflcc, "-fno-builtin-strcasestr");

  }

  if (!aflcc->have_pic) { insert_param(aflcc, "-fPIC"); }

  if (getenv("AFL_HARDEN")) {

    insert_param(aflcc, "-fstack-protector-all");

    if (!aflcc->fortify_set) add_defs_fortify(aflcc, 2);

  }

  if (!getenv("AFL_DONT_OPTIMIZE")) {

    insert_param(aflcc, "-g");
    if (!aflcc->have_o) insert_param(aflcc, get_opt_level());
    if (!aflcc->have_unroll) insert_param(aflcc, "-funroll-loops");
    // if (strlen(aflcc->march_opt) > 1 && aflcc->march_opt[0] == '-')
    //     insert_param(aflcc, aflcc->march_opt);

  }

  if (aflcc->x_set) {

    insert_param(aflcc, "-x");
    insert_param(aflcc, "none");

  }

}

/*
  Parse and process a variety of args under our matching rules,
  return PARAM_MISS if nothing matched.
*/
param_st parse_misc_params(aflcc_state_t *aflcc, u8 *cur_argv, u8 scan) {

  param_st final_ = PARAM_MISS;

// MACRO START
#define SCAN_KEEP(dst, src) \
  do {                      \
                            \
    if (scan) {             \
                            \
      dst = src;            \
      final_ = PARAM_SCAN;  \
                            \
    } else {                \
                            \
      final_ = PARAM_KEEP;  \
                            \
    }                       \
                            \
  } while (0)

  // MACRO END

  if (!strncasecmp(cur_argv, "-fpic", 5)) {

    SCAN_KEEP(aflcc->have_pic, 1);

  } else if (!strcmp(cur_argv, "-m32") ||

             !strcmp(cur_argv, "armv7a-linux-androideabi")) {

    SCAN_KEEP(aflcc->bit_mode, 32);

  } else if (!strcmp(cur_argv, "-m64")) {

    SCAN_KEEP(aflcc->bit_mode, 64);

  } else if (strstr(cur_argv, "FORTIFY_SOURCE")) {

    SCAN_KEEP(aflcc->fortify_set, 1);

  } else if (!strcmp(cur_argv, "-x")) {

    SCAN_KEEP(aflcc->x_set, 1);

  } else if (!strcmp(cur_argv, "-E")) {

    SCAN_KEEP(aflcc->preprocessor_only, 1);

  } else if (!strcmp(cur_argv, "--target=wasm32-wasi")) {

    SCAN_KEEP(aflcc->passthrough, 1);

  } else if (!strcmp(cur_argv, "-c")) {

    SCAN_KEEP(aflcc->have_c, 1);

  } else if (!strcmp(cur_argv, "-static-libasan")) {

    SCAN_KEEP(aflcc->have_staticasan, 1);

  } else if (strstr(cur_argv, "librustc") && strstr(cur_argv, "_rt.asan.a")) {

    SCAN_KEEP(aflcc->have_rust_asanrt, 1);

  } else if (!strcmp(cur_argv, "-fno-omit-frame-pointer")) {

    SCAN_KEEP(aflcc->have_fp, 1);

  } else if (!strcmp(cur_argv, "-fvisibility=hidden")) {

    SCAN_KEEP(aflcc->have_hidden, 1);

  } else if (!strcmp(cur_argv, "-flto") || !strcmp(cur_argv, "-flto=full")) {

    SCAN_KEEP(aflcc->have_flto, 1);

  } else if (!strncmp(cur_argv, "-D_FORTIFY_SOURCE",

                      strlen("-D_FORTIFY_SOURCE"))) {

    SCAN_KEEP(aflcc->have_fortify, 1);

  } else if (!strncmp(cur_argv, "-fcf-protection", strlen("-fcf-protection"))) {

    SCAN_KEEP(aflcc->have_cfisan, 1);

  } else if (!strncmp(cur_argv, "-O", 2)) {

    SCAN_KEEP(aflcc->have_o, 1);

  } else if (!strncmp(cur_argv, "-funroll-loop", 13)) {

    SCAN_KEEP(aflcc->have_unroll, 1);

  } else if (!strncmp(cur_argv, "--afl", 5)) {

    if (scan)
      final_ = PARAM_SCAN;
    else
      final_ = PARAM_DROP;

  } else if (!strncmp(cur_argv, "-fno-unroll", 11)) {

    if (scan)
      final_ = PARAM_SCAN;
    else
      final_ = PARAM_DROP;

  } else if (!strcmp(cur_argv, "-pipe") && aflcc->compiler_mode == GCC_PLUGIN) {

    if (scan)
      final_ = PARAM_SCAN;
    else
      final_ = PARAM_DROP;

  } else if (!strncmp(cur_argv, "-stdlib=", 8) &&

             (aflcc->compiler_mode == GCC ||
              aflcc->compiler_mode == GCC_PLUGIN)) {

    if (scan) {

      final_ = PARAM_SCAN;

    } else {

      if (!be_quiet) WARNF("Found '%s' - stripping!", cur_argv);
      final_ = PARAM_DROP;

    }

  } else if (cur_argv[0] != '-') {

    /* It's a weak, loose pattern, with very different purpose
     than others. We handle it at last, cautiously and robustly. */

    if (scan && cur_argv[0] != '@')  // response file support
      aflcc->non_dash = 1;

  }

#undef SCAN_KEEP

  if (final_ == PARAM_KEEP) insert_param(aflcc, cur_argv);

  return final_;

}

/** Miscellaneous routines -----END----- **/

/* Print help message on request */
static void maybe_usage(aflcc_state_t *aflcc, int argc, char **argv) {

  if (argc < 2 || strncmp(argv[1], "-h", 2) == 0) {

    printf("afl-cc" VERSION
           " by Michal Zalewski, Laszlo Szekeres, Marc Heuse\n");

    SAYF(
        "\n"
        "afl-cc/afl-c++ [options]\n"
        "\n"
        "This is a helper application for afl-fuzz. It serves as a drop-in "
        "replacement\n"
        "for gcc and clang, letting you recompile third-party code with the "
        "required\n"
        "runtime instrumentation. A common use pattern would be one of the "
        "following:\n\n"

        "  CC=afl-cc CXX=afl-c++ ./configure --disable-shared\n"
        "  cmake -DCMAKE_C_COMPILERC=afl-cc -DCMAKE_CXX_COMPILER=afl-c++ .\n"
        "  CC=afl-cc CXX=afl-c++ meson\n\n");

    SAYF(
        "                                       |------------- FEATURES "
        "-------------|\n"
        "MODES:                                  NCC PERSIST DICT   LAF "
        "CMPLOG SELECT\n"
        "  [LLVM] LLVM:             %s%s\n"
        "      PCGUARD              %s yes yes     module yes yes    "
        "yes\n"
        "      NATIVE               AVAILABLE    no  yes     no     no  "
        "part.  yes\n"
        "      CLASSIC              %s no  yes     module yes yes    "
        "yes\n"
        "        - NORMAL\n"
        "        - CALLER\n"
        "        - CTX\n"
        "        - NGRAM-{2-16}\n"
        "  [LTO] LLVM LTO:          %s%s\n"
        "      PCGUARD              DEFAULT      yes yes     yes    yes yes "
        "   yes\n"
        "      CLASSIC                           yes yes     yes    yes yes "
        "   yes\n"
        "  [GCC_PLUGIN] gcc plugin: %s%s\n"
        "      CLASSIC              DEFAULT      no  yes     no     no  no     "
        "yes\n"
        "  [GCC/CLANG] simple gcc/clang: %s%s\n"
        "      CLASSIC              DEFAULT      no  no      no     no  no     "
        "no\n\n",
        aflcc->have_llvm ? "AVAILABLE   " : "unavailable!",
        aflcc->compiler_mode == LLVM ? " [SELECTED]" : "",
        aflcc->have_llvm ? "AVAILABLE   " : "unavailable!",
        aflcc->have_llvm ? "AVAILABLE   " : "unavailable!",
        aflcc->have_lto ? "AVAILABLE" : "unavailable!",
        aflcc->compiler_mode == LTO ? " [SELECTED]" : "",
        aflcc->have_gcc_plugin ? "AVAILABLE" : "unavailable!",
        aflcc->compiler_mode == GCC_PLUGIN ? " [SELECTED]" : "",
        aflcc->have_gcc && aflcc->have_clang
            ? "AVAILABLE"
            : (aflcc->have_gcc
                   ? "GCC ONLY "
                   : (aflcc->have_clang ? "CLANG ONLY" : "unavailable!")),
        (aflcc->compiler_mode == GCC || aflcc->compiler_mode == CLANG)
            ? " [SELECTED]"
            : "");

    SAYF(
        "Modes:\n"
        "  To select the compiler mode use a symlink version (e.g. "
        "afl-clang-fast), set\n"
        "  the environment variable AFL_CC_COMPILER to a mode (e.g. LLVM) or "
        "use the\n"
        "  command line parameter --afl-MODE (e.g. --afl-llvm). If none is "
        "selected,\n"
        "  afl-cc will select the best available (LLVM -> GCC_PLUGIN -> GCC).\n"
        "  The best is LTO but it often needs RANLIB and AR settings outside "
        "of afl-cc.\n\n");

#if LLVM_MAJOR >= 11 || (LLVM_MAJOR == 10 && LLVM_MINOR > 0)
  #define NATIVE_MSG                                                   \
    "  LLVM-NATIVE:  use llvm's native PCGUARD instrumentation (less " \
    "performant)\n"
#else
  #define NATIVE_MSG ""
#endif

    SAYF(
        "Sub-Modes: (set via env AFL_LLVM_INSTRUMENT, afl-cc selects the best "
        "available)\n"
        "  PCGUARD: Dominator tree instrumentation (best!) (README.llvm.md)\n"

        NATIVE_MSG

        "  CLASSIC: decision target instrumentation (README.llvm.md)\n"
        "  CALLER:  CLASSIC + single callee context "
        "(instrumentation/README.ctx.md)\n"
        "  CTX:     CLASSIC + full callee context "
        "(instrumentation/README.ctx.md)\n"
        "  NGRAM-x: CLASSIC + previous path "
        "((instrumentation/README.ngram.md)\n\n");

#undef NATIVE_MSG

    SAYF(
        "Features: (see documentation links)\n"
        "  NCC:    non-colliding coverage [automatic] (that is an amazing "
        "thing!)\n"
        "          (instrumentation/README.lto.md)\n"
        "  PERSIST: persistent mode support [code] (huge speed increase!)\n"
        "          (instrumentation/README.persistent_mode.md)\n"
        "  DICT:   dictionary in the target [yes=automatic or LLVM module "
        "pass]\n"
        "          (instrumentation/README.lto.md + "
        "instrumentation/README.llvm.md)\n"
        "  LAF:    comparison splitting [env] "
        "(instrumentation/README.laf-intel.md)\n"
        "  CMPLOG: input2state exploration [env] "
        "(instrumentation/README.cmplog.md)\n"
        "  SELECT: selective instrumentation (allow/deny) on filename or "
        "function [env]\n"
        "          (instrumentation/README.instrument_list.md)\n\n");

    if (argc < 2 || strncmp(argv[1], "-hh", 3)) {

      SAYF(
          "To see all environment variables for the configuration of afl-cc "
          "use \"-hh\".\n");

    } else {

      SAYF(
          "Environment variables used:\n"
          "  AFL_CC: path to the C compiler to use\n"
          "  AFL_CXX: path to the C++ compiler to use\n"
          "  AFL_DEBUG: enable developer debugging output\n"
          "  AFL_DONT_OPTIMIZE: disable optimization instead of -O3\n"
          "  AFL_NO_BUILTIN: no builtins for string compare functions (for "
          "libtokencap.so)\n"
          "  AFL_NOOPT: behave like a normal compiler (to pass configure "
          "tests)\n"
          "  AFL_PATH: path to instrumenting pass and runtime  "
          "(afl-compiler-rt.*o)\n"
          "  AFL_IGNORE_UNKNOWN_ENVS: don't warn on unknown env vars\n"
          "  AFL_INST_RATIO: percentage of branches to instrument\n"
          "  AFL_QUIET: suppress verbose output\n"
          "  AFL_HARDEN: adds code hardening to catch memory bugs\n"
          "  AFL_USE_ASAN: activate address sanitizer\n"
          "  AFL_USE_CFISAN: activate control flow sanitizer\n"
          "  AFL_USE_MSAN: activate memory sanitizer\n"
          "  AFL_USE_UBSAN: activate undefined behaviour sanitizer\n"
          "  AFL_USE_TSAN: activate thread sanitizer\n"
          "  AFL_USE_LSAN: activate leak-checker sanitizer\n");

      if (aflcc->have_gcc_plugin)
        SAYF(
            "\nGCC Plugin-specific environment variables:\n"
            "  AFL_GCC_CMPLOG: log operands of comparisons (RedQueen mutator)\n"
            "  AFL_GCC_DISABLE_VERSION_CHECK: disable GCC plugin version "
            "control\n"
            "  AFL_GCC_OUT_OF_LINE: disable inlined instrumentation\n"
            "  AFL_GCC_SKIP_NEVERZERO: do not skip zero on trace counters\n"
            "  AFL_GCC_INSTRUMENT_FILE: enable selective instrumentation by "
            "filename\n");

#if LLVM_MAJOR >= 9
  #define COUNTER_BEHAVIOUR \
    "  AFL_LLVM_SKIP_NEVERZERO: do not skip zero on trace counters\n"
#else
  #define COUNTER_BEHAVIOUR \
    "  AFL_LLVM_NOT_ZERO: use cycling trace counters that skip zero\n"
#endif
      if (aflcc->have_llvm)
        SAYF(
            "\nLLVM/LTO/afl-clang-fast/afl-clang-lto specific environment "
            "variables:\n"
            "  AFL_LLVM_THREADSAFE_INST: instrument with thread safe counters, "
            "disables neverzero\n"

            COUNTER_BEHAVIOUR

            "  AFL_LLVM_DICT2FILE: generate an afl dictionary based on found "
            "comparisons\n"
            "  AFL_LLVM_DICT2FILE_NO_MAIN: skip parsing main() for the "
            "dictionary\n"
            "  AFL_LLVM_INJECTIONS_ALL: enables all injections hooking\n"
            "  AFL_LLVM_INJECTIONS_SQL: enables SQL injections hooking\n"
            "  AFL_LLVM_INJECTIONS_LDAP: enables LDAP injections hooking\n"
            "  AFL_LLVM_INJECTIONS_XSS: enables XSS injections hooking\n"
            "  AFL_LLVM_LAF_ALL: enables all LAF splits/transforms\n"
            "  AFL_LLVM_LAF_SPLIT_COMPARES: enable cascaded comparisons\n"
            "  AFL_LLVM_LAF_SPLIT_COMPARES_BITW: size limit (default 8)\n"
            "  AFL_LLVM_LAF_SPLIT_SWITCHES: cascaded comparisons on switches\n"
            "  AFL_LLVM_LAF_SPLIT_FLOATS: cascaded comparisons on floats\n"
            "  AFL_LLVM_LAF_TRANSFORM_COMPARES: cascade comparisons for string "
            "functions\n"
            "  AFL_LLVM_ALLOWLIST/AFL_LLVM_DENYLIST: enable "
            "instrument allow/\n"
            "    deny listing (selective instrumentation)\n");

      if (aflcc->have_llvm)
        SAYF(
            "  AFL_LLVM_CMPLOG: log operands of comparisons (RedQueen "
            "mutator)\n"
            "  AFL_LLVM_INSTRUMENT: set instrumentation mode:\n"
            "    CLASSIC, PCGUARD, LTO, GCC, CLANG, CALLER, CTX, NGRAM-2 "
            "..-16\n"
            " You can also use the old environment variables instead:\n"
            "  AFL_LLVM_USE_TRACE_PC: use LLVM trace-pc-guard instrumentation\n"
            "  AFL_LLVM_CALLER: use single context sensitive coverage (for "
            "CLASSIC)\n"
            "  AFL_LLVM_CTX: use full context sensitive coverage (for "
            "CLASSIC)\n"
            "  AFL_LLVM_NGRAM_SIZE: use ngram prev_loc count coverage (for "
            "CLASSIC)\n"
            "  AFL_LLVM_NO_RPATH: disable rpath setting for custom LLVM "
            "locations\n");

#ifdef AFL_CLANG_FLTO
      if (aflcc->have_lto)
        SAYF(
            "\nLTO/afl-clang-lto specific environment variables:\n"
            "  AFL_LLVM_MAP_ADDR: use a fixed coverage map address (speed), "
            "e.g. "
            "0x10000\n"
            "  AFL_LLVM_DOCUMENT_IDS: write all edge IDs and the corresponding "
            "functions\n"
            "    into this file (LTO mode)\n"
            "  AFL_LLVM_LTO_CALLER: activate CALLER/CTX instrumentation\n"
            "  AFL_LLVM_LTO_CALLER_DEPTH: skip how many empty functions\n"
            "  AFL_LLVM_LTO_DONTWRITEID: don't write the highest ID used to a "
            "global var\n"
            "  AFL_LLVM_LTO_STARTID: from which ID to start counting from for "
            "a bb\n"
            "  AFL_REAL_LD: use this lld linker instead of the compiled in "
            "path\n"
            "  AFL_LLVM_LTO_SKIPINIT: don't inject initialization code "
            "(used in WAFL mode)\n"
            "If anything fails - be sure to read README.lto.md!\n");
#endif

      SAYF(
          "\nYou can supply --afl-noopt to not instrument, like AFL_NOOPT. "
          "(this is helpful\n"
          "in some build systems if you do not want to instrument "
          "everything.\n");

    }

    SAYF(
        "\nFor any information on the available instrumentations and options "
        "please \n"
        "consult the README.md, especially section 3.1 about instrumenting "
        "targets.\n\n");

#if (LLVM_MAJOR >= 3)
    if (aflcc->have_lto)
      SAYF("afl-cc LTO with ld=%s %s\n", AFL_REAL_LD, AFL_CLANG_FLTO);
    if (aflcc->have_llvm)
      SAYF("afl-cc LLVM version %d using the binary path \"%s\".\n", LLVM_MAJOR,
           LLVM_BINDIR);
#endif

#ifdef USEMMAP
  #if !defined(__HAIKU__)
    SAYF("Compiled with shm_open support.\n");
  #else
    SAYF("Compiled with shm_open support (adds -lrt when linking).\n");
  #endif
#else
    SAYF("Compiled with shmat support.\n");
#endif
    SAYF("\n");

    SAYF(
        "Do not be overwhelmed :) afl-cc uses good defaults if no options are "
        "selected.\n"
        "Read the documentation for FEATURES though, all are good but few are "
        "defaults.\n"
        "Recommended is afl-clang-lto with AFL_LLVM_CMPLOG or afl-clang-fast "
        "with\n"
        "AFL_LLVM_CMPLOG and "
        "AFL_LLVM_DICT2FILE+AFL_LLVM_DICT2FILE_NO_MAIN.\n\n");

    if (LLVM_MAJOR < 13) {

      SAYF(
          "Warning: It is highly recommended to use at least LLVM version 13 "
          "(or better, higher) rather than %d!\n\n",
          LLVM_MAJOR);

    }

    exit(1);

  }

}

/*
  Process params passed to afl-cc.

  We have two working modes, *scan* and *non-scan*. In scan mode,
  the main task is to set some variables in aflcc according to current argv[i],
  while in non-scan mode, is to choose keep or drop current argv[i].

  We have several matching routines being called sequentially in the while-loop,
  and each of them try to parse and match current argv[i] according to their own
  rules. If one miss match, the next will then take over. In non-scan mode, each
  argv[i] mis-matched by all the routines will be kept.

  These routines are:
  1. parse_misc_params
  2. parse_fsanitize
  3. parse_linking_params
  4. `if (*cur == '@') {...}`, i.e., parse response files
*/
static void process_params(aflcc_state_t *aflcc, u8 scan, u32 argc,
                           char **argv) {

  // for (u32 x = 0; x < argc; ++x) fprintf(stderr, "[%u] %s\n", x, argv[x]);

  /* Process the argument list. */

  u8 skip_next = 0;
  while (--argc) {

    u8 *cur = *(++argv);

    if (skip_next > 0) {

      skip_next--;
      continue;

    }

    if (PARAM_MISS != parse_misc_params(aflcc, cur, scan)) continue;

    if (PARAM_MISS != parse_fsanitize(aflcc, cur, scan)) continue;

    if (PARAM_MISS != parse_linking_params(aflcc, cur, scan, &skip_next, argv))
      continue;

    /* Response file support -----BEGIN-----
      We have two choices - move everything to the command line or
      rewrite the response files to temporary files and delete them
      afterwards. We choose the first for easiness.
      For clang, llvm::cl::ExpandResponseFiles does this, however it
      only has C++ interface. And for gcc there is expandargv in libiberty,
      written in C, but we can't simply copy-paste since its LGPL licensed.
      So here we use an equivalent FSM as alternative, and try to be compatible
      with the two above. See:
        - https://gcc.gnu.org/onlinedocs/gcc/Overall-Options.html
        - driver::expand_at_files in gcc.git/gcc/gcc.c
        - expandargv in gcc.git/libiberty/argv.c
        - llvm-project.git/clang/tools/driver/driver.cpp
        - ExpandResponseFiles in
          llvm-project.git/llvm/lib/Support/CommandLine.cpp
    */
    if (*cur == '@') {

      u8 *filename = cur + 1;
      if (aflcc->debug) { DEBUGF("response file=%s\n", filename); }

      // Check not found or empty? let the compiler complain if so.
      FILE *f = fopen(filename, "r");
      if (!f) {

        if (!scan) insert_param(aflcc, cur);
        continue;

      }

      struct stat st;
      if (fstat(fileno(f), &st) || !S_ISREG(st.st_mode) || st.st_size < 1) {

        fclose(f);
        if (!scan) insert_param(aflcc, cur);
        continue;

      }

      // Limit the number of response files, the max value
      // just keep consistent with expandargv. Only do this in
      // scan mode, and not touch rsp_count anymore in the next.
      static u32 rsp_count = 2000;
      if (scan) {

        if (rsp_count == 0) FATAL("Too many response files provided!");

        --rsp_count;

      }

      // argc, argv acquired from this rsp file. Note that
      // process_params ignores argv[0], we need to put a const "" here.
      u32    argc_read = 1;
      char **argv_read = ck_alloc(sizeof(char *));
      argv_read[0] = "";

      char *arg_buf = NULL;
      u64   arg_len = 0;

      enum fsm_state {

        fsm_whitespace,    // whitespace seen so far
        fsm_double_quote,  // have unpaired double quote
        fsm_single_quote,  // have unpaired single quote
        fsm_backslash,     // a backslash is seen with no unpaired quote
        fsm_normal         // a normal char is seen

      };

      // Workaround to append c to arg buffer, and append the buffer to argv
#define ARG_ALLOC(c)                                             \
  do {                                                           \
                                                                 \
    ++arg_len;                                                   \
    arg_buf = ck_realloc(arg_buf, (arg_len + 1) * sizeof(char)); \
    arg_buf[arg_len] = '\0';                                     \
    arg_buf[arg_len - 1] = (char)c;                              \
                                                                 \
  } while (0)

#define ARG_STORE()                                                \
  do {                                                             \
                                                                   \
    ++argc_read;                                                   \
    argv_read = ck_realloc(argv_read, argc_read * sizeof(char *)); \
    argv_read[argc_read - 1] = arg_buf;                            \
    arg_buf = NULL;                                                \
    arg_len = 0;                                                   \
                                                                   \
  } while (0)

      int cur_chr = (int)' ';  // init as whitespace, as a good start :)
      enum fsm_state state_ = fsm_whitespace;

      while (cur_chr != EOF) {

        switch (state_) {

          case fsm_whitespace:

            if (arg_buf) {

              ARG_STORE();
              break;

            }

            if (isspace(cur_chr)) {

              cur_chr = fgetc(f);

            } else if (cur_chr == (int)'\'') {

              state_ = fsm_single_quote;
              cur_chr = fgetc(f);

            } else if (cur_chr == (int)'"') {

              state_ = fsm_double_quote;
              cur_chr = fgetc(f);

            } else if (cur_chr == (int)'\\') {

              state_ = fsm_backslash;
              cur_chr = fgetc(f);

            } else {

              state_ = fsm_normal;

            }

            break;

          case fsm_normal:

            if (isspace(cur_chr)) {

              state_ = fsm_whitespace;

            } else if (cur_chr == (int)'\'') {

              state_ = fsm_single_quote;
              cur_chr = fgetc(f);

            } else if (cur_chr == (int)'\"') {

              state_ = fsm_double_quote;
              cur_chr = fgetc(f);

            } else if (cur_chr == (int)'\\') {

              state_ = fsm_backslash;
              cur_chr = fgetc(f);

            } else {

              ARG_ALLOC(cur_chr);
              cur_chr = fgetc(f);

            }

            break;

          case fsm_backslash:

            ARG_ALLOC(cur_chr);
            cur_chr = fgetc(f);
            state_ = fsm_normal;

            break;

          case fsm_single_quote:

            if (cur_chr == (int)'\\') {

              cur_chr = fgetc(f);
              if (cur_chr == EOF) break;
              ARG_ALLOC(cur_chr);

            } else if (cur_chr == (int)'\'') {

              state_ = fsm_normal;

            } else {

              ARG_ALLOC(cur_chr);

            }

            cur_chr = fgetc(f);
            break;

          case fsm_double_quote:

            if (cur_chr == (int)'\\') {

              cur_chr = fgetc(f);
              if (cur_chr == EOF) break;
              ARG_ALLOC(cur_chr);

            } else if (cur_chr == (int)'"') {

              state_ = fsm_normal;

            } else {

              ARG_ALLOC(cur_chr);

            }

            cur_chr = fgetc(f);
            break;

          default:
            break;

        }

      }

      if (arg_buf) { ARG_STORE(); }  // save the pending arg after EOF

#undef ARG_ALLOC
#undef ARG_STORE

      if (argc_read > 1) { process_params(aflcc, scan, argc_read, argv_read); }

      // We cannot free argv_read[] unless we don't need to keep any
      // reference in cc_params. Never free argv[0], the const "".
      if (scan) {

        while (argc_read > 1)
          ck_free(argv_read[--argc_read]);

        ck_free(argv_read);

      }

      continue;

    }                                /* Response file support -----END----- */

    if (!scan) insert_param(aflcc, cur);

  }

}

/* Process each of the existing argv, also add a few new args. */
static void edit_params(aflcc_state_t *aflcc, u32 argc, char **argv,
                        char **envp) {

  add_real_argv0(aflcc);

  // prevent unnecessary build errors
  insert_param(aflcc, "-Wno-unused-command-line-argument");

  {

    if (aflcc->lto_mode && aflcc->have_instr_env) {

      load_llvm_pass(aflcc, "afl-llvm-lto-instrumentlist.so");

    }

    if (getenv("AFL_LLVM_DICT2FILE")) {

      load_llvm_pass(aflcc, "afl-llvm-dict2file.so");

    }

    // #if LLVM_MAJOR >= 13
    //     // Use the old pass manager in LLVM 14 which the AFL++ passes still
    //     use. insert_param(aflcc, "-flegacy-pass-manager");
    // #endif


    insert_param(aflcc, aflcc->lto_flag);

    if (!aflcc->have_c) {

      add_lto_linker(aflcc);
      add_lto_passes(aflcc);

    }

    // insert_param(aflcc, "-Qunused-arguments");

  }

  /* Inspect the command line parameters. */

  process_params(aflcc, 0, argc, argv);

  add_sanitizers(aflcc, envp);

  add_misc_params(aflcc);

  add_defs_common(aflcc);

  add_runtime(aflcc);

  insert_param(aflcc, NULL);

}

/* Main entry point */
int main(int argc, char **argv, char **envp) {

  aflcc_state_t *aflcc = malloc(sizeof(aflcc_state_t));
  aflcc_state_init(aflcc, (u8 *)argv[0]);

  find_built_deps(aflcc);

  mode_setting(aflcc);

  process_params(aflcc, 1, argc, argv);

  maybe_usage(aflcc, argc, argv);

  mode_notification(aflcc);

  if (aflcc->debug) debugf_args(argc, argv);

  edit_params(aflcc, argc, argv, envp);

  if (aflcc->debug)
    debugf_args((s32)aflcc->cc_par_cnt, (char **)aflcc->cc_params);

  if (aflcc->passthrough) {

    argv[0] = aflcc->cc_params[0];
    execvp(aflcc->cc_params[0], (char **)argv);

  } else {

    execvp(aflcc->cc_params[0], (char **)aflcc->cc_params);

  }

  FATAL("Oops, failed to execute '%s' - check your PATH", aflcc->cc_params[0]);

  return 0;

}

