/*
   american fuzzy lop++ - instrumentation bootstrap
   ------------------------------------------------

   Copyright 2015, 2016 Google Inc. All rights reserved.
   Copyright 2019-2024 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0


*/

#include "types.h"

#include <stdio.h>
#include <unistd.h>

u32 __afl_already_initialized_first;
u32 __afl_already_initialized_second;
u32 __afl_already_initialized_init;

__attribute__((constructor())) void __afl_auto_init(void) {

  if (__afl_already_initialized_init) { return; }
  
  if (getenv("AFL_DEBUG")) {

    fprintf(stderr, "DEBUG: Initialization latest possible\n");

  }

}

/* preset __afl_area_ptr #2 */

__attribute__((constructor(1))) void __afl_auto_second(void) {

  if (__afl_already_initialized_second) return;
  __afl_already_initialized_second = 1;

  if (getenv("AFL_DEBUG")) {

    fprintf(stderr, "DEBUG: debug enabled\n");
    fprintf(stderr, "DEBUG: AFL++ afl-compiler-rt" VERSION "\n");

  }

}  // ptr memleak report is a false positive

/* preset __afl_area_ptr #1 - at constructor level 0 global variables have
   not been set */

__attribute__((constructor(0))) void __afl_auto_first(void) {

  if (__afl_already_initialized_first) return;
  __afl_already_initialized_first = 1;

  if (getenv("AFL_DEBUG")) {

    fprintf(stderr, "DEBUG: __afl_auto_first\n");

  }

}  // ptr memleak report is a false positive
