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
   american fuzzy lop - LLVM-mode instrumentation pass
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   LLVM integration design comes from Laszlo Szekeres. C bits copied-and-pasted
   from afl-as.c are Michal's fault.

   This library is plugged into LLVM when invoking clang through afl-clang-fast.
   It tells the compiler to add code roughly equivalent to the bits discussed
   in ../afl-as.h.
*/

#define AFL_LLVM_PASS

#include "../config.h"
#include "../debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "llvm/Config/llvm-config.h"
#include <optional>
// None becomes deprecated
// the standard std::nullopt_t is recommended instead
// from C++17 and onwards.
constexpr std::nullopt_t None = std::nullopt;

#include "llvm/Pass.h"

#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

#include "llvm/IR/Module.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/CFG.h"

#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Bitcode/BitcodeWriter.h"

using namespace llvm;

#if LLVM_VERSION_MAJOR != 16
  #error Designed only for llvm 16
#endif

namespace {

  class AFLCoverage : public PassInfoMixin<AFLCoverage> {

    public:
      AFLCoverage() {}

      PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
  
  };

  class SVFAnalysis : public PassInfoMixin<SVFAnalysis> {

    public:
      SVFAnalysis() {}

      PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);

      void DumpBC(Module &M);
  
  };

}

void SVFAnalysis::DumpBC(Module &M) {

  char *ptr;

  if ((ptr = getenv("SVF_DUMP_BC")) != NULL) {
    std::string BcDmpPth(ptr);
    BcDmpPth += ".";
    BcDmpPth += M.getSourceFileName().substr(0,16);
    BcDmpPth += ".";
    BcDmpPth += std::to_string((unsigned int)getpid());
    BcDmpPth += ".bc";
    std::error_code ec_;
    std::unique_ptr<raw_fd_ostream> BcDmpDst = 
      std::make_unique<raw_fd_ostream>(BcDmpPth, ec_, (sys::fs::OpenFlags) 0);
    if (ec_) {
      WARNF("Cannot access bc dump path %s", BcDmpPth.c_str());
    } else {
      WriteBitcodeToFile(M, *BcDmpDst);
      BcDmpDst->close();
      SAYF("Write Bitcode to %s\n", BcDmpPth.c_str());
    }
  }
}

PreservedAnalyses SVFAnalysis::run(Module &M, ModuleAnalysisManager &MAM) {

  LLVMContext &C = M.getContext();

  IntegerType *Int8Ty  = IntegerType::getInt8Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);

  /* Show a banner */

  char be_quiet = 0;

  if (isatty(2) && !getenv("AFL_QUIET")) {

    SAYF(cYEL "SVF Analysis Pass" cRST " :)\n");

  } else be_quiet = 1;

  if (!getenv("AFL_LTO_ENABLE")) {

    if (!be_quiet)
      { WARNF("AFL_LTO_ENABLE not set"); }
    
    return PreservedAnalyses::all(); // no thing changed

  }
  
  if (getenv("SVF_DUMP_BC")) {

    DumpBC(M);
    return PreservedAnalyses::all(); // no thing changed

  }

  unsigned int cnt_bb = 0;
  unsigned int cnt_func = 0;
  
  for (auto &F : M) {

    SAYF("SVF Analysis: %s\n", F.getName().str().c_str());

    ++cnt_func;

    for (auto &BB : F) {

      ++cnt_bb;

    }

  }

  if (!be_quiet)
    { SAYF("SVF Analysis: cnt_bb=%u, cnt_func=%u\n", cnt_bb, cnt_func); }

  return PreservedAnalyses();

}

PreservedAnalyses AFLCoverage::run(Module &M, ModuleAnalysisManager &MAM) {

  LLVMContext &C = M.getContext();

  IntegerType *Int8Ty  = IntegerType::getInt8Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);

  /* Show a banner */

  char be_quiet = 0;

  if (isatty(2) && !getenv("AFL_QUIET")) {

    SAYF(cCYA "afl-llvm-pass " cBRI VERSION cRST " by <lszekeres@google.com>\n");

  } else be_quiet = 1;

  if (getenv("SVF_DUMP_BC")) {

    SAYF("SVF_DUMP_BC set, exit AFLCoverage\n");
    return PreservedAnalyses::all(); // no thing changed

  }

  /* Decide instrumentation ratio */

  char* inst_ratio_str = getenv("AFL_INST_RATIO");
  unsigned int inst_ratio = 100;

  if (inst_ratio_str) {

    if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
        inst_ratio > 100)
      FATAL("Bad value of AFL_INST_RATIO (must be between 1 and 100)");

  }

  /* Get globals for the SHM region and the previous location. Note that
     __afl_prev_loc is thread-local. */

  GlobalVariable *AFLMapPtr =
      new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                         GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");

  GlobalVariable *AFLPrevLoc = new GlobalVariable(
      M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc",
      0, GlobalVariable::GeneralDynamicTLSModel, 0, false);

  /* Instrument all the things! */

  int inst_blocks = 0;

  for (auto &F : M) {

    if (F.getName().contains("__afl_svf_")) continue;

    for (auto &BB : F) {

      BasicBlock::iterator IP = BB.getFirstInsertionPt();
      IRBuilder<> IRB(&(*IP));

      if (AFL_R(100) >= inst_ratio) continue;

      /* Make up cur_loc */

      unsigned int cur_loc = AFL_R(MAP_SIZE);

      ConstantInt *CurLoc = ConstantInt::get(Int32Ty, cur_loc);

      /* Load prev_loc */

      LoadInst *PrevLoc = IRB.CreateLoad(IRB.getInt32Ty(), AFLPrevLoc);
      PrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *PrevLocCasted = IRB.CreateZExt(PrevLoc, IRB.getInt32Ty());

      /* Load SHM pointer */

      LoadInst *MapPtr = IRB.CreateLoad(PointerType::get(Int8Ty, 0), AFLMapPtr);
      MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *MapPtrIdx = IRB.CreateGEP(Int8Ty, MapPtr, IRB.CreateXor(PrevLocCasted, CurLoc));

      /* Update bitmap */

      LoadInst *Counter = IRB.CreateLoad(IRB.getInt8Ty(), MapPtrIdx);
      Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *Incr = IRB.CreateAdd(Counter, ConstantInt::get(Int8Ty, 1));
      IRB.CreateStore(Incr, MapPtrIdx)
          ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      /* Set prev_loc to cur_loc >> 1 */

      StoreInst *Store =
          IRB.CreateStore(ConstantInt::get(Int32Ty, cur_loc >> 1), AFLPrevLoc);
      Store->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      inst_blocks++;

    }
  }

  /* Say something nice. */

  if (!be_quiet) {

    if (!inst_blocks) WARNF("No instrumentation targets found.");
    else OKF("Instrumented %u locations (%s mode, ratio %u%%).",
             inst_blocks, getenv("AFL_HARDEN") ? "hardened" :
             ((getenv("AFL_USE_ASAN") || getenv("AFL_USE_MSAN")) ?
              "ASAN/MSAN" : "non-hardened"), inst_ratio);

  }

  return PreservedAnalyses();

}

extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {

  return {LLVM_PLUGIN_API_VERSION, "AFLCoverage", "v0.1",
          /* lambda to insert our pass into the pass pipeline. */
          [](PassBuilder &PB) {

            auto AFLCallback = [](ModulePassManager &MPM, OptimizationLevel OL) {

                                  MPM.addPass(AFLCoverage());

                                };
            auto SVFCallback = [](ModulePassManager &MPM, OptimizationLevel OL) {

                                  MPM.addPass(SVFAnalysis());

                                };
            PB.registerFullLinkTimeOptimizationEarlyEPCallback(SVFCallback);
            PB.registerFullLinkTimeOptimizationLastEPCallback(AFLCallback);
          }};

}
