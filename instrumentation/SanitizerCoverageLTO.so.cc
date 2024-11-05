/* SanitizeCoverage.cpp ported to AFL++ LTO :-) */

#define AFL_LLVM_PASS

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>

#include <list>
#include <string>
#include <fstream>
#include <set>
#include <iostream>

#include "llvm/Transforms/Instrumentation/SanitizerCoverage.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/SmallVector.h"
#if LLVM_VERSION_MAJOR < 17
  #include "llvm/ADT/Triple.h"
  #include "llvm/Analysis/EHPersonalities.h"
#else
  #include "llvm/IR/EHPersonalities.h"
#endif
#include "llvm/Analysis/PostDominators.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constant.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Mangler.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/InitializePasses.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/SpecialCaseList.h"
#include "llvm/Support/VirtualFileSystem.h"
#include "llvm/Support/raw_ostream.h"
#if LLVM_VERSION_MAJOR < 20
  #include "llvm/Transforms/Instrumentation.h"
#else
  #include "llvm/Transforms/Utils/Instrumentation.h"
#endif
#if LLVM_VERSION_MAJOR < 17
  #include "llvm/Transforms/IPO/PassManagerBuilder.h"
#endif
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/PassManager.h"

#include "llvm/Bitcode/BitcodeWriter.h"

#include "config.h"
#include "debug.h"
#include "afl-llvm-common.h"

using namespace llvm;

#define DEBUG_TYPE "sancov"

const char SanCovTracePCIndirName[] = "__sanitizer_cov_trace_pc_indir";
const char SanCovTracePCName[] = "__sanitizer_cov_trace_pc";
// const char SanCovTracePCGuardName =
//    "__sanitizer_cov_trace_pc_guard";
const char SanCovGuardsSectionName[] = "sancov_guards";
const char SanCovCountersSectionName[] = "sancov_cntrs";
const char SanCovBoolFlagSectionName[] = "sancov_bools";
const char SanCovPCsSectionName[] = "sancov_pcs";

static cl::opt<int> ClCoverageLevel(
    "lto-coverage-level",
    cl::desc("Sanitizer Coverage. 0: none, 1: entry block, 2: all blocks, "
             "3: all blocks and critical edges"),
    cl::Hidden, cl::init(3));

static cl::opt<bool> ClTracePC("lto-coverage-trace-pc",
                               cl::desc("Experimental pc tracing"), cl::Hidden,
                               cl::init(false));

static cl::opt<bool> ClTracePCGuard("lto-coverage-trace-pc-guard",
                                    cl::desc("pc tracing with a guard"),
                                    cl::Hidden, cl::init(false));

// If true, we create a global variable that contains PCs of all instrumented
// BBs, put this global into a named section, and pass this section's bounds
// to __sanitizer_cov_pcs_init.
// This way the coverage instrumentation does not need to acquire the PCs
// at run-time. Works with trace-pc-guard, inline-8bit-counters, and
// inline-bool-flag.
static cl::opt<bool> ClCreatePCTable("lto-coverage-pc-table",
                                     cl::desc("create a static PC table"),
                                     cl::Hidden, cl::init(false));

static cl::opt<bool> ClInline8bitCounters(
    "lto-coverage-inline-8bit-counters",
    cl::desc("increments 8-bit counter for every edge"), cl::Hidden,
    cl::init(false));

static cl::opt<bool> ClInlineBoolFlag(
    "lto-coverage-inline-bool-flag",
    cl::desc("sets a boolean flag for every edge"), cl::Hidden,
    cl::init(false));

static cl::opt<bool> ClPruneBlocks(
    "lto-coverage-prune-blocks",
    cl::desc("Reduce the number of instrumented blocks"), cl::Hidden,
    cl::init(true));

namespace llvm {

void initializeModuleSanitizerCoverageLTOLegacyPassPass(PassRegistry &PB);

}

namespace {

SanitizerCoverageOptions getOptions(int LegacyCoverageLevel) {

  SanitizerCoverageOptions Res;
  switch (LegacyCoverageLevel) {

    case 0:
      Res.CoverageType = SanitizerCoverageOptions::SCK_None;
      break;
    case 1:
      Res.CoverageType = SanitizerCoverageOptions::SCK_Function;
      break;
    case 2:
      Res.CoverageType = SanitizerCoverageOptions::SCK_BB;
      break;
    case 3:
      Res.CoverageType = SanitizerCoverageOptions::SCK_Edge;
      break;
    case 4:
      Res.CoverageType = SanitizerCoverageOptions::SCK_Edge;
      Res.IndirectCalls = true;
      break;

  }

  return Res;

}

SanitizerCoverageOptions OverrideFromCL(SanitizerCoverageOptions Options) {

  // Sets CoverageType and IndirectCalls.
  SanitizerCoverageOptions CLOpts = getOptions(ClCoverageLevel);
  Options.CoverageType = std::max(Options.CoverageType, CLOpts.CoverageType);
  Options.IndirectCalls |= CLOpts.IndirectCalls;
  Options.TracePC |= ClTracePC;
  Options.TracePCGuard |= ClTracePCGuard;
  Options.Inline8bitCounters |= ClInline8bitCounters;
  Options.InlineBoolFlag |= ClInlineBoolFlag;
  Options.PCTable |= ClCreatePCTable;
  Options.NoPrune |= !ClPruneBlocks;
  if (!Options.TracePCGuard && !Options.TracePC &&
      !Options.Inline8bitCounters && !Options.InlineBoolFlag)
    Options.TracePCGuard = true;  // TracePCGuard is default.
  return Options;

}

using DomTreeCallback = function_ref<const DominatorTree *(Function &F)>;
using PostDomTreeCallback =
    function_ref<const PostDominatorTree *(Function &F)>;

class ModuleSanitizerCoverageLTO
    : public PassInfoMixin<ModuleSanitizerCoverageLTO> {

 public:
  ModuleSanitizerCoverageLTO(
      const SanitizerCoverageOptions &Options = SanitizerCoverageOptions())
      : Options(OverrideFromCL(Options)) {

  }

  bool instrumentModule(Module &M, DomTreeCallback DTCallback,
                        PostDomTreeCallback PDTCallback);

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);

 private:
  void instrumentFunction(Function &F, DomTreeCallback DTCallback,
                          PostDomTreeCallback PDTCallback);

  void SetNoSanitizeMetadata(Instruction *I) {

#if LLVM_VERSION_MAJOR >= 19
    I->setNoSanitizeMetadata();
#else
    I->setMetadata(I->getModule()->getMDKindID("nosanitize"),
                   MDNode::get(*C, None));
#endif

  }

  FunctionCallee SanCovTracePCIndir;
  FunctionCallee SanCovTracePC /*, SanCovTracePCGuard*/;
  Type *IntptrTy, *IntptrPtrTy, *Int64Ty, *Int64PtrTy, *Int32Ty, *Int32PtrTy,
      *Int16Ty, *Int8Ty, *Int8PtrTy, *Int1Ty, *Int1PtrTy, *PtrTy;
  Module           *CurModule;
  std::string       CurModuleUniqueId;
  Triple            TargetTriple;
  LLVMContext      *C;
  const DataLayout *DL;

  SmallVector<GlobalValue *, 20> GlobalsToAppendToUsed;
  SmallVector<GlobalValue *, 20> GlobalsToAppendToCompilerUsed;

  SanitizerCoverageOptions Options;

  // AFL++ START
  uint32_t                         inst = 0;
  uint32_t                         unhandled = 0;
  uint32_t                         select_cnt = 0;
  IntegerType                     *Int8Tyi = NULL;
  IntegerType                     *Int32Tyi = NULL;
  IntegerType                     *Int64Tyi = NULL;
  ConstantInt                     *Zero = NULL;
  ConstantInt                     *Zero32 = NULL;
  ConstantInt                     *One = NULL;
  LLVMContext                     *Ct = NULL;
  Module                          *Mo = NULL;
  GlobalVariable                  *AFLMapPtr = NULL;
  // AFL++ END

};

class ModuleSanitizerCoverageLTOLegacyPass : public ModulePass {

 public:
  static char ID;
  StringRef   getPassName() const override {

    return "sancov-lto";

  }

  void getAnalysisUsage(AnalysisUsage &AU) const override {

    AU.addRequired<DominatorTreeWrapperPass>();
    AU.addRequired<PostDominatorTreeWrapperPass>();

  }

  ModuleSanitizerCoverageLTOLegacyPass(
      const SanitizerCoverageOptions &Options = SanitizerCoverageOptions())
      : ModulePass(ID), Options(Options) {

    initializeModuleSanitizerCoverageLTOLegacyPassPass(
        *PassRegistry::getPassRegistry());

  }

  bool runOnModule(Module &M) override {

    ModuleSanitizerCoverageLTO ModuleSancov(Options);
    auto DTCallback = [this](Function &F) -> const DominatorTree * {

      return &this->getAnalysis<DominatorTreeWrapperPass>(F).getDomTree();

    };

    auto PDTCallback = [this](Function &F) -> const PostDominatorTree * {

      return &this->getAnalysis<PostDominatorTreeWrapperPass>(F)
                  .getPostDomTree();

    };

    return ModuleSancov.instrumentModule(M, DTCallback, PDTCallback);

  }

 private:
  SanitizerCoverageOptions Options;

};

}  // namespace

extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {

  return {LLVM_PLUGIN_API_VERSION, "SanitizerCoverageLTO", "v0.1",
          /*
            ==== CLANG-LTO-WRAP ==== 
            lambda to insert our pass into the pass pipeline. 
          */
          [](PassBuilder &PB) {

#if LLVM_VERSION_MAJOR <= 13
            using OptimizationLevel = typename PassBuilder::OptimizationLevel;
#endif
#if LLVM_VERSION_MAJOR >= 15
            PB.registerFullLinkTimeOptimizationLastEPCallback(
#else
            PB.registerOptimizerLastEPCallback(
#endif
                [](ModulePassManager &MPM, OptimizationLevel OL) {

                  MPM.addPass(ModuleSanitizerCoverageLTO());

                });

          }};

}

PreservedAnalyses ModuleSanitizerCoverageLTO::run(Module                &M,
                                                  ModuleAnalysisManager &MAM) {

  ModuleSanitizerCoverageLTO ModuleSancov(Options);
  auto &FAM = MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();
  auto  DTCallback = [&FAM](Function &F) -> const DominatorTree  *{

    return &FAM.getResult<DominatorTreeAnalysis>(F);

  };

  auto PDTCallback = [&FAM](Function &F) -> const PostDominatorTree * {

    return &FAM.getResult<PostDominatorTreeAnalysis>(F);

  };

  if (ModuleSancov.instrumentModule(M, DTCallback, PDTCallback))
    return PreservedAnalyses::none();

  return PreservedAnalyses::all();

}

/* 
  ==== CLANG-LTO-WRAP ====
  instrumentModule
*/
bool ModuleSanitizerCoverageLTO::instrumentModule(
    Module &M, DomTreeCallback DTCallback, PostDomTreeCallback PDTCallback) {

  if (Options.CoverageType == SanitizerCoverageOptions::SCK_None) return false;

  C = &(M.getContext());
  DL = &M.getDataLayout();
  CurModule = &M;
  CurModuleUniqueId = getUniqueModuleId(CurModule);
  TargetTriple = Triple(M.getTargetTriple());
  IntptrTy = Type::getIntNTy(*C, DL->getPointerSizeInBits());
  IntptrPtrTy = PointerType::getUnqual(IntptrTy);
  Type       *VoidTy = Type::getVoidTy(*C);
  IRBuilder<> IRB(*C);
  Int64PtrTy = PointerType::getUnqual(IRB.getInt64Ty());
  Int32PtrTy = PointerType::getUnqual(IRB.getInt32Ty());
  Int8PtrTy = PointerType::getUnqual(IRB.getInt8Ty());
  Int1PtrTy = PointerType::getUnqual(IRB.getInt1Ty());
  Int64Ty = IRB.getInt64Ty();
  Int32Ty = IRB.getInt32Ty();
  Int16Ty = IRB.getInt16Ty();
  Int8Ty = IRB.getInt8Ty();
  Int1Ty = IRB.getInt1Ty();
  PtrTy = PointerType::getUnqual(*C);

  /* AFL++ START */
  char        *ptr;
  LLVMContext &Ctx = M.getContext();
  Ct = &Ctx;
  Int8Tyi = IntegerType::getInt8Ty(Ctx);
  Int32Tyi = IntegerType::getInt32Ty(Ctx);
  Int64Tyi = IntegerType::getInt64Ty(Ctx);

  /* Save the bc before this pass applied */
  if ((ptr = getenv("AFL_DUMP_BC")) != NULL) {

    std::string BcDmpPth(ptr);
    BcDmpPth += ".";
    BcDmpPth += M.getSourceFileName().substr(0,8);
    BcDmpPth += ".";
    BcDmpPth += std::to_string((unsigned int)getpid());
    BcDmpPth += ".bc";

    std::error_code ec_;
    std::unique_ptr<raw_fd_ostream> BcDmpDst = 
      std::make_unique<raw_fd_ostream>(BcDmpPth, ec_, sys::fs::OF_None);
    
    if (ec_) {
      WARNF("Cannot access bc dump path %s", BcDmpPth.c_str());
    } else {
      WriteBitcodeToFile(M, *BcDmpDst);
      BcDmpDst->close();
    }

  }

  /* Show a banner */
  setvbuf(stdout, NULL, _IONBF, 0);
  if (getenv("AFL_DEBUG")) { debug = 1; }


  if ((isatty(2) && !getenv("AFL_QUIET")) || debug) {

    char buf[64] = {};

    SAYF(cCYA "afl-llvm-lto" VERSION cRST
              "%s by Marc \"vanHauser\" Heuse <mh@mh-sec.de>\n",
         buf);

  } else {

    be_quiet = 1;

  }

  /* Get/set the globals */

  AFLMapPtr =
      new GlobalVariable(M, PointerType::get(Int8Tyi, 0), false,
                          GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");

  Zero = ConstantInt::get(Int8Tyi, 0);
  Zero32 = ConstantInt::get(Int32Tyi, 0);
  One = ConstantInt::get(Int8Tyi, 1);

  initInstrumentList();
  scanForDangerousFunctions(&M);
  Mo = &M;

  // AFL++ END

  SanCovTracePCIndir =
      M.getOrInsertFunction(SanCovTracePCIndirName, VoidTy, IntptrTy);
  // Make sure smaller parameters are zero-extended to i64 as required by the
  // x86_64 ABI.
  AttributeList SanCovTraceCmpZeroExtAL;
  if (TargetTriple.getArch() == Triple::x86_64) {

    SanCovTraceCmpZeroExtAL =
        SanCovTraceCmpZeroExtAL.addParamAttribute(*C, 0, Attribute::ZExt);
    SanCovTraceCmpZeroExtAL =
        SanCovTraceCmpZeroExtAL.addParamAttribute(*C, 1, Attribute::ZExt);

  }

  SanCovTracePC = M.getOrInsertFunction(SanCovTracePCName, VoidTy);

  // SanCovTracePCGuard =
  //    M.getOrInsertFunction(SanCovTracePCGuardName, VoidTy, Int32PtrTy);

  /* 
    ==== CLANG-LTO-WRAP ====
    main for-loop on functions
  */
  for (auto &F : M)
    instrumentFunction(F, DTCallback, PDTCallback);

  /* Say something nice. */

  if (!be_quiet) {

    if (!inst)
      WARNF("No instrumentation targets found.");
    else {

      char modeline[128];
      snprintf(modeline, sizeof(modeline), "%s%s%s%s%s%s",
               getenv("AFL_HARDEN") ? "hardened" : "non-hardened",
               getenv("AFL_USE_ASAN") ? ", ASAN" : "",
               getenv("AFL_USE_MSAN") ? ", MSAN" : "",
               getenv("AFL_USE_TSAN") ? ", TSAN" : "",
               getenv("AFL_USE_CFISAN") ? ", CFISAN" : "",
               getenv("AFL_USE_UBSAN") ? ", UBSAN" : "");

      OKF("Instrumented %u locations (%u selects) (%s mode).", inst,
          select_cnt, modeline);

    }

  }

  // AFL++ END

  // We don't reference these arrays directly in any of our runtime functions,
  // so we need to prevent them from being dead stripped.
  if (TargetTriple.isOSBinFormatMachO()) appendToUsed(M, GlobalsToAppendToUsed);
  appendToCompilerUsed(M, GlobalsToAppendToCompilerUsed);
  return true;

}

// True if block has successors and it dominates all of them.
static bool isFullDominator(const BasicBlock *BB, const DominatorTree *DT) {

  if (succ_begin(BB) == succ_end(BB)) return false;

  for (const BasicBlock *SUCC : make_range(succ_begin(BB), succ_end(BB))) {

    if (!DT->dominates(BB, SUCC)) return false;

  }

  return true;

}

// True if block has predecessors and it postdominates all of them.
static bool isFullPostDominator(const BasicBlock        *BB,
                                const PostDominatorTree *PDT) {

  if (pred_begin(BB) == pred_end(BB)) return false;

  for (const BasicBlock *PRED : make_range(pred_begin(BB), pred_end(BB))) {

    if (!PDT->dominates(BB, PRED)) return false;

  }

  return true;

}

/// return the number of calls to this function
u32 countCallers(Function *F) {

  u32 callers = 0;

  if (!F) { return 0; }

  for (auto *U : F->users()) {

    if (auto *CI = dyn_cast<CallInst>(U)) {

      ++callers;
      (void)(CI);

    }

  }

  return callers;

}

/// return the calling function of a function - only if there is a single caller
Function *returnOnlyCaller(Function *F) {

  Function *caller = NULL;

  if (!F) { return NULL; }

  for (auto *U : F->users()) {

    if (auto *CI = dyn_cast<CallInst>(U)) {

      if (caller == NULL) {

        caller = CI->getParent()->getParent();

      } else {

        return NULL;

      }

    }

  }

  return caller;

}

/*
  ==== CLANG-LTO-WRAP ====
  instrumentFunction
*/
void ModuleSanitizerCoverageLTO::instrumentFunction(
    Function &F, DomTreeCallback DTCallback, PostDomTreeCallback PDTCallback) {

  if (F.empty()) return;
  if (F.getName().contains(".module_ctor"))
    return;  // Should not instrument sanitizer init functions.
#if LLVM_VERSION_MAJOR >= 18
  if (F.getName().starts_with("__sanitizer_"))
#else
  if (F.getName().startswith("__sanitizer_"))
#endif
    return;  // Don't instrument __sanitizer_* callbacks.
  // Don't touch available_externally functions, their actual body is elsewhere.
  if (F.getLinkage() == GlobalValue::AvailableExternallyLinkage) return;
  // Don't instrument MSVC CRT configuration helpers. They may run before normal
  // initialization.
  if (F.getName() == "__local_stdio_printf_options" ||
      F.getName() == "__local_stdio_scanf_options")
    return;
  if (isa<UnreachableInst>(F.getEntryBlock().getTerminator())) return;
  // Don't instrument functions using SEH for now. Splitting basic blocks like
  // we do for coverage breaks WinEHPrepare.
  // FIXME: Remove this when SEH no longer uses landingpad pattern matching.
  if (F.hasPersonalityFn() &&
      isAsynchronousEHPersonality(classifyEHPersonality(F.getPersonalityFn())))
    return;
  if (F.hasFnAttribute(Attribute::NoSanitizeCoverage)) return;
#if LLVM_VERSION_MAJOR >= 19
  if (F.hasFnAttribute(Attribute::DisableSanitizerInstrumentation)) return;
#endif

  // AFL++ START
  if (!F.size()) return;

  LLVMContext &Context = F.getContext();
  MDNode      *N = MDNode::get(Context, MDString::get(Context, "nosanitize"));

  if (!isInInstrumentList(&F, FMNAME)) return;
  // AFL++ END

  if (Options.CoverageType >= SanitizerCoverageOptions::SCK_Edge)
    /* 
      ==== CLANG-LTO-WRAP ====
      It will do this in default.
      > An edge between basic blocks is considered a critical edge
      > if the predecessor has multiple successors, and the successor
      > has multiple predecessors.
    */
    SplitAllCriticalEdges(
        F, CriticalEdgeSplittingOptions().setIgnoreUnreachableDests());

  //SmallVector<BasicBlock *, 16> BlocksToInstrument;

  const DominatorTree     *DT = DTCallback(F);
  const PostDominatorTree *PDT = PDTCallback(F);
  uint32_t                 skip_next = 0;

  if (debug) 
    fprintf(stderr, "==== CLANG-LTO-WRAP ====\nFunction: %s\n", 
            F.getName().str().c_str());

  /* 
    ==== CLANG-LTO-WRAP ====
    main for-loop on BBs
  */
  for (auto &BB : F) {

    skip_next = 0;

    uint32_t j = 0;

    for (auto &IN : BB) {

      CallInst *callInst = nullptr;

      if ((callInst = dyn_cast<CallInst>(&IN))) {

        Function *Callee = callInst->getCalledFunction();
        if (!Callee) continue;
        if (callInst->getCallingConv() != llvm::CallingConv::C) continue;
        StringRef FuncName = Callee->getName();
        if (!FuncName.compare(StringRef("dlopen")) ||
            !FuncName.compare(StringRef("_dlopen"))) {

          fprintf(stderr,
                  "WARNING: dlopen() detected. To have coverage for a library "
                  "that your target dlopen()'s this must either happen before "
                  "__AFL_INIT() or you must use AFL_PRELOAD to preload all "
                  "dlopen()'ed libraries!\n");
          continue;

        }

        if (FuncName.compare(StringRef("__afl_coverage_interesting"))) continue;

        ++inst;

      }

      SelectInst *selectInst = nullptr;

      if ((selectInst = dyn_cast<SelectInst>(&IN))) {

        if (!skip_next) {

          fprintf(stderr, "Select in\n");

          uint32_t    vector_cnt = 0;
          Value      *condition = selectInst->getCondition();
          Value      *result;
          auto        t = condition->getType();
          IRBuilder<> IRB(selectInst->getNextNode());

          ++select_cnt;

          if (t->getTypeID() == llvm::Type::IntegerTyID) {

            skip_next = 1;
            inst += 2;

          } else {

            ++unhandled;
            continue;

          }

          skip_next = 1;
          fprintf(stderr, "Select out\n");

        } else {

          fprintf(stderr, "Select skip\n");
          skip_next = 0;

        }

      }

    }

    //if (shouldInstrumentBlock(F, &BB, DT, PDT, Options))
    //  BlocksToInstrument.push_back(&BB);

  }

  //InjectCoverage(F, BlocksToInstrument, IsLeafFunc);

}

char ModuleSanitizerCoverageLTOLegacyPass::ID = 0;

INITIALIZE_PASS_BEGIN(ModuleSanitizerCoverageLTOLegacyPass, "sancov-lto",
                      "Pass for instrumenting stuffs on functions", false,
                      false)
INITIALIZE_PASS_DEPENDENCY(DominatorTreeWrapperPass)
INITIALIZE_PASS_DEPENDENCY(PostDominatorTreeWrapperPass)
INITIALIZE_PASS_END(ModuleSanitizerCoverageLTOLegacyPass, "sancov-lto",
                    "Pass for instrumenting stuffs on functions", false,
                    false)

#if LLVM_VERSION_MAJOR < 16
static void registerLTOPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {

  auto p = new ModuleSanitizerCoverageLTOLegacyPass();
  PM.add(p);

}

static RegisterStandardPasses RegisterCompTransPass(
    PassManagerBuilder::EP_OptimizerLast, registerLTOPass);

static RegisterStandardPasses RegisterCompTransPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerLTOPass);

  #if LLVM_VERSION_MAJOR >= 11
static RegisterStandardPasses RegisterCompTransPassLTO(
    PassManagerBuilder::EP_FullLinkTimeOptimizationLast, registerLTOPass);
  #endif
#endif

