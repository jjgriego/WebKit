/*
 * Copyright (C) 2019-2022 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "WasmAirIRGenerator.h"

#if ENABLE(WEBASSEMBLY_B3JIT)

#include "AirCode.h"
#include "AirGenerate.h"
#include "AirHelpers.h"
#include "AirOpcodeUtils.h"
#include "AllowMacroScratchRegisterUsageIf.h"
#include "B3CheckSpecial.h"
#include "B3CheckValue.h"
#include "B3Commutativity.h"
#include "B3PatchpointSpecial.h"
#include "B3Procedure.h"
#include "B3ProcedureInlines.h"
#include "B3StackmapGenerationParams.h"
#include "BinarySwitch.h"
#include "JSCJSValueInlines.h"
#include "JSWebAssemblyInstance.h"
#include "ScratchRegisterAllocator.h"
#include "WasmBranchHints.h"
#include "WasmCallingConvention.h"
#include "WasmContextInlines.h"
#include "WasmExceptionType.h"
#include "WasmFunctionParser.h"
#include "WasmIRGeneratorHelpers.h"
#include "WasmInstance.h"
#include "WasmMemory.h"
#include "WasmOSREntryData.h"
#include "WasmOpcodeOrigin.h"
#include "WasmOperations.h"
#include "WasmThunks.h"
#include "WasmTypeDefinitionInlines.h"
#include <limits>
#include <wtf/Box.h>
#include <wtf/StdLibExtras.h>

namespace JSC { namespace Wasm {

using namespace B3::Air;

struct ConstrainedTmp {
    ConstrainedTmp() = default;
    ConstrainedTmp(Tmp tmp)
        : ConstrainedTmp(tmp, tmp.isReg() ? B3::ValueRep::reg(tmp.reg()) : B3::ValueRep::SomeRegister)
    { }

    ConstrainedTmp(Tmp tmp, B3::ValueRep rep)
        : tmp(tmp)
        , rep(rep)
    {
    }

    explicit operator bool() const { return !!tmp; }

    Tmp tmp;
    B3::ValueRep rep;
};

template<typename Derived, typename ExpressionType>
struct AirIRGeneratorBase {
    ////////////////////////////////////////////////////////////////////////////////
    // Related types

    using ResultList = Vector<ExpressionType, 8>;

    struct ControlData {
        ControlData(B3::Origin, BlockSignature result, ResultList resultTmps, BlockType type, BasicBlock* continuation, BasicBlock* special = nullptr)
            : controlBlockType(type)
            , continuation(continuation)
            , special(special)
            , results(resultTmps)
            , returnType(result)
        {
        }

        ControlData(B3::Origin, BlockSignature result, ResultList resultTmps, BlockType type, BasicBlock* continuation, unsigned tryStart, unsigned tryDepth)
            : controlBlockType(type)
            , continuation(continuation)
            , special(nullptr)
            , results(resultTmps)
            , returnType(result)
            , m_tryStart(tryStart)
            , m_tryCatchDepth(tryDepth)
        {
        }

        ControlData()
        {
        }

        static bool isIf(const ControlData& control) { return control.blockType() == BlockType::If; }
        static bool isTry(const ControlData& control) { return control.blockType() == BlockType::Try; }
        static bool isAnyCatch(const ControlData& control) { return control.blockType() == BlockType::Catch; }
        static bool isCatch(const ControlData& control) { return isAnyCatch(control) && control.catchKind() == CatchKind::Catch; }
        static bool isTopLevel(const ControlData& control) { return control.blockType() == BlockType::TopLevel; }
        static bool isLoop(const ControlData& control) { return control.blockType() == BlockType::Loop; }
        static bool isBlock(const ControlData& control) { return control.blockType() == BlockType::Block; }

        void dump(PrintStream& out) const
        {
            switch (blockType()) {
            case BlockType::If:
                out.print("If:       ");
                break;
            case BlockType::Block:
                out.print("Block:    ");
                break;
            case BlockType::Loop:
                out.print("Loop:     ");
                break;
            case BlockType::TopLevel:
                out.print("TopLevel: ");
                break;
            case BlockType::Try:
                out.print("Try: ");
                break;
            case BlockType::Catch:
                out.print("Catch: ");
                break;
            }
            out.print("Continuation: ", *continuation, ", Special: ");
            if (special)
                out.print(*special);
            else
                out.print("None");

            CommaPrinter comma(", ", " Result Tmps: [");
            for (const auto& tmp : results)
                out.print(comma, tmp);
            if (comma.didPrint())
                out.print("]");
        }

        BlockType blockType() const { return controlBlockType; }
        BlockSignature signature() const { return returnType; }

        BasicBlock* targetBlockForBranch()
        {
            if (blockType() == BlockType::Loop)
                return special;
            return continuation;
        }

        void convertIfToBlock()
        {
            ASSERT(blockType() == BlockType::If);
            controlBlockType = BlockType::Block;
            special = nullptr;
        }

        FunctionArgCount branchTargetArity() const
        {
            if (blockType() == BlockType::Loop)
                return returnType->as<FunctionSignature>()->argumentCount();
            return returnType->as<FunctionSignature>()->returnCount();
        }

        Type branchTargetType(unsigned i) const
        {
            ASSERT(i < branchTargetArity());
            if (blockType() == BlockType::Loop)
                return returnType->as<FunctionSignature>()->argumentType(i);
            return returnType->as<FunctionSignature>()->returnType(i);
        }

        void convertTryToCatch(unsigned tryEndCallSiteIndex, ExpressionType exception)
        {
            ASSERT(blockType() == BlockType::Try);
            controlBlockType = BlockType::Catch;
            m_catchKind = CatchKind::Catch;
            m_tryEnd = tryEndCallSiteIndex;
            m_exception = exception;
        }

        void convertTryToCatchAll(unsigned tryEndCallSiteIndex, ExpressionType exception)
        {
            ASSERT(blockType() == BlockType::Try);
            controlBlockType = BlockType::Catch;
            m_catchKind = CatchKind::CatchAll;
            m_tryEnd = tryEndCallSiteIndex;
            m_exception = exception;
        }

        unsigned tryStart() const
        {
            ASSERT(controlBlockType == BlockType::Try || controlBlockType == BlockType::Catch);
            return m_tryStart;
        }

        unsigned tryEnd() const
        {
            ASSERT(controlBlockType == BlockType::Catch);
            return m_tryEnd;
        }

        unsigned tryDepth() const
        {
            ASSERT(controlBlockType == BlockType::Try || controlBlockType == BlockType::Catch);
            return m_tryCatchDepth;
        }

        CatchKind catchKind() const
        {
            ASSERT(controlBlockType == BlockType::Catch);
            return m_catchKind;
        }

        ExpressionType exception() const
        {
            ASSERT(controlBlockType == BlockType::Catch);
            return m_exception;
        }

    private:
        friend Derived;
        BlockType controlBlockType;
        BasicBlock* continuation;
        BasicBlock* special;
        ResultList results;
        BlockSignature returnType;
        unsigned m_tryStart;
        unsigned m_tryEnd;
        unsigned m_tryCatchDepth;
        CatchKind m_catchKind;
        ExpressionType m_exception;
    };

    using ControlType = ControlData;

    using ParserTypes = FunctionParserTypes<ControlType, ExpressionType>;

    using ControlEntry = typename ParserTypes::ControlEntry;
    using ControlStack = typename ParserTypes::ControlStack;
    using Stack = typename ParserTypes::Stack;
    using TypedExpression = typename ParserTypes::TypedExpression;

    using ErrorType = String;
    using UnexpectedResult = Unexpected<ErrorType>;
    using Result = Expected<std::unique_ptr<InternalFunction>, ErrorType>;
    using PartialResult = Expected<void, ErrorType>;

    static_assert(std::is_same_v<ResultList, typename ParserTypes::ResultList>);

    ////////////////////////////////////////////////////////////////////////////////
    // Get concrete instance

    Derived& self()
    {
        return *static_cast<Derived*>(this);
    }

    const Derived& self() const
    {
        return *static_cast<const Derived*>(this);
    }

    ////////////////////////////////////////////////////////////////////////////////
    // Failure reporting

#define WASM_COMPILE_FAIL_IF(condition, ...) \
    do {                                     \
        if (UNLIKELY(condition))             \
            return self().fail(__VA_ARGS__); \
    } while (0)

    template<typename... Args>
    NEVER_INLINE UnexpectedResult WARN_UNUSED_RETURN fail(Args... args) const
    {
        using namespace FailureHelper; // See ADL comment in WasmParser.h.
        return UnexpectedResult(makeString("WebAssembly.Module failed compiling: "_s, makeString(args)...));
    }

    ////////////////////////////////////////////////////////////////////////////////
    // Code generation utilities

protected:
    void emitEntryTierUpCheck();

    ////////////////////////////////////////////////////////////////////////////////
    // Manipulating air code

protected:
    ALWAYS_INLINE void validateInst(Inst& inst)
    {
        if (ASSERT_ENABLED) {
            if (!inst.isValidForm()) {
                dataLogLn("Inst validation failed:");
                dataLogLn(inst, "\n");
                if (inst.origin)
                    dataLogLn(deepDump(inst.origin), "\n");
                CRASH();
            }
        }
    }

    template<typename... Arguments>
    void append(BasicBlock* block, Kind kind, Arguments&&... arguments)
    {
        // FIXME: Find a way to use origin here.
        auto& inst = block->append(kind, nullptr, Derived::extractArg(arguments)...);
        validateInst(inst);
    }

    template<typename... Arguments>
    void append(Kind kind, Arguments&&... arguments)
    {
        append(m_currentBlock, kind, std::forward<Arguments>(arguments)...);
    }

    template<typename... Arguments>
    void appendEffectful(B3::Air::Opcode op, Arguments&&... arguments)
    {
        Kind kind = op;
        kind.effects = true;
        append(m_currentBlock, kind, std::forward<Arguments>(arguments)...);
    }

    template<typename... Arguments>
    void appendEffectful(BasicBlock* block, B3::Air::Opcode op, Arguments&&... arguments)
    {
        Kind kind = op;
        kind.effects = true;
        append(block, kind, std::forward<Arguments>(arguments)...);
    }

    B3::PatchpointValue* addPatchpoint(B3::Type type)
    {
        auto* result = m_proc.add<B3::PatchpointValue>(type, B3::Origin());
        if (UNLIKELY(shouldDumpIRAtEachPhase(B3::AirMode)))
            m_patchpoints.add(result);
        return result;
    }

    template<typename... Args>
    void emitPatchpoint(B3::PatchpointValue* patch, Tmp result, Args... theArgs)
    {
        emitPatchpoint(m_currentBlock, patch, result, std::forward<Args>(theArgs)...);
    }

    template<typename... Args>
    void emitPatchpoint(BasicBlock* basicBlock, B3::PatchpointValue* patch, Tmp result, Args... theArgs)
    {
        emitPatchpoint(basicBlock, patch, Vector<Tmp, 8> { result }, Vector<ConstrainedTmp, sizeof...(Args)>::from(theArgs...));
    }

    void emitPatchpoint(BasicBlock* basicBlock, B3::PatchpointValue* patch, Tmp result)
    {
        emitPatchpoint(basicBlock, patch, Vector<Tmp, 8> { result }, Vector<ConstrainedTmp>());
    }

    template<size_t inlineSize>
    void emitPatchpoint(BasicBlock* basicBlock, B3::PatchpointValue* patch, Tmp result, Vector<ConstrainedTmp, inlineSize>&& args)
    {
        emitPatchpoint(basicBlock, patch, Vector<Tmp, 8> { result }, WTFMove(args));
    }

    template<typename ResultTmpType, size_t inlineSize>
    void emitPatchpoint(BasicBlock* basicBlock, B3::PatchpointValue* patch, const Vector<ResultTmpType, 8>& results, Vector<ConstrainedTmp, inlineSize>&& args);

public:
    void setParser(FunctionParser<Derived>* parser)
    {
        m_parser = parser;
    };

    const Bag<B3::PatchpointValue*>& patchpoints() const
    {
        return m_patchpoints;
    }

    StackMaps&& takeStackmaps()
    {
        return WTFMove(m_stackmaps);
    }

    void addStackMap(unsigned callSiteIndex, StackMap&& stackmap)
    {
        m_stackmaps.add(CallSiteIndex(callSiteIndex), WTFMove(stackmap));
    }

    Vector<UnlinkedHandlerInfo>&& takeExceptionHandlers()
    {
        return WTFMove(m_exceptionHandlers);
    }

    void finalizeEntrypoints();

protected:
    Tmp newTmp(B3::Bank bank)
    {
        return m_code.newTmp(bank);
    }

    ResultList tmpsForSignature(BlockSignature signature)
    {
        ResultList result(signature->as<FunctionSignature>()->returnCount());
        for (unsigned i = 0; i < signature->as<FunctionSignature>()->returnCount(); ++i)
            result[i] = self().tmpForType(signature->as<FunctionSignature>()->returnType(i));
        return result;
    }

    ////////////////////////////////////////////////////////////////////////////////
    // Constructor

    AirIRGeneratorBase(const ModuleInformation& info, B3::Procedure& procedure, InternalFunction* compilation, Vector<UnlinkedWasmToWasmCall>& unlinkedWasmToWasmCalls, MemoryMode mode, unsigned functionIndex, std::optional<bool> hasExceptionHandlers, TierUpCount* tierUp, const TypeDefinition& originalSignature, unsigned& osrEntryScratchBufferSize);

    ////////////////////////////////////////////////////////////////////////////////
    // manipualte ExpressionType

    ExpressionType tmpForType(Type type)
    {
        switch (type.kind) {
        case TypeKind::I32:
            return self().g32();
        case TypeKind::I64:
            return self().g64();
        case TypeKind::Funcref:
            return self().gFuncref();
        case TypeKind::Ref:
        case TypeKind::RefNull:
            return self().gRef(type);
        case TypeKind::Externref:
            return self().gExternref();
        case TypeKind::F32:
            return self().f32();
        case TypeKind::F64:
            return self().f64();
        case TypeKind::Void:
            return {};
        default:
            RELEASE_ASSERT_NOT_REACHED();
        }
    }

    ////////////////////////////////////////////////////////////////////////////////
    // interface to parser
public:

    PartialResult addLocal(Type type, uint32_t count)
    {
        size_t newSize = m_locals.size() + count;
        ASSERT(!(CheckedUint32(count) + m_locals.size()).hasOverflowed());
        ASSERT(newSize <= maxFunctionLocals);
        WASM_COMPILE_FAIL_IF(!m_locals.tryReserveCapacity(newSize), "can't allocate memory for ", newSize, " locals");

        for (uint32_t i = 0; i < count; ++i) {
            auto local = self().tmpForType(type);
            m_locals.uncheckedAppend(local);
            self().emitZeroInitialize(local);
        }
        return { };
    }

    PartialResult addArguments(const TypeDefinition& signature)
    {
        RELEASE_ASSERT(m_locals.size() == signature.as<FunctionSignature>()->argumentCount()); // We handle arguments in the prologue
        return {};
    }

    void didFinishParsingLocals() {}
    void didPopValueFromStack() {}

    ControlData addTopLevel(BlockSignature);
    PartialResult WARN_UNUSED_RETURN endTopLevel(BlockSignature, const Stack&) { return {}; }

    ////////////////////////////////////////////////////////////////////////////////
    // debug utilities

    void dump(const ControlStack& controlStack, const Stack* stack)
    {
        dataLogLn("Processing Graph:");
        dataLog(m_code);
        dataLogLn("With current block:", *m_currentBlock);
        dataLogLn("Control stack:");
        for (size_t i = controlStack.size(); i--;) {
            dataLog("  ", controlStack[i].controlData, ": ");
            CommaPrinter comma(", ", "");
            dumpExpressionStack(comma, *stack);
            stack = &controlStack[i].enclosedExpressionStack;
            dataLogLn();
        }
        dataLogLn("\n");
    }

    static void dumpExpressionStack(const CommaPrinter& comma, const Stack& expressionStack)
    {
        dataLog(comma, "ExpressionStack:");
        for (const auto& expression : expressionStack)
            dataLog(comma, expression.value());
    }

    ////////////////////////////////////////////////////////////////////////////////
    // data members

    FunctionParser<Derived>* m_parser { nullptr };
    const ModuleInformation& m_info;
    const MemoryMode m_mode { MemoryMode::BoundsChecking };
    const unsigned m_functionIndex { UINT_MAX };
    TierUpCount* m_tierUp { nullptr };

    B3::Procedure& m_proc;
    Code& m_code;
    Vector<uint32_t> m_outerLoops;
    BasicBlock* m_currentBlock { nullptr };
    BasicBlock* m_rootBlock { nullptr };
    BasicBlock* m_mainEntrypointStart { nullptr };
    Vector<ExpressionType> m_locals;
    Vector<UnlinkedWasmToWasmCall>& m_unlinkedWasmToWasmCalls; // List each call site and the function index whose address it should be patched with.

    GPRReg m_memoryBaseGPR { InvalidGPRReg };
    GPRReg m_boundsCheckingSizeGPR { InvalidGPRReg };
    GPRReg m_wasmContextInstanceGPR { InvalidGPRReg };
    GPRReg m_prologueWasmContextGPR { InvalidGPRReg };
    bool m_makesCalls { false };
    std::optional<bool> m_hasExceptionHandlers;

    HashMap<BlockSignature, B3::Type> m_tupleMap;
    // This is only filled if we are dumping IR.
    Bag<B3::PatchpointValue*> m_patchpoints;

    ExpressionType m_instanceValue; // Always use the accessor below to ensure the instance value is materialized when used.
    bool m_usesInstanceValue { false };
    ExpressionType instanceValue()
    {
        m_usesInstanceValue = true;
        return m_instanceValue;
    }

    uint32_t m_maxNumJSCallArguments { 0 };
    unsigned m_numImportFunctions;

    B3::PatchpointSpecial* m_patchpointSpecial { nullptr };

    RefPtr<B3::Air::PrologueGenerator> m_prologueGenerator;

    Vector<BasicBlock*> m_catchEntrypoints;

    Checked<unsigned> m_tryCatchDepth { 0 };
    Checked<unsigned> m_callSiteIndex { 0 };
    StackMaps m_stackmaps;
    Vector<UnlinkedHandlerInfo> m_exceptionHandlers;

    Vector<std::pair<BasicBlock*, Vector<ExpressionType>>> m_loopEntryVariableData;
    unsigned& m_osrEntryScratchBufferSize;

    ////////////////////////////////////////////////////////////////////////////////
    // parameters for shared code

public:
    static constexpr bool generatesB3OriginData = true;
};


template <typename Derived, typename ExpressionType>
AirIRGeneratorBase<Derived,ExpressionType>::AirIRGeneratorBase(const ModuleInformation& info, B3::Procedure& procedure, InternalFunction* compilation, Vector<UnlinkedWasmToWasmCall>& unlinkedWasmToWasmCalls, MemoryMode mode, unsigned functionIndex, std::optional<bool> hasExceptionHandlers, TierUpCount* tierUp, const TypeDefinition& originalSignature, unsigned& osrEntryScratchBufferSize)
    : m_info(info)
    , m_mode(mode)
    , m_functionIndex(functionIndex)
    , m_tierUp(tierUp)
    , m_proc(procedure)
    , m_code(m_proc.code())
    , m_unlinkedWasmToWasmCalls(unlinkedWasmToWasmCalls)
    , m_hasExceptionHandlers(hasExceptionHandlers)
    , m_numImportFunctions(info.importFunctionCount())
    , m_osrEntryScratchBufferSize(osrEntryScratchBufferSize)
{
    m_currentBlock = m_code.addBlock();
    m_rootBlock = m_currentBlock;

    // FIXME we don't really need to pin registers here if there's no memory. It makes wasm -> wasm thunks simpler for now. https://bugs.webkit.org/show_bug.cgi?id=166623
    const PinnedRegisterInfo& pinnedRegs = PinnedRegisterInfo::get();

    m_memoryBaseGPR = pinnedRegs.baseMemoryPointer;
    m_code.pinRegister(m_memoryBaseGPR);

    m_wasmContextInstanceGPR = pinnedRegs.wasmContextInstancePointer;
    if (!Context::useFastTLS())
        m_code.pinRegister(m_wasmContextInstanceGPR);

    if (mode == MemoryMode::BoundsChecking) {
        m_boundsCheckingSizeGPR = pinnedRegs.boundsCheckingSizeRegister;
        m_code.pinRegister(m_boundsCheckingSizeGPR);
    }

    m_prologueWasmContextGPR = Context::useFastTLS() ? wasmCallingConvention().prologueScratchGPRs[1] : m_wasmContextInstanceGPR;

    m_prologueGenerator = createSharedTask<B3::Air::PrologueGeneratorFunction>([=, this] (CCallHelpers& jit, B3::Air::Code& code) {
        AllowMacroScratchRegisterUsage allowScratch(jit);
        code.emitDefaultPrologue(jit);

        {
            GPRReg calleeGPR = wasmCallingConvention().prologueScratchGPRs[0];
            auto moveLocation = jit.moveWithPatch(MacroAssembler::TrustedImmPtr(nullptr), calleeGPR);
            jit.addLinkTask([compilation, moveLocation] (LinkBuffer& linkBuffer) {
                compilation->calleeMoveLocations.append(linkBuffer.locationOf<WasmEntryPtrTag>(moveLocation));
            });
            jit.emitPutToCallFrameHeader(calleeGPR, CallFrameSlot::callee);
            jit.emitPutToCallFrameHeader(nullptr, CallFrameSlot::codeBlock);
        }

        {
            const Checked<int32_t> wasmFrameSize = m_code.frameSize();
            const unsigned minimumParentCheckSize = WTF::roundUpToMultipleOf(stackAlignmentBytes(), 1024);
            const unsigned extraFrameSize = WTF::roundUpToMultipleOf(stackAlignmentBytes(), std::max<uint32_t>(
                // This allows us to elide stack checks for functions that are terminal nodes in the call
                // tree, (e.g they don't make any calls) and have a small enough frame size. This works by
                // having any such terminal node have its parent caller include some extra size in its
                // own check for it. The goal here is twofold:
                // 1. Emit less code.
                // 2. Try to speed things up by skipping stack checks.
                minimumParentCheckSize,
                // This allows us to elide stack checks in the Wasm -> Embedder call IC stub. Since these will
                // spill all arguments to the stack, we ensure that a stack check here covers the
                // stack that such a stub would use.
                Checked<uint32_t>(m_maxNumJSCallArguments) * sizeof(Register) + jsCallingConvention().headerSizeInBytes
            ));
            const int32_t checkSize = m_makesCalls ? (wasmFrameSize + extraFrameSize).value() : wasmFrameSize.value();
            bool needUnderflowCheck = static_cast<unsigned>(checkSize) > Options::reservedZoneSize();
            bool needsOverflowCheck = m_makesCalls || wasmFrameSize >= static_cast<int32_t>(minimumParentCheckSize) || needUnderflowCheck;
            bool mayHaveExceptionHandlers = !m_hasExceptionHandlers || m_hasExceptionHandlers.value();

            if ((needsOverflowCheck || m_usesInstanceValue || mayHaveExceptionHandlers) && Context::useFastTLS())
                jit.loadWasmContextInstance(m_prologueWasmContextGPR);

            // We need to setup JSWebAssemblyInstance in |this| slot first.
            if (mayHaveExceptionHandlers) {
                GPRReg scratch = wasmCallingConvention().prologueScratchGPRs[0];
                jit.loadPtr(CCallHelpers::Address(m_prologueWasmContextGPR, Instance::offsetOfOwner()), scratch);
                jit.storePtr(scratch, CCallHelpers::Address(GPRInfo::callFrameRegister, CallFrameSlot::thisArgument * sizeof(Register)));
            }

            // This allows leaf functions to not do stack checks if their frame size is within
            // certain limits since their caller would have already done the check.
            if (needsOverflowCheck) {
                if (mayHaveExceptionHandlers)
                    jit.store32(CCallHelpers::TrustedImm32(PatchpointExceptionHandle::s_invalidCallSiteIndex), CCallHelpers::tagFor(CallFrameSlot::argumentCountIncludingThis));

                GPRReg scratch = wasmCallingConvention().prologueScratchGPRs[0];
                jit.addPtr(CCallHelpers::TrustedImm32(-checkSize), GPRInfo::callFrameRegister, scratch);
                MacroAssembler::JumpList overflow;
                if (UNLIKELY(needUnderflowCheck))
                    overflow.append(jit.branchPtr(CCallHelpers::Above, scratch, GPRInfo::callFrameRegister));
                overflow.append(jit.branchPtr(CCallHelpers::Below, scratch, CCallHelpers::Address(m_prologueWasmContextGPR, Instance::offsetOfCachedStackLimit())));
                jit.addLinkTask([overflow] (LinkBuffer& linkBuffer) {
                    linkBuffer.link(overflow, CodeLocationLabel<JITThunkPtrTag>(Thunks::singleton().stub(throwStackOverflowFromWasmThunkGenerator).code()));
                });
            }

        }
    });

    if (Context::useFastTLS()) {
        m_instanceValue = self().gPtr();
        // FIXME: Would be nice to only do this if we use instance value.
        append(Move, Tmp(m_prologueWasmContextGPR), m_instanceValue);
    } else
        m_instanceValue = { Tmp(m_prologueWasmContextGPR), Types::IPtr };

    append(EntrySwitch);
    m_mainEntrypointStart = m_code.addBlock();
    m_currentBlock = m_mainEntrypointStart;

    const TypeDefinition& signature = originalSignature.expand();
    ASSERT(!m_locals.size());
    m_locals.grow(signature.as<FunctionSignature>()->argumentCount());
    for (unsigned i = 0; i < signature.as<FunctionSignature>()->argumentCount(); ++i) {
        Type type = signature.as<FunctionSignature>()->argumentType(i);
        m_locals[i] = self().tmpForType(type);
    }

    CallInformation wasmCallInfo = wasmCallingConvention().callInformationFor(signature, CallRole::Callee);

    for (unsigned i = 0; i < wasmCallInfo.params.size(); ++i) {
        B3::ValueRep location = wasmCallInfo.params[i];
        Arg arg = location.isReg() ? Arg(Tmp(location.reg())) : Arg::addr(Tmp(GPRInfo::callFrameRegister), location.offsetFromFP());
        switch (signature.as<FunctionSignature>()->argumentType(i).kind) {
        case TypeKind::I32:
            append(Move32, arg, m_locals[i]);
            break;
        case TypeKind::I64:
        case TypeKind::Externref:
        case TypeKind::Funcref:
        case TypeKind::Ref:
        case TypeKind::RefNull:
            append(Move, arg, m_locals[i]);
            break;
        case TypeKind::F32:
            append(MoveFloat, arg, m_locals[i]);
            break;
        case TypeKind::F64:
            append(MoveDouble, arg, m_locals[i]);
            break;
        default:
            RELEASE_ASSERT_NOT_REACHED();
        }
    }

    emitEntryTierUpCheck();
}

template<typename Generator>
Expected<std::unique_ptr<InternalFunction>, String> parseAndCompileAirImpl(CompilationContext& compilationContext, const FunctionData& function, const TypeDefinition& signature, Vector<UnlinkedWasmToWasmCall>& unlinkedWasmToWasmCalls, const ModuleInformation& info, MemoryMode mode, uint32_t functionIndex, std::optional<bool> hasExceptionHandlers, TierUpCount* tierUp)
{
    auto result = makeUnique<InternalFunction>();

    compilationContext.wasmEntrypointJIT = makeUnique<CCallHelpers>();

    compilationContext.procedure = makeUnique<B3::Procedure>();
    auto& procedure = *compilationContext.procedure;
    Code& code = procedure.code();

    if constexpr (Generator::generatesB3OriginData) {
        procedure.setOriginPrinter([](PrintStream& out, B3::Origin origin) {
            if (origin.data())
                out.print("Wasm: ", OpcodeOrigin(origin));
        });
    }
    
    // This means we cannot use either StackmapGenerationParams::usedRegisters() or
    // StackmapGenerationParams::unavailableRegisters(). In exchange for this concession, we
    // don't strictly need to run Air::reportUsedRegisters(), which saves a bit of CPU time at
    // optLevel=1.
    procedure.setNeedsUsedRegisters(false);
    
    procedure.setOptLevel(Options::webAssemblyBBQAirOptimizationLevel());

    Generator irGenerator(info, procedure, result.get(), unlinkedWasmToWasmCalls, mode, functionIndex, hasExceptionHandlers, tierUp, signature, result->osrEntryScratchBufferSize);
    FunctionParser<Generator> parser(irGenerator, function.data.data(), function.data.size(), signature, info);
    WASM_FAIL_IF_HELPER_FAILS(parser.parse());

    irGenerator.finalizeEntrypoints();

    for (BasicBlock* block : code) {
        for (size_t i = 0; i < block->numSuccessors(); ++i)
            block->successorBlock(i)->addPredecessor(block);
    }

    if (UNLIKELY(shouldDumpIRAtEachPhase(B3::AirMode))) {
        dataLogLn("Generated patchpoints");
        for (B3::PatchpointValue** patch : irGenerator.patchpoints())
            dataLogLn(deepDump(procedure, *patch));
    }

    B3::Air::prepareForGeneration(code);
    B3::Air::generate(code, *compilationContext.wasmEntrypointJIT);

    compilationContext.wasmEntrypointByproducts = procedure.releaseByproducts();
    result->entrypoint.calleeSaveRegisters = code.calleeSaveRegisterAtOffsetList();
    result->stackmaps = irGenerator.takeStackmaps();
    result->exceptionHandlers = irGenerator.takeExceptionHandlers();

    return result;
}

template <typename Derived, typename ExpressionType>
void AirIRGeneratorBase<Derived, ExpressionType>::finalizeEntrypoints()
{
    unsigned numEntrypoints = Checked<unsigned>(1) + m_catchEntrypoints.size() + m_loopEntryVariableData.size();
    m_proc.setNumEntrypoints(numEntrypoints);
    m_code.setPrologueForEntrypoint(0, Ref<B3::Air::PrologueGenerator>(*m_prologueGenerator));
    for (unsigned i = 1 + m_catchEntrypoints.size(); i < numEntrypoints; ++i)
        m_code.setPrologueForEntrypoint(i, Ref<B3::Air::PrologueGenerator>(*m_prologueGenerator));

    if (m_catchEntrypoints.size()) {
        Ref<B3::Air::PrologueGenerator> catchPrologueGenerator = createSharedTask<B3::Air::PrologueGeneratorFunction>([this] (CCallHelpers& jit, B3::Air::Code& code) {
            AllowMacroScratchRegisterUsage allowScratch(jit);
            emitCatchPrologueShared(code, jit);

            if (Context::useFastTLS()) {
                // Shared prologue expects this in this register when entering the function using fast TLS.
                jit.loadWasmContextInstance(m_prologueWasmContextGPR);
            }
        });

        for (unsigned i = 0; i < m_catchEntrypoints.size(); ++i)
            m_code.setPrologueForEntrypoint(1 + i, catchPrologueGenerator.copyRef());
    }

    BasicBlock::SuccessorList successors;
    successors.append(m_mainEntrypointStart);
    successors.appendVector(m_catchEntrypoints);

    for (auto& pair : m_loopEntryVariableData) {
        BasicBlock* loopBody = pair.first;
        BasicBlock* entry = m_code.addBlock();
        successors.append(entry);
        m_currentBlock = entry;

        auto& temps = pair.second;
        m_osrEntryScratchBufferSize = std::max(m_osrEntryScratchBufferSize, static_cast<unsigned>(temps.size()));
        Tmp basePtr = Tmp(GPRInfo::argumentGPR0);

        for (size_t i = 0; i < temps.size(); ++i) {
            size_t offset = static_cast<size_t>(i) * sizeof(uint64_t);
            self().emitLoad(basePtr, offset, temps[i]);
        }

        append(Jump);
        entry->setSuccessors(loopBody);
    }

    RELEASE_ASSERT(numEntrypoints == successors.size());
    m_rootBlock->successors() = successors;
}

template <typename Derived, typename ExpressionType>
auto AirIRGeneratorBase<Derived, ExpressionType>::addTopLevel(BlockSignature signature) -> ControlData
{
    return ControlData(B3::Origin(), signature, tmpsForSignature(signature), BlockType::TopLevel, m_code.addBlock());
}

template <typename Derived, typename ExpressionType>
void AirIRGeneratorBase<Derived, ExpressionType>::emitEntryTierUpCheck()
{
    if (!m_tierUp)
        return;

    auto countdownPtr = self().gPtr();
    append(Move, Arg::bigImm(bitwise_cast<uintptr_t>(&m_tierUp->m_counter)), countdownPtr);

    auto* patch = addPatchpoint(B3::Void);
    B3::Effects effects = B3::Effects::none();
    effects.reads = B3::HeapRange::top();
    effects.writes = B3::HeapRange::top();
    patch->effects = effects;
    patch->clobber(RegisterSet::macroScratchRegisters());

    patch->setGenerator([=, this] (CCallHelpers& jit, const B3::StackmapGenerationParams& params) {
        AllowMacroScratchRegisterUsage allowScratch(jit);

        CCallHelpers::Jump tierUp = jit.branchAdd32(CCallHelpers::PositiveOrZero, CCallHelpers::TrustedImm32(TierUpCount::functionEntryIncrement()), CCallHelpers::Address(params[0].gpr()));
        CCallHelpers::Label tierUpResume = jit.label();

        params.addLatePath([=, this] (CCallHelpers& jit) {
            tierUp.link(&jit);

            const unsigned extraPaddingBytes = 0;
            RegisterSet registersToSpill = { };
            registersToSpill.add(GPRInfo::argumentGPR1);
            unsigned numberOfStackBytesUsedForRegisterPreservation = ScratchRegisterAllocator::preserveRegistersToStackForCall(jit, registersToSpill, extraPaddingBytes);

            jit.move(MacroAssembler::TrustedImm32(m_functionIndex), GPRInfo::argumentGPR1);
            MacroAssembler::Call call = jit.nearCall();

            ScratchRegisterAllocator::restoreRegistersFromStackForCall(jit, registersToSpill, RegisterSet(), numberOfStackBytesUsedForRegisterPreservation, extraPaddingBytes);
            jit.jump(tierUpResume);

            jit.addLinkTask([=] (LinkBuffer& linkBuffer) {
                MacroAssembler::repatchNearCall(linkBuffer.locationOfNearCall<NoPtrTag>(call), CodeLocationLabel<JITThunkPtrTag>(Thunks::singleton().stub(triggerOMGEntryTierUpThunkGenerator).code()));
            });
        });
    });

    self().emitPatchpoint(patch, Tmp(), countdownPtr);
}

template <typename Derived, typename ExpressionType>
template <typename ResultTmpType, size_t inlineSize>
void AirIRGeneratorBase<Derived, ExpressionType>::emitPatchpoint(BasicBlock* basicBlock, B3::PatchpointValue* patch, const Vector<ResultTmpType, 8>& results, Vector<ConstrainedTmp, inlineSize>&& args)
{
    if (!m_patchpointSpecial)
        m_patchpointSpecial = static_cast<B3::PatchpointSpecial*>(m_code.addSpecial(makeUnique<B3::PatchpointSpecial>()));

    auto toTmp = [&] (ResultTmpType tmp) {
        if constexpr (std::is_same_v<ResultTmpType, Tmp>)
            return tmp;
        else
            return tmp.tmp();
    };

    Inst inst(Patch, patch, Arg::special(m_patchpointSpecial));
    Vector<Inst, 1> resultMovs;
    switch (patch->type().kind()) {
    case B3::Void:
        break;
    default: {
        ASSERT(results.size());
        for (unsigned i = 0; i < results.size(); ++i) {
            switch (patch->resultConstraints[i].kind()) {
            case B3::ValueRep::StackArgument: {
                Arg arg = Arg::callArg(patch->resultConstraints[i].offsetFromSP());
                inst.args.append(arg);
                resultMovs.append(Inst(B3::Air::moveForType(m_proc.typeAtOffset(patch->type(), i)), nullptr, arg, toTmp(results[i])));
                break;
            }
            case B3::ValueRep::Register: {
                inst.args.append(Tmp(patch->resultConstraints[i].reg()));
                resultMovs.append(Inst(B3::Air::relaxedMoveForType(m_proc.typeAtOffset(patch->type(), i)), nullptr, Tmp(patch->resultConstraints[i].reg()), toTmp(results[i])));
                break;
            }
            case B3::ValueRep::SomeRegister: {
                inst.args.append(toTmp(results[i]));
                break;
            }
            default:
                RELEASE_ASSERT_NOT_REACHED();
            }
        }
    }
    }

    for (unsigned i = 0; i < args.size(); ++i) {
        ConstrainedTmp& tmp = args[i];
        // FIXME: This is less than ideal to create dummy values just to satisfy Air's
        // validation. We should abstract Patch enough so ValueRep's don't need to be
        // backed by Values.
        // https://bugs.webkit.org/show_bug.cgi?id=194040
        B3::Value* dummyValue = m_proc.addConstant(B3::Origin(), tmp.tmp.isGP() ? B3::Int64 : B3::Double, 0);
        patch->append(dummyValue, tmp.rep);
        switch (tmp.rep.kind()) {
        // B3::Value propagates (Late)ColdAny information and later Air will allocate appropriate stack.
        case B3::ValueRep::ColdAny: 
        case B3::ValueRep::LateColdAny:
        case B3::ValueRep::SomeRegister:
            inst.args.append(tmp.tmp);
            break;
        case B3::ValueRep::Register:
            patch->earlyClobbered().clear(tmp.rep.reg());
            append(basicBlock, tmp.tmp.isGP() ? Move : MoveDouble, tmp.tmp, tmp.rep.reg());
            inst.args.append(Tmp(tmp.rep.reg()));
            break;
        case B3::ValueRep::StackArgument: {
            Arg arg = Arg::callArg(tmp.rep.offsetFromSP());
            append(basicBlock, tmp.tmp.isGP() ? Move : MoveDouble, tmp.tmp, arg);
            ASSERT(arg.canRepresent(patch->child(i)->type()));
            inst.args.append(arg);
            break;
        }
        default:
            RELEASE_ASSERT_NOT_REACHED();
        }
    }

    for (auto valueRep : patch->resultConstraints) {
        if (valueRep.isReg())
            patch->lateClobbered().clear(valueRep.reg());
    }
    for (unsigned i = patch->numGPScratchRegisters; i--;)
        inst.args.append(newTmp(B3::GP));
    for (unsigned i = patch->numFPScratchRegisters; i--;)
        inst.args.append(newTmp(B3::FP));

    validateInst(inst);
    basicBlock->append(WTFMove(inst));
    for (Inst result : resultMovs) {
        validateInst(result);
        basicBlock->append(WTFMove(result));
    }
}




} } // namespace JSC::Wasm

#endif // ENABLE(WEBASSEMBLY_B3JIT)
