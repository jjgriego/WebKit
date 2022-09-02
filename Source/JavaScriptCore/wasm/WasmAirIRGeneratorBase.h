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

public:
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
    // Constructors

    AirIRGeneratorBase(const ModuleInformation& info, B3::Procedure& procedure, InternalFunction* compilation, Vector<UnlinkedWasmToWasmCall>& unlinkedWasmToWasmCalls, MemoryMode mode, unsigned functionIndex, std::optional<bool> hasExceptionHandlers, TierUpCount* tierUp, const TypeDefinition& originalSignature, unsigned& osrEntryScratchBufferSize)
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
                    jit.store64(scratch, CCallHelpers::Address(GPRInfo::callFrameRegister, CallFrameSlot::thisArgument * sizeof(Register)));
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
            m_instanceValue = { Tmp(m_prologueWasmContextGPR), Types::I64 };

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
};

} } // namespace JSC::Wasm

#endif // ENABLE(WEBASSEMBLY_B3JIT)
