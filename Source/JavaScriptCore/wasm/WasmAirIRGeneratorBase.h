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
        friend AirIRGeneratorBase;
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
    void emitLoopTierUpCheck(uint32_t loopIndex, const Vector<ExpressionType>& liveValues);

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

    template<typename Branch, typename Generator>
    void emitCheck(const Branch& makeBranch, const Generator& generator)
    {
        // We fail along the truthy edge of 'branch'.
        Inst branch = makeBranch();

        // FIXME: Make a hashmap of these.
        B3::CheckSpecial::Key key(branch);
        B3::CheckSpecial* special = static_cast<B3::CheckSpecial*>(m_code.addSpecial(makeUnique<B3::CheckSpecial>(key)));

        // FIXME: Remove the need for dummy values
        // https://bugs.webkit.org/show_bug.cgi?id=194040
        B3::Value* dummyPredicate = m_proc.addConstant(B3::Origin(), B3::Int32, 42);
        B3::CheckValue* checkValue = m_proc.add<B3::CheckValue>(B3::Check, B3::Origin(), dummyPredicate);
        checkValue->setGenerator(generator);

        Inst inst(Patch, checkValue, Arg::special(special));
        inst.args.appendVector(branch.args);
        m_currentBlock->append(WTFMove(inst));
    }

    template <typename Func, typename ...Args>
    void emitCCall(Func func, ExpressionType result, Args... args)
    {
        emitCCall(m_currentBlock, func, result, std::forward<Args>(args)...);
    }
    template <typename Func, typename ...Args>
    void emitCCall(BasicBlock* block, Func func, ExpressionType result, Args... theArgs)
    {
        B3::Type resultType = B3::Void;
        if (result) {
            switch (result.type().kind) {
            case TypeKind::I32:
                resultType = B3::Int32;
                break;
            case TypeKind::I64:
            case TypeKind::Externref:
            case TypeKind::Funcref:
            case TypeKind::Ref:
            case TypeKind::RefNull:
                resultType = B3::Int64;
                break;
            case TypeKind::F32:
                resultType = B3::Float;
                break;
            case TypeKind::F64:
                resultType = B3::Double;
                break;
            default:
                RELEASE_ASSERT_NOT_REACHED();
            }
        }

        auto makeDummyValue = [&] (auto tmp) {
            // FIXME: This is less than ideal to create dummy values just to satisfy Air's
            // validation. We should abstrcat CCall enough so we're not reliant on arguments
            // to the B3::CCallValue.
            // https://bugs.webkit.org/show_bug.cgi?id=194040
            return m_proc.addConstant(B3::Origin(), toB3Type(tmp.type()), 0);
        };

        B3::Value* dummyFunc = m_proc.addConstant(B3::Origin(), B3::Int64, bitwise_cast<uintptr_t>(func));
        B3::Value* origin = m_proc.add<B3::CCallValue>(resultType, B3::Origin(), B3::Effects::none(), dummyFunc, makeDummyValue(theArgs)...);

        Inst inst(CCall, origin);

        auto callee = self().gPtr();
        append(block, Move, Arg::immPtr(tagCFunctionPtr<void*, OperationPtrTag>(func)), callee);
        inst.args.append(callee);

        if (result)
            self().appendCCallArg(inst, result);

        for (auto tmp : Vector<ExpressionType, sizeof...(Args)>::from(theArgs...))
            self().appendCCallArg(inst, tmp);

        block->append(WTFMove(inst));
    }

    void emitThrowException(CCallHelpers& jit, ExceptionType type);

    void emitThrowOnNullReference(const ExpressionType& ref) {
        self().emitCheckForNullReference(ref, [=, this](CCallHelpers& jit, const B3::StackmapGenerationParams&) {
            this->emitThrowException(jit, ExceptionType::NullI31Get);
        });
    }

    int32_t WARN_UNUSED_RETURN fixupPointerPlusOffset(ExpressionType&, uint32_t);

    void restoreWasmContextInstance(BasicBlock*, ExpressionType);
    enum class RestoreCachedStackLimit { No, Yes };
    void restoreWebAssemblyGlobalState(RestoreCachedStackLimit, const MemoryInformation&, ExpressionType instance, BasicBlock*);

    void emitWriteBarrierForJSWrapper();

    template<typename Function>
    void forEachLiveValue(Function&& function)
    {
        for (const auto& local : m_locals)
            function(local);
        for (unsigned controlIndex = 0; controlIndex < m_parser->controlStack().size(); ++controlIndex) {
            ControlData& data = m_parser->controlStack()[controlIndex].controlData;
            Stack& expressionStack = m_parser->controlStack()[controlIndex].enclosedExpressionStack;
            for (const auto& tmp : expressionStack)
                function(tmp.value());
            if (ControlType::isAnyCatch(data))
                function(data.exception());
        }
    }

    B3::Origin origin()
    {
        // FIXME: We should implement a way to give Inst's an origin, and pipe that
        // information into the sampling profiler: https://bugs.webkit.org/show_bug.cgi?id=234182
        return B3::Origin();
    }

    B3::Type toB3ResultType(BlockSignature returnType)
    {
        if (returnType->as<FunctionSignature>()->returnsVoid())
            return B3::Void;

        if (returnType->as<FunctionSignature>()->returnCount() == 1)
            return toB3Type(returnType->as<FunctionSignature>()->returnType(0));

        auto result = m_tupleMap.ensure(returnType, [&] {
            Vector<B3::Type> result;
            for (unsigned i = 0; i < returnType->as<FunctionSignature>()->returnCount(); ++i)
                result.append(toB3Type(returnType->as<FunctionSignature>()->returnType(i)));
            return m_proc.addTuple(WTFMove(result));
        });
        return result.iterator->value;
    }

    void unifyValuesWithBlock(const Stack& resultStack, const ResultList& stack);

    uint32_t outerLoopIndex() const
    {
        if (m_outerLoops.isEmpty())
            return UINT32_MAX;
        return m_outerLoops.last();
    }

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


    ExpressionType addBottom(BasicBlock*, Type);

    // References
    //                               addRefIsNull (in derived classes)
    PartialResult WARN_UNUSED_RETURN addRefFunc(uint32_t index, ExpressionType& result);

    // Globals
    PartialResult WARN_UNUSED_RETURN getGlobal(uint32_t index, ExpressionType& result);
    PartialResult WARN_UNUSED_RETURN setGlobal(uint32_t index, ExpressionType value);

    // Tables
    PartialResult WARN_UNUSED_RETURN addTableGet(unsigned, ExpressionType index, ExpressionType& result);
    PartialResult WARN_UNUSED_RETURN addTableSet(unsigned, ExpressionType index, ExpressionType value);
    PartialResult WARN_UNUSED_RETURN addTableInit(unsigned, unsigned, ExpressionType dstOffset, ExpressionType srcOffset, ExpressionType length);
    PartialResult WARN_UNUSED_RETURN addElemDrop(unsigned);
    PartialResult WARN_UNUSED_RETURN addTableSize(unsigned, ExpressionType& result);
    PartialResult WARN_UNUSED_RETURN addTableGrow(unsigned, ExpressionType fill, ExpressionType delta, ExpressionType& result);
    PartialResult WARN_UNUSED_RETURN addTableFill(unsigned, ExpressionType offset, ExpressionType fill, ExpressionType count);
    PartialResult WARN_UNUSED_RETURN addTableCopy(unsigned, unsigned, ExpressionType dstOffset, ExpressionType srcOffset, ExpressionType length);

    // Locals
    PartialResult WARN_UNUSED_RETURN getLocal(uint32_t index, ExpressionType& result);
    PartialResult WARN_UNUSED_RETURN setLocal(uint32_t index, ExpressionType value);
    // Memory
    PartialResult WARN_UNUSED_RETURN addGrowMemory(ExpressionType delta, ExpressionType& result);
    PartialResult WARN_UNUSED_RETURN addCurrentMemory(ExpressionType& result);
    PartialResult WARN_UNUSED_RETURN addMemoryFill(ExpressionType dstAddress, ExpressionType targetValue, ExpressionType count);
    PartialResult WARN_UNUSED_RETURN addMemoryCopy(ExpressionType dstAddress, ExpressionType srcAddress, ExpressionType count);
    PartialResult WARN_UNUSED_RETURN addMemoryInit(unsigned, ExpressionType dstAddress, ExpressionType srcAddress, ExpressionType length);
    PartialResult WARN_UNUSED_RETURN addDataDrop(unsigned);

    // Control flow
    //                               addReturn (in derived classes)
    PartialResult WARN_UNUSED_RETURN addBlock(BlockSignature, Stack& enclosingStack, ControlType& newBlock, Stack& newStack);
    PartialResult WARN_UNUSED_RETURN addLoop(BlockSignature, Stack& enclosingStack, ControlType& block, Stack& newStack, uint32_t loopIndex);
    PartialResult WARN_UNUSED_RETURN addIf(ExpressionType condition, BlockSignature, Stack& enclosingStack, ControlType& result, Stack& newStack);
    PartialResult WARN_UNUSED_RETURN addElse(ControlData&, const Stack&);
    PartialResult WARN_UNUSED_RETURN addElseToUnreachable(ControlData&);

    PartialResult WARN_UNUSED_RETURN addTry(BlockSignature, Stack& enclosingStack, ControlType& result, Stack& newStack);
    PartialResult WARN_UNUSED_RETURN addCatch(unsigned exceptionIndex, const TypeDefinition&, Stack&, ControlType&, ResultList&);
    PartialResult WARN_UNUSED_RETURN addCatchToUnreachable(unsigned exceptionIndex, const TypeDefinition&, ControlType&, ResultList&);
    PartialResult WARN_UNUSED_RETURN addCatchAll(Stack&, ControlType&);
    PartialResult WARN_UNUSED_RETURN addCatchAllToUnreachable(ControlType&);
    PartialResult WARN_UNUSED_RETURN addDelegate(ControlType&, ControlType&);
    PartialResult WARN_UNUSED_RETURN addDelegateToUnreachable(ControlType&, ControlType&);
    //                               addThrow
    //                               addRethrow (in derived classes)

    PartialResult WARN_UNUSED_RETURN addBranch(ControlData&, ExpressionType condition, const Stack& returnValues);
    PartialResult WARN_UNUSED_RETURN addSwitch(ExpressionType condition, const Vector<ControlData*>& targets, ControlData& defaultTargets, const Stack& expressionStack);
    PartialResult WARN_UNUSED_RETURN endBlock(ControlEntry&, Stack& expressionStack);
    PartialResult WARN_UNUSED_RETURN addEndToUnreachable(ControlEntry&, const Stack& expressionStack = { });

    // Calls
    PartialResult WARN_UNUSED_RETURN addCall(uint32_t calleeIndex, const TypeDefinition&, Vector<ExpressionType>& args, ResultList& results);
    PartialResult WARN_UNUSED_RETURN addCallIndirect(unsigned tableIndex, const TypeDefinition&, Vector<ExpressionType>& args, ResultList& results);
    PartialResult WARN_UNUSED_RETURN addCallRef(const TypeDefinition&, Vector<ExpressionType>& args, ResultList& results);
    PartialResult WARN_UNUSED_RETURN emitIndirectCall(ExpressionType calleeInstance, ExpressionType calleeCode, const TypeDefinition&, const Vector<ExpressionType>& args, ResultList&);
    PartialResult WARN_UNUSED_RETURN addUnreachable();

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
    static constexpr bool supportsPinnedStateRegisters = true;
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
void AirIRGeneratorBase<Derived, ExpressionType>::emitLoopTierUpCheck(uint32_t loopIndex, const Vector<ExpressionType>& liveValues)
{
    uint32_t outerLoopIndex = this->outerLoopIndex();
    m_outerLoops.append(loopIndex);

    if (!m_tierUp)
        return;

    ASSERT(m_tierUp->osrEntryTriggers().size() == loopIndex);
    m_tierUp->osrEntryTriggers().append(TierUpCount::TriggerReason::DontTrigger);
    m_tierUp->outerLoops().append(outerLoopIndex);

    auto countdownPtr = self().gPtr();
    append(Move, Arg::bigImm(bitwise_cast<uintptr_t>(&m_tierUp->m_counter)), countdownPtr);

    auto* patch = addPatchpoint(B3::Void);
    B3::Effects effects = B3::Effects::none();
    effects.reads = B3::HeapRange::top();
    effects.writes = B3::HeapRange::top();
    effects.exitsSideways = true;
    patch->effects = effects;

    patch->clobber(RegisterSet::macroScratchRegisters());
    RegisterSet clobberLate;
    clobberLate.add(GPRInfo::argumentGPR0);
    patch->clobberLate(clobberLate);

    Vector<ConstrainedTmp> patchArgs;
    patchArgs.append(countdownPtr);
    for (const auto& tmp : liveValues)
        patchArgs.append(ConstrainedTmp(tmp.tmp(), B3::ValueRep::ColdAny));

    TierUpCount::TriggerReason* forceEntryTrigger = &(m_tierUp->osrEntryTriggers().last());
    static_assert(!static_cast<uint8_t>(TierUpCount::TriggerReason::DontTrigger), "the JIT code assumes non-zero means 'enter'");
    static_assert(sizeof(TierUpCount::TriggerReason) == 1, "branchTest8 assumes this size");
    patch->setGenerator([=, this] (CCallHelpers& jit, const B3::StackmapGenerationParams& params) {
        AllowMacroScratchRegisterUsage allowScratch(jit);
        CCallHelpers::Jump forceOSREntry = jit.branchTest8(CCallHelpers::NonZero, CCallHelpers::AbsoluteAddress(forceEntryTrigger));
        CCallHelpers::Jump tierUp = jit.branchAdd32(CCallHelpers::PositiveOrZero, CCallHelpers::TrustedImm32(TierUpCount::loopIncrement()), CCallHelpers::Address(params[0].gpr()));
        MacroAssembler::Label tierUpResume = jit.label();

        // First argument is the countdown location.
        ASSERT(params.value()->numChildren() >= 1);
        StackMap values(params.value()->numChildren() - 1);
        for (unsigned i = 1; i < params.value()->numChildren(); ++i)
            values[i - 1] = OSREntryValue(params[i], params.value()->child(i)->type());

        OSREntryData& osrEntryData = m_tierUp->addOSREntryData(m_functionIndex, loopIndex, WTFMove(values));
        OSREntryData* osrEntryDataPtr = &osrEntryData;

        params.addLatePath([=] (CCallHelpers& jit) {
            AllowMacroScratchRegisterUsage allowScratch(jit);
            forceOSREntry.link(&jit);
            tierUp.link(&jit);

            jit.probe(tagCFunction<JITProbePtrTag>(operationWasmTriggerOSREntryNow), osrEntryDataPtr);
            jit.branchTestPtr(CCallHelpers::Zero, GPRInfo::argumentGPR0).linkTo(tierUpResume, &jit);
            jit.farJump(GPRInfo::argumentGPR1, WasmEntryPtrTag);
        });
    });

    emitPatchpoint(m_currentBlock, patch, ResultList { }, WTFMove(patchArgs));
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

template <typename Derived, typename ExpressionType>
void AirIRGeneratorBase<Derived, ExpressionType>::emitThrowException(CCallHelpers& jit, ExceptionType type)
{
    jit.move(CCallHelpers::TrustedImm32(static_cast<uint32_t>(type)), GPRInfo::argumentGPR1);
    auto jumpToExceptionStub = jit.jump();

    jit.addLinkTask([jumpToExceptionStub](LinkBuffer& linkBuffer) {
        linkBuffer.link(jumpToExceptionStub, CodeLocationLabel<JITThunkPtrTag>(Thunks::singleton().stub(throwExceptionFromWasmThunkGenerator).code()));
    });
}

template <typename Derived, typename ExpressionType>
void AirIRGeneratorBase<Derived, ExpressionType>::restoreWasmContextInstance(BasicBlock* block, ExpressionType instance)
{
    if (Context::useFastTLS()) {
        auto* patchpoint = addPatchpoint(B3::Void);
        if (CCallHelpers::storeWasmContextInstanceNeedsMacroScratchRegister())
            patchpoint->clobber(RegisterSet::macroScratchRegisters());
        patchpoint->setGenerator([=] (CCallHelpers& jit, const B3::StackmapGenerationParams& params) {
            AllowMacroScratchRegisterUsageIf allowScratch(jit, CCallHelpers::storeWasmContextInstanceNeedsMacroScratchRegister());
            jit.storeWasmContextInstance(params[0].gpr());
        });
        emitPatchpoint(block, patchpoint, Tmp(), instance);
        return;
    }

    // FIXME: Because WasmToWasm call clobbers wasmContextInstance register and does not restore it, we need to restore it in the caller side.
    // This prevents us from using ArgumentReg to this (logically) immutable pinned register.
    auto* patchpoint = addPatchpoint(B3::Void);
    B3::Effects effects = B3::Effects::none();
    effects.writesPinned = true;
    effects.reads = B3::HeapRange::top();
    patchpoint->effects = effects;
    patchpoint->clobberLate(RegisterSet(m_wasmContextInstanceGPR));
    GPRReg wasmContextInstanceGPR = m_wasmContextInstanceGPR;
    patchpoint->setGenerator([=] (CCallHelpers& jit, const B3::StackmapGenerationParams& param) {
        jit.move(param[0].gpr(), wasmContextInstanceGPR);
    });
    emitPatchpoint(block, patchpoint, Tmp(), instance);
}

template<typename Derived, typename ExpressionType>
void AirIRGeneratorBase<Derived, ExpressionType>::restoreWebAssemblyGlobalState(RestoreCachedStackLimit restoreCachedStackLimit, const MemoryInformation& memory, ExpressionType instance, BasicBlock* block)
{
    restoreWasmContextInstance(block, instance);

    if (restoreCachedStackLimit == RestoreCachedStackLimit::Yes) {
        // The Instance caches the stack limit, but also knows where its canonical location is.
        RELEASE_ASSERT(Arg::isValidAddrForm(Instance::offsetOfPointerToActualStackLimit(), B3::Width64));
        RELEASE_ASSERT(Arg::isValidAddrForm(Instance::offsetOfCachedStackLimit(), B3::Width64));
        auto temp = self().gPtr();
        append(block, Move, Arg::addr(instanceValue(), Instance::offsetOfPointerToActualStackLimit()), temp);
        append(block, Move, Arg::addr(temp), temp);
        append(block, Move, temp, Arg::addr(instanceValue(), Instance::offsetOfCachedStackLimit()));
    }

    if (!!memory && Derived::supportsPinnedStateRegisters) {
        const PinnedRegisterInfo* pinnedRegs = &PinnedRegisterInfo::get();
        RegisterSet clobbers;
        clobbers.set(pinnedRegs->baseMemoryPointer);
        clobbers.set(pinnedRegs->boundsCheckingSizeRegister);
        clobbers.set(RegisterSet::macroScratchRegisters());

        auto* patchpoint = addPatchpoint(B3::Void);
        B3::Effects effects = B3::Effects::none();
        effects.writesPinned = true;
        effects.reads = B3::HeapRange::top();
        patchpoint->effects = effects;
        patchpoint->clobber(clobbers);
        patchpoint->numGPScratchRegisters = 1;

        patchpoint->setGenerator([pinnedRegs] (CCallHelpers& jit, const B3::StackmapGenerationParams& params) {
            AllowMacroScratchRegisterUsage allowScratch(jit);
            GPRReg baseMemory = pinnedRegs->baseMemoryPointer;
            GPRReg scratch = params.gpScratch(0);

            jit.loadPtr(CCallHelpers::Address(params[0].gpr(), Instance::offsetOfCachedBoundsCheckingSize()), pinnedRegs->boundsCheckingSizeRegister);
            jit.loadPtr(CCallHelpers::Address(params[0].gpr(), Instance::offsetOfCachedMemory()), baseMemory);

            jit.cageConditionallyAndUntag(Gigacage::Primitive, baseMemory, pinnedRegs->boundsCheckingSizeRegister, scratch);
        });

        emitPatchpoint(block, patchpoint, Tmp(), instance);
    }
}

template<typename Derived, typename ExpressionType>
auto AirIRGeneratorBase<Derived, ExpressionType>::addBottom(BasicBlock* block, Type type) -> ExpressionType
{
    append(block, B3::Air::Oops);
    return self().addConstant(type, 0);
}

template <typename Derived, typename ExpressionType>
auto AirIRGeneratorBase<Derived, ExpressionType>::addRefFunc(uint32_t index, ExpressionType& result) -> PartialResult
{
    // FIXME: Emit this inline <https://bugs.webkit.org/show_bug.cgi?id=198506>.
    if (Options::useWebAssemblyTypedFunctionReferences()) {
        TypeIndex typeIndex = m_info.typeIndexFromFunctionIndexSpace(index);
        result = tmpForType(Type { TypeKind::Ref, Nullable::No, typeIndex });
    } else
        result = tmpForType(Types::Funcref);
    emitCCall(&operationWasmRefFunc, result, instanceValue(), self().addConstant(Types::I32, index));

    return {};
}

template<typename Derived, typename ExpressionType>
void AirIRGeneratorBase<Derived, ExpressionType>::emitWriteBarrierForJSWrapper()
{
    auto cell = self().g64();
    auto vm = self().g64();
    auto cellState = self().g32();
    auto threshold = self().g32();

    BasicBlock* fenceCheckPath = m_code.addBlock();
    BasicBlock* fencePath = m_code.addBlock();
    BasicBlock* doSlowPath = m_code.addBlock();
    BasicBlock* continuation = m_code.addBlock();

    append(Move, Arg::addr(instanceValue(), Instance::offsetOfOwner()), cell);
    append(Move, Arg::addr(cell, JSWebAssemblyInstance::offsetOfVM()), vm);
    append(Load8, Arg::addr(cell, JSCell::cellStateOffset()), cellState);
    append(Move32, Arg::addr(vm, VM::offsetOfHeapBarrierThreshold()), threshold);

    append(Branch32, Arg::relCond(MacroAssembler::Above), cellState, threshold);
    m_currentBlock->setSuccessors(continuation, fenceCheckPath);
    m_currentBlock = fenceCheckPath;

    append(Load8, Arg::addr(vm, VM::offsetOfHeapMutatorShouldBeFenced()), threshold);
    append(BranchTest32, Arg::resCond(MacroAssembler::Zero), threshold, threshold);
    m_currentBlock->setSuccessors(doSlowPath, fencePath);
    m_currentBlock = fencePath;

    auto* doFence = addPatchpoint(B3::Void);
    doFence->setGenerator([] (CCallHelpers& jit, const B3::StackmapGenerationParams&) {
        jit.memoryFence();
    });
    emitPatchpoint(doFence, Tmp());

    append(Load8, Arg::addr(cell, JSCell::cellStateOffset()), cellState);
    append(Branch32, Arg::relCond(MacroAssembler::Above), cellState, Arg::imm(blackThreshold));
    m_currentBlock->setSuccessors(continuation, doSlowPath);
    m_currentBlock = doSlowPath;

    emitCCall(&operationWasmWriteBarrierSlowPath, ExpressionType(), cell, vm);
    append(Jump);
    m_currentBlock->setSuccessors(continuation);
    m_currentBlock = continuation;
}


template <typename Derived, typename ExpressionType>
auto AirIRGeneratorBase<Derived, ExpressionType>::getGlobal(uint32_t index, ExpressionType& result) -> PartialResult
{
    const Wasm::GlobalInformation& global = m_info.globals[index];
    Type type = global.type;

    result = tmpForType(type);

    auto temp = self().gPtr();
    RELEASE_ASSERT(Arg::isValidAddrForm(Instance::offsetOfGlobals(), B3::pointerWidth()));
    append(Move, Arg::addr(instanceValue(), Instance::offsetOfGlobals()), temp);
    int32_t offset = safeCast<int32_t>(index * sizeof(Register));

    if (global.bindingMode == Wasm::GlobalInformation::BindingMode::Portable) {
        ASSERT(global.mutability == Wasm::Mutability::Mutable);
        if (Arg::isValidAddrForm(offset, B3::pointerWidth()))
            append(Move, Arg::addr(temp, offset), temp);
        else {
            auto temp2 = self().gPtr();
            append(Move, Arg::bigImm(offset), temp2);
            append(Derived::AddPtr, temp2, temp, temp);
            append(Move, Arg::addr(temp), temp);
        }
        offset = 0;
    } else
        ASSERT(global.bindingMode == Wasm::GlobalInformation::BindingMode::EmbeddedInInstance);

    result = tmpForType(type);
    self().emitLoad(temp, offset, result);
    return {};
}

template <typename Derived, typename ExpressionType>
auto AirIRGeneratorBase<Derived, ExpressionType>::setGlobal(uint32_t index, ExpressionType value) -> PartialResult
{
    const Wasm::GlobalInformation& global = m_info.globals[index];
    Type type = global.type;

    auto temp = self().gPtr();
    RELEASE_ASSERT(Arg::isValidAddrForm(Instance::offsetOfGlobals(), B3::pointerWidth()));
    append(Move, Arg::addr(instanceValue(), Instance::offsetOfGlobals()), temp);
    int32_t offset = safeCast<int32_t>(index * sizeof(Register));

    if (global.bindingMode == Wasm::GlobalInformation::BindingMode::Portable) {
        ASSERT(global.mutability == Wasm::Mutability::Mutable);
        if (Arg::isValidAddrForm(offset, B3::pointerWidth()))
            append(Move, Arg::addr(temp, offset), temp);
        else {
            auto temp2 = self().gPtr();
            append(Move, Arg::bigImm(offset), temp2);
            append(Derived::AddPtr, temp2, temp, temp);
            append(Move, Arg::addr(temp), temp);
        }
        offset = 0;
    } else
        ASSERT(global.bindingMode == Wasm::GlobalInformation::BindingMode::EmbeddedInInstance);


    self().emitStore(value, temp, offset);

    if (isRefType(type)) {
        switch (global.bindingMode) {
        case Wasm::GlobalInformation::BindingMode::EmbeddedInInstance:
            emitWriteBarrierForJSWrapper();
            break;
        case Wasm::GlobalInformation::BindingMode::Portable:
            auto cell = self().gPtr();
            auto vm = self().gPtr();
            auto cellState = self().g32();
            auto threshold = self().g32();

            BasicBlock* fenceCheckPath = m_code.addBlock();
            BasicBlock* fencePath = m_code.addBlock();
            BasicBlock* doSlowPath = m_code.addBlock();
            BasicBlock* continuation = m_code.addBlock();

            append(Move, Arg::addr(instanceValue(), Instance::offsetOfOwner()), cell);
            append(Move, Arg::addr(cell, JSWebAssemblyInstance::offsetOfVM()), vm);

            append(Move, Arg::addr(temp, Wasm::Global::offsetOfOwner() - Wasm::Global::offsetOfValue()), cell);
            append(Load8, Arg::addr(cell, JSCell::cellStateOffset()), cellState);
            append(Move32, Arg::addr(vm, VM::offsetOfHeapBarrierThreshold()), threshold);

            append(Branch32, Arg::relCond(MacroAssembler::Above), cellState, threshold);
            m_currentBlock->setSuccessors(continuation, fenceCheckPath);
            m_currentBlock = fenceCheckPath;

            append(Load8, Arg::addr(vm, VM::offsetOfHeapMutatorShouldBeFenced()), threshold);
            append(BranchTest32, Arg::resCond(MacroAssembler::Zero), threshold, threshold);
            m_currentBlock->setSuccessors(doSlowPath, fencePath);
            m_currentBlock = fencePath;

            auto* doFence = addPatchpoint(B3::Void);
            doFence->setGenerator([](CCallHelpers& jit, const B3::StackmapGenerationParams&) {
                jit.memoryFence();
            });
            emitPatchpoint(doFence, ExpressionType());

            append(Load8, Arg::addr(cell, JSCell::cellStateOffset()), cellState);
            append(Branch32, Arg::relCond(MacroAssembler::Above), cellState, Arg::imm(blackThreshold));
            m_currentBlock->setSuccessors(continuation, doSlowPath);
            m_currentBlock = doSlowPath;

            emitCCall(&operationWasmWriteBarrierSlowPath, ExpressionType(), cell, vm);
            append(Jump);
            m_currentBlock->setSuccessors(continuation);
            m_currentBlock = continuation;
            break;
        }
    }

    return { };
}


template <typename Derived, typename ExpressionType>
auto AirIRGeneratorBase<Derived, ExpressionType>::addTableInit(unsigned elementIndex, unsigned tableIndex, ExpressionType dstOffset, ExpressionType srcOffset, ExpressionType length) -> PartialResult
{
    ASSERT(dstOffset.tmp());
    ASSERT(dstOffset.type().isI32());

    ASSERT(srcOffset.tmp());
    ASSERT(srcOffset.type().isI32());

    ASSERT(length.tmp());
    ASSERT(length.type().isI32());

    auto result = tmpForType(Types::I32);
    emitCCall(
        &operationWasmTableInit, result, instanceValue(),
        self().addConstant(Types::I32, elementIndex),
        self().addConstant(Types::I32, tableIndex),
        dstOffset, srcOffset, length);

    emitCheck([&] {
        return Inst(BranchTest32, nullptr, Arg::resCond(MacroAssembler::Zero), result, result);
    }, [=, this] (CCallHelpers& jit, const B3::StackmapGenerationParams&) {
        this->emitThrowException(jit, ExceptionType::OutOfBoundsTableAccess);
    });

    return { };
}

template <typename Derived, typename ExpressionType>
auto AirIRGeneratorBase<Derived, ExpressionType>::addElemDrop(unsigned elementIndex) -> PartialResult
{
    emitCCall(&operationWasmElemDrop, ExpressionType(), instanceValue(), self().addConstant(Types::I32, elementIndex));
    return { };
}

template <typename Derived, typename ExpressionType>
auto AirIRGeneratorBase<Derived, ExpressionType>::addTableSize(unsigned tableIndex, ExpressionType& result) -> PartialResult
{
    // FIXME: Emit this inline <https://bugs.webkit.org/show_bug.cgi?id=198506>.
    result = tmpForType(Types::I32);

    emitCCall(&operationGetWasmTableSize, result, instanceValue(), self().addConstant(Types::I32, tableIndex));

    return { };
}

template <typename Derived, typename ExpressionType>
auto AirIRGeneratorBase<Derived, ExpressionType>::addTableGrow(unsigned tableIndex, ExpressionType fill, ExpressionType delta, ExpressionType& result) -> PartialResult
{
    ASSERT(fill.tmp());
    ASSERT(isSubtype(fill.type(), m_info.tables[tableIndex].wasmType()));
    ASSERT(delta.tmp());
    ASSERT(delta.type().isI32());
    result = tmpForType(Types::I32);

    emitCCall(&operationWasmTableGrow, result, instanceValue(), self().addConstant(Types::I32, tableIndex), fill, delta);

    return { };
}

template <typename Derived, typename ExpressionType>
auto AirIRGeneratorBase<Derived, ExpressionType>::addTableFill(unsigned tableIndex, ExpressionType offset, ExpressionType fill, ExpressionType count) -> PartialResult
{
    ASSERT(fill.tmp());
    ASSERT(isSubtype(fill.type(), m_info.tables[tableIndex].wasmType()));
    ASSERT(offset.tmp());
    ASSERT(offset.type().isI32());
    ASSERT(count.tmp());
    ASSERT(count.type().isI32());

    auto result = tmpForType(Types::I32);
    emitCCall(&operationWasmTableFill, result, instanceValue(), self().addConstant(Types::I32, tableIndex), offset, fill, count);

    emitCheck([&] {
        return Inst(BranchTest32, nullptr, Arg::resCond(MacroAssembler::Zero), result, result);
    }, [=, this] (CCallHelpers& jit, const B3::StackmapGenerationParams&) {
        this->emitThrowException(jit, ExceptionType::OutOfBoundsTableAccess);
    });

    return { };
}

template <typename Derived, typename ExpressionType>
auto AirIRGeneratorBase<Derived, ExpressionType>::addTableCopy(unsigned dstTableIndex, unsigned srcTableIndex, ExpressionType dstOffset, ExpressionType srcOffset, ExpressionType length) -> PartialResult
{
    ASSERT(dstOffset.tmp());
    ASSERT(dstOffset.type().isI32());

    ASSERT(srcOffset.tmp());
    ASSERT(srcOffset.type().isI32());

    ASSERT(length.tmp());
    ASSERT(length.type().isI32());

    auto result = self().tmpForType(Types::I32);
    emitCCall(
        &operationWasmTableCopy, result, instanceValue(),
        self().addConstant(Types::I32, dstTableIndex),
        self().addConstant(Types::I32, srcTableIndex),
        dstOffset, srcOffset, length);

    emitCheck([&] {
        return Inst(BranchTest32, nullptr, Arg::resCond(MacroAssembler::Zero), result, result);
    }, [=, this] (CCallHelpers& jit, const B3::StackmapGenerationParams&) {
        this->emitThrowException(jit, ExceptionType::OutOfBoundsTableAccess);
    });

    return { };
}

template <typename Derived, typename ExpressionType>
auto AirIRGeneratorBase<Derived, ExpressionType>::addTableGet(unsigned tableIndex, ExpressionType index, ExpressionType& result) -> PartialResult
{
    // FIXME: Emit this inline <https://bugs.webkit.org/show_bug.cgi?id=198506>.
    ASSERT(index.tmp());

    ASSERT(index.type().isI32());
    result = self().tmpForType(m_info.tables[tableIndex].wasmType());

    emitCCall(&operationGetWasmTableElement, result, instanceValue(), self().addConstant(Types::I32, tableIndex), index);

    self().emitCheckI64Zero(result, [=, this](CCallHelpers &jit, const B3::StackmapGenerationParams &) {
        this->emitThrowException(jit, ExceptionType::OutOfBoundsTableAccess);
    });

    return {};
}

template <typename Derived, typename ExpressionType>
auto AirIRGeneratorBase<Derived, ExpressionType>::addTableSet(unsigned tableIndex, ExpressionType index, ExpressionType value) -> PartialResult
{
    // FIXME: Emit this inline <https://bugs.webkit.org/show_bug.cgi?id=198506>.
    ASSERT(index.tmp());
    ASSERT(index.type().isI32());
    ASSERT(value.tmp());

    auto shouldThrow = self().g32();
    emitCCall(&operationSetWasmTableElement, shouldThrow, instanceValue(), self().addConstant(Types::I32, tableIndex), index, value);

    emitCheck([&] { return Inst(BranchTest32, nullptr, Arg::resCond(MacroAssembler::Zero), shouldThrow, shouldThrow); }, [=, this](CCallHelpers& jit, const B3::StackmapGenerationParams&) { this->emitThrowException(jit, ExceptionType::OutOfBoundsTableAccess); });

    return {};
}

template <typename Derived, typename ExpressionType>
auto AirIRGeneratorBase<Derived, ExpressionType>::getLocal(uint32_t index, ExpressionType& result) -> PartialResult
{
    auto local = m_locals[index];
    ASSERT(local);
    result = self().tmpForType(local.type());
    self().emitMove(local, result);
    return {};
}

template <typename Derived, typename ExpressionType>
auto AirIRGeneratorBase<Derived, ExpressionType>::setLocal(uint32_t index, ExpressionType value) -> PartialResult
{
    auto local = m_locals[index];
    ASSERT(local);
    self().emitMove(value, local);
    return {};
}

// Memory accesses in WebAssembly have unsigned 32-bit offsets, whereas they have signed 32-bit offsets in B3.
template<typename Derived, typename ExpressionType>
int32_t AirIRGeneratorBase<Derived, ExpressionType>::fixupPointerPlusOffset(ExpressionType& ptr, uint32_t offset)
{
    if (static_cast<uint64_t>(offset) > static_cast<uint64_t>(std::numeric_limits<int32_t>::max())) {
        auto previousPtr = ptr;
        ptr = self().gPtr();
        auto constant = self().gPtr();
        append(Move, Arg::bigImm(offset), constant);
        append(Derived::AddPtr, constant, previousPtr, ptr);
        return 0;
    }
    return offset;
}

// TODO(jgriego) find a better home for these
inline uint32_t sizeOfLoadOp(LoadOpType op)
{
    switch (op) {
    case LoadOpType::I32Load8S:
    case LoadOpType::I32Load8U:
    case LoadOpType::I64Load8S:
    case LoadOpType::I64Load8U:
        return 1;
    case LoadOpType::I32Load16S:
    case LoadOpType::I64Load16S:
    case LoadOpType::I32Load16U:
    case LoadOpType::I64Load16U:
        return 2;
    case LoadOpType::I32Load:
    case LoadOpType::I64Load32S:
    case LoadOpType::I64Load32U:
    case LoadOpType::F32Load:
        return 4;
    case LoadOpType::I64Load:
    case LoadOpType::F64Load:
        return 8;
    }
    RELEASE_ASSERT_NOT_REACHED();
}

inline uint32_t sizeOfStoreOp(StoreOpType op)
{
    switch (op) {
    case StoreOpType::I32Store8:
    case StoreOpType::I64Store8:
        return 1;
    case StoreOpType::I32Store16:
    case StoreOpType::I64Store16:
        return 2;
    case StoreOpType::I32Store:
    case StoreOpType::I64Store32:
    case StoreOpType::F32Store:
        return 4;
    case StoreOpType::I64Store:
    case StoreOpType::F64Store:
        return 8;
    }
    RELEASE_ASSERT_NOT_REACHED();
}

template <typename Derived, typename ExpressionType>
auto AirIRGeneratorBase<Derived, ExpressionType>::addGrowMemory(ExpressionType delta, ExpressionType& result) -> PartialResult
{
    result = self().g32();
    emitCCall(&operationGrowMemory, result, ExpressionType { Tmp(GPRInfo::callFrameRegister), Types::IPtr }, instanceValue(), delta);
    restoreWebAssemblyGlobalState(RestoreCachedStackLimit::No, m_info.memory, instanceValue(), m_currentBlock);

    return { };
}

template <typename Derived, typename ExpressionType>
auto AirIRGeneratorBase<Derived, ExpressionType>::addCurrentMemory(ExpressionType& result) -> PartialResult
{
    auto temp1 = self().gPtr();
    auto temp2 = self().gPtr();

    RELEASE_ASSERT(Arg::isValidAddrForm(Instance::offsetOfMemory(), B3::Width64));
    RELEASE_ASSERT(Arg::isValidAddrForm(Memory::offsetOfHandle(), B3::Width64));
    RELEASE_ASSERT(Arg::isValidAddrForm(MemoryHandle::offsetOfSize(), B3::Width64));
    append(Move, Arg::addr(instanceValue(), Instance::offsetOfMemory()), temp1);
    append(Move, Arg::addr(temp1, Memory::offsetOfHandle()), temp1);
    append(Move, Arg::addr(temp1, MemoryHandle::offsetOfSize()), temp1);
    constexpr uint32_t shiftValue = 16;
    static_assert(PageCount::pageSize == 1ull << shiftValue, "This must hold for the code below to be correct.");
    append(Move, Arg::imm(16), temp2);
    self().addShift(Types::I32, Derived::UrshiftPtr, temp1, temp2, result);
    append(Move32, result, result);

    return { };
}


template <typename Derived, typename ExpressionType>
auto AirIRGeneratorBase<Derived, ExpressionType>::addMemoryFill(ExpressionType dstAddress, ExpressionType targetValue, ExpressionType count) -> PartialResult
{
    ASSERT(dstAddress.tmp());
    ASSERT(dstAddress.type().isI32());

    ASSERT(targetValue.tmp());
    ASSERT(targetValue.type().isI32());

    ASSERT(count.tmp());
    ASSERT(count.type().isI32());

    auto result = tmpForType(Types::I32);
    emitCCall(
        &operationWasmMemoryFill, result, instanceValue(),
        dstAddress, targetValue, count);

    emitCheck([&] {
        return Inst(BranchTest32, nullptr, Arg::resCond(MacroAssembler::Zero), result, result);
    }, [=, this] (CCallHelpers& jit, const B3::StackmapGenerationParams&) {
        this->emitThrowException(jit, ExceptionType::OutOfBoundsMemoryAccess);
    });

    return { };
}

template <typename Derived, typename ExpressionType>
auto AirIRGeneratorBase<Derived, ExpressionType>::addMemoryCopy(ExpressionType dstAddress, ExpressionType srcAddress, ExpressionType count) -> PartialResult
{
    ASSERT(dstAddress.tmp());
    ASSERT(dstAddress.type().isI32());

    ASSERT(srcAddress.tmp());
    ASSERT(srcAddress.type().isI32());

    ASSERT(count.tmp());
    ASSERT(count.type().isI32());

    auto result = tmpForType(Types::I32);
    emitCCall(
        &operationWasmMemoryCopy, result, instanceValue(),
        dstAddress, srcAddress, count);

    emitCheck([&] {
        return Inst(BranchTest32, nullptr, Arg::resCond(MacroAssembler::Zero), result, result);
    }, [=, this] (CCallHelpers& jit, const B3::StackmapGenerationParams&) {
        this->emitThrowException(jit, ExceptionType::OutOfBoundsMemoryAccess);
    });

    return { };
}

template <typename Derived, typename ExpressionType>
auto AirIRGeneratorBase<Derived, ExpressionType>::addMemoryInit(unsigned dataSegmentIndex, ExpressionType dstAddress, ExpressionType srcAddress, ExpressionType length) -> PartialResult
{
    ASSERT(dstAddress.tmp());
    ASSERT(dstAddress.type().isI32());

    ASSERT(srcAddress.tmp());
    ASSERT(srcAddress.type().isI32());

    ASSERT(length.tmp());
    ASSERT(length.type().isI32());

    auto result = tmpForType(Types::I32);
    emitCCall(
        &operationWasmMemoryInit, result, instanceValue(),
        self().addConstant(Types::I32, dataSegmentIndex),
        dstAddress, srcAddress, length);

    emitCheck([&] {
        return Inst(BranchTest32, nullptr, Arg::resCond(MacroAssembler::Zero), result, result);
    }, [=, this] (CCallHelpers& jit, const B3::StackmapGenerationParams&) {
        this->emitThrowException(jit, ExceptionType::OutOfBoundsMemoryAccess);
    });

    return {};
}

template <typename Derived, typename ExpressionType>
auto AirIRGeneratorBase<Derived, ExpressionType>::addDataDrop(unsigned dataSegmentIndex) -> PartialResult
{
    emitCCall(&operationWasmDataDrop, ExpressionType(), instanceValue(), self().addConstant(Types::I32, dataSegmentIndex));
    return {};
}

template <typename Derived, typename ExpressionType>
void AirIRGeneratorBase<Derived, ExpressionType>::unifyValuesWithBlock(const Stack& resultStack, const ResultList& result)
{
    ASSERT(result.size() <= resultStack.size());

    for (size_t i = 0; i < result.size(); ++i)
        self().emitMove(resultStack[resultStack.size() - 1 - i], result[result.size() - 1 - i]);
}

template <typename Derived, typename ExpressionType>
auto AirIRGeneratorBase<Derived, ExpressionType>::addLoop(BlockSignature signature, Stack& enclosingStack, ControlType& block, Stack& newStack, uint32_t loopIndex) -> PartialResult
{
    RELEASE_ASSERT(loopIndex == m_loopEntryVariableData.size());

    BasicBlock* body = m_code.addBlock();
    BasicBlock* continuation = m_code.addBlock();

    splitStack(signature, enclosingStack, newStack);

    Vector<ExpressionType> liveValues;
    forEachLiveValue([&] (auto tmp) {
        liveValues.append(tmp);
    });
    for (auto variable : enclosingStack)
        liveValues.append(variable);
    for (auto variable : newStack)
        liveValues.append(variable);

    ResultList results;
    results.reserveInitialCapacity(newStack.size());
    for (auto item : newStack)
        results.uncheckedAppend(item);
    block = ControlData(origin(), signature, WTFMove(results), BlockType::Loop, continuation, body);

    append(Jump);
    m_currentBlock->setSuccessors(body);

    m_currentBlock = body;
    emitLoopTierUpCheck(loopIndex, liveValues);

    m_loopEntryVariableData.append(std::pair<BasicBlock*, Vector<ExpressionType>>(body, WTFMove(liveValues)));

    return { };
}

template <typename Derived, typename ExpressionType>
auto AirIRGeneratorBase<Derived, ExpressionType>::addBlock(BlockSignature signature, Stack& enclosingStack, ControlType& newBlock, Stack& newStack) -> PartialResult
{
    splitStack(signature, enclosingStack, newStack);
    newBlock = ControlData(origin(), signature, tmpsForSignature(signature), BlockType::Block, m_code.addBlock());
    return { };
}

template <typename Derived, typename ExpressionType>
auto AirIRGeneratorBase<Derived, ExpressionType>::addIf(ExpressionType condition, BlockSignature signature, Stack& enclosingStack, ControlType& result, Stack& newStack) -> PartialResult
{
    BasicBlock* taken = m_code.addBlock();
    BasicBlock* notTaken = m_code.addBlock();
    BasicBlock* continuation = m_code.addBlock();
    B3::FrequencyClass takenFrequency = B3::FrequencyClass::Normal;
    B3::FrequencyClass notTakenFrequency= B3::FrequencyClass::Normal;

    if (Options::useWebAssemblyBranchHints()) {
        BranchHint hint = m_info.getBranchHint(m_functionIndex, m_parser->currentOpcodeStartingOffset());

        switch (hint) {
        case BranchHint::Unlikely:
            takenFrequency = B3::FrequencyClass::Rare;
            break;
        case BranchHint::Likely:
            notTakenFrequency = B3::FrequencyClass::Rare;
            break;
        case BranchHint::Invalid:
            break;
        }
    }

    // Wasm bools are i32.
    append(BranchTest32, Arg::resCond(MacroAssembler::NonZero), condition, condition);
    m_currentBlock->setSuccessors(FrequentedBlock(taken, takenFrequency), FrequentedBlock(notTaken, notTakenFrequency));

    m_currentBlock = taken;
    splitStack(signature, enclosingStack, newStack);
    result = ControlData(origin(), signature, tmpsForSignature(signature), BlockType::If, continuation, notTaken);
    return { };
}

template <typename Derived, typename ExpressionType>
auto AirIRGeneratorBase<Derived, ExpressionType>::addElse(ControlData& data, const Stack& currentStack) -> PartialResult
{
    unifyValuesWithBlock(currentStack, data.results);
    append(Jump);
    m_currentBlock->setSuccessors(data.continuation);
    return addElseToUnreachable(data);
}

template <typename Derived, typename ExpressionType>
auto AirIRGeneratorBase<Derived, ExpressionType>::addElseToUnreachable(ControlData& data) -> PartialResult
{
    ASSERT(data.blockType() == BlockType::If);
    m_currentBlock = data.special;
    data.convertIfToBlock();
    return { };
}

template <typename Derived, typename ExpressionType>
auto AirIRGeneratorBase<Derived, ExpressionType>::addTry(BlockSignature signature, Stack& enclosingStack, ControlType& result, Stack& newStack) -> PartialResult
{
    ++m_tryCatchDepth;

    BasicBlock* continuation = m_code.addBlock();
    splitStack(signature, enclosingStack, newStack);
    result = ControlData(origin(), signature, tmpsForSignature(signature), BlockType::Try, continuation, ++m_callSiteIndex, m_tryCatchDepth);
    return { };
}

template <typename Derived, typename ExpressionType>
auto AirIRGeneratorBase<Derived, ExpressionType>::addCatch(unsigned exceptionIndex, const TypeDefinition& signature, Stack& currentStack, ControlType& data, ResultList& results) -> PartialResult
{
    unifyValuesWithBlock(currentStack, data.results);
    append(Jump);
    m_currentBlock->setSuccessors(data.continuation);
    return addCatchToUnreachable(exceptionIndex, signature, data, results);
}

template <typename Derived, typename ExpressionType>
auto AirIRGeneratorBase<Derived, ExpressionType>::addCatchAll(Stack& currentStack, ControlType& data) -> PartialResult
{
    unifyValuesWithBlock(currentStack, data.results);
    append(Jump);
    m_currentBlock->setSuccessors(data.continuation);
    return addCatchAllToUnreachable(data);
}

template <typename Derived, typename ExpressionType>
auto AirIRGeneratorBase<Derived, ExpressionType>::addCatchToUnreachable(unsigned exceptionIndex, const TypeDefinition& signature, ControlType& data, ResultList& results) -> PartialResult
{
    Tmp buffer = self().emitCatchImpl(CatchKind::Catch, data, exceptionIndex);
    for (unsigned i = 0; i < signature.as<FunctionSignature>()->argumentCount(); ++i) {
        Type type = signature.as<FunctionSignature>()->argumentType(i);
        auto tmp = tmpForType(type);
        self().emitLoad(buffer, i * sizeof(uint64_t), tmp);
        results.append(tmp);
    }
    return { };
}

template <typename Derived, typename ExpressionType>
auto AirIRGeneratorBase<Derived, ExpressionType>::addCatchAllToUnreachable(ControlType& data) -> PartialResult
{
    self().emitCatchImpl(CatchKind::CatchAll, data);
    return { };
}

template <typename Derived, typename ExpressionType>
auto AirIRGeneratorBase<Derived, ExpressionType>::addDelegate(ControlType& target, ControlType& data) -> PartialResult
{
    return addDelegateToUnreachable(target, data);
}

template <typename Derived, typename ExpressionType>
auto AirIRGeneratorBase<Derived, ExpressionType>::addDelegateToUnreachable(ControlType& target, ControlType& data) -> PartialResult
{
    unsigned targetDepth = 0;
    if (ControlType::isTry(target))
        targetDepth = target.tryDepth();

    m_exceptionHandlers.append({ HandlerType::Delegate, data.tryStart(), ++m_callSiteIndex, 0, m_tryCatchDepth, targetDepth });
    return {};
}

// NOTE: All branches in Wasm are on 32-bit ints

template <typename Derived, typename ExpressionType>
auto AirIRGeneratorBase<Derived, ExpressionType>::addBranch(ControlData& data, ExpressionType condition, const Stack& returnValues) -> PartialResult
{
    unifyValuesWithBlock(returnValues, data.results);

    BasicBlock* target = data.targetBlockForBranch();
    B3::FrequencyClass targetFrequency = B3::FrequencyClass::Normal;
    B3::FrequencyClass continuationFrequency = B3::FrequencyClass::Normal;

    if (Options::useWebAssemblyBranchHints()) {
        BranchHint hint = m_info.getBranchHint(m_functionIndex, m_parser->currentOpcodeStartingOffset());

        switch (hint) {
        case BranchHint::Unlikely:
            targetFrequency = B3::FrequencyClass::Rare;
            break;
        case BranchHint::Likely:
            continuationFrequency = B3::FrequencyClass::Rare;
            break;
        case BranchHint::Invalid:
            break;
        }
    }

    if (condition) {
        BasicBlock* continuation = m_code.addBlock();
        append(BranchTest32, Arg::resCond(MacroAssembler::NonZero), condition, condition);
        m_currentBlock->setSuccessors(FrequentedBlock(target, targetFrequency), FrequentedBlock(continuation, continuationFrequency));
        m_currentBlock = continuation;
    } else {
        append(Jump);
        m_currentBlock->setSuccessors(FrequentedBlock(target, targetFrequency));
    }

    return { };
}

template <typename Derived, typename ExpressionType>
auto AirIRGeneratorBase<Derived, ExpressionType>::addSwitch(ExpressionType condition, const Vector<ControlData*>& targets, ControlData& defaultTarget, const Stack& expressionStack) -> PartialResult
{
    auto& successors = m_currentBlock->successors();
    ASSERT(successors.isEmpty());
    for (const auto& target : targets) {
        unifyValuesWithBlock(expressionStack, target->results);
        successors.append(target->targetBlockForBranch());
    }
    unifyValuesWithBlock(expressionStack, defaultTarget.results);
    successors.append(defaultTarget.targetBlockForBranch());

    ASSERT(condition.type().isI32());

    // FIXME: We should consider dynamically switching between a jump table
    // and a binary switch depending on the number of successors.
    // https://bugs.webkit.org/show_bug.cgi?id=194477

    size_t numTargets = targets.size();

    auto* patchpoint = addPatchpoint(B3::Void);
    patchpoint->effects = B3::Effects::none();
    patchpoint->effects.terminal = true;
    patchpoint->clobber(RegisterSet::macroScratchRegisters());

    patchpoint->setGenerator([=] (CCallHelpers& jit, const B3::StackmapGenerationParams& params) {
        AllowMacroScratchRegisterUsage allowScratch(jit);

        Vector<int64_t> cases;
        cases.reserveInitialCapacity(numTargets);
        for (size_t i = 0; i < numTargets; ++i)
            cases.uncheckedAppend(i);

        GPRReg valueReg = params[0].gpr();
        BinarySwitch binarySwitch(valueReg, cases, BinarySwitch::Int32);

        Vector<CCallHelpers::Jump> caseJumps;
        caseJumps.resize(numTargets);

        while (binarySwitch.advance(jit)) {
            unsigned value = binarySwitch.caseValue();
            unsigned index = binarySwitch.caseIndex();
            ASSERT_UNUSED(value, value == index);
            ASSERT(index < numTargets);
            caseJumps[index] = jit.jump();
        }

        CCallHelpers::JumpList fallThrough = binarySwitch.fallThrough();

        Vector<Box<CCallHelpers::Label>> successorLabels = params.successorLabels();
        ASSERT(successorLabels.size() == caseJumps.size() + 1);

        params.addLatePath([=, caseJumps = WTFMove(caseJumps), successorLabels = WTFMove(successorLabels)] (CCallHelpers& jit) {
            for (size_t i = 0; i < numTargets; ++i)
                caseJumps[i].linkTo(*successorLabels[i], &jit);                
            fallThrough.linkTo(*successorLabels[numTargets], &jit);
        });
    });

    emitPatchpoint(patchpoint, ExpressionType(), condition);

    return { };
}

template <typename Derived, typename ExpressionType>
auto AirIRGeneratorBase<Derived, ExpressionType>::endBlock(ControlEntry& entry, Stack& expressionStack) -> PartialResult
{
    ControlData& data = entry.controlData;

    if (data.blockType() != BlockType::Loop)
        unifyValuesWithBlock(expressionStack, data.results);
    append(Jump);
    m_currentBlock->setSuccessors(data.continuation);

    return addEndToUnreachable(entry, expressionStack);
}

template <typename Derived, typename ExpressionType>
auto AirIRGeneratorBase<Derived, ExpressionType>::addEndToUnreachable(ControlEntry& entry, const Stack& expressionStack) -> PartialResult
{
    ControlData& data = entry.controlData;
    m_currentBlock = data.continuation;

    if (data.blockType() == BlockType::If) {
        append(data.special, Jump);
        data.special->setSuccessors(m_currentBlock);
    } else if (data.blockType() == BlockType::Try || data.blockType() == BlockType::Catch)
        --m_tryCatchDepth;

    if (data.blockType() == BlockType::Loop) {
        m_outerLoops.removeLast();
        for (unsigned i = 0; i < data.signature()->template as<FunctionSignature>()->returnCount(); ++i) {
            if (i < expressionStack.size())
                entry.enclosedExpressionStack.append(expressionStack[i]);
            else {
                Type type = data.signature()->template as<FunctionSignature>()->returnType(i);
                entry.enclosedExpressionStack.constructAndAppend(type, addBottom(m_currentBlock, type));
            }
        }
    } else {
        for (unsigned i = 0; i < data.signature()->template as<FunctionSignature>()->returnCount(); ++i)
            entry.enclosedExpressionStack.constructAndAppend(data.signature()->template as<FunctionSignature>()->returnType(i), data.results[i]);
    }

    // TopLevel does not have any code after this so we need to make sure we emit a return here.
    if (data.blockType() == BlockType::TopLevel)
        return self().addReturn(data, entry.enclosedExpressionStack);

    return { };
}

template<typename Derived, typename ExpressionType>
auto AirIRGeneratorBase<Derived, ExpressionType>::addCall(uint32_t functionIndex, const TypeDefinition& signature, Vector<ExpressionType>& args, ResultList& results) -> PartialResult
{
    ASSERT(signature.as<FunctionSignature>()->argumentCount() == args.size());

    m_makesCalls = true;

    for (unsigned i = 0; i < signature.as<FunctionSignature>()->returnCount(); ++i)
        results.append(tmpForType(signature.as<FunctionSignature>()->returnType(i)));

    Vector<UnlinkedWasmToWasmCall>* unlinkedWasmToWasmCalls = &m_unlinkedWasmToWasmCalls;

    if (m_info.isImportedFunctionFromFunctionIndexSpace(functionIndex)) {
        m_maxNumJSCallArguments = std::max(m_maxNumJSCallArguments, static_cast<uint32_t>(args.size()));

        auto currentInstance = self().gPtr();
        append(Move, instanceValue(), currentInstance);

        auto targetInstance = self().gPtr();

        // FIXME: We should have better isel here.
        // https://bugs.webkit.org/show_bug.cgi?id=193999
        append(Move, Arg::bigImm(Instance::offsetOfTargetInstance(functionIndex)), targetInstance);
        append(Derived::AddPtr, instanceValue(), targetInstance);
        append(Move, Arg::addr(targetInstance), targetInstance);

        BasicBlock* isWasmBlock = m_code.addBlock();
        BasicBlock* isEmbedderBlock = m_code.addBlock();
        BasicBlock* continuation = m_code.addBlock();

        append(Derived::BranchTestPtr, Arg::resCond(MacroAssembler::NonZero), targetInstance, targetInstance);
        m_currentBlock->setSuccessors(isWasmBlock, isEmbedderBlock);

        {
            auto pair = self().emitCallPatchpoint(isWasmBlock, signature, results, args);
            auto* patchpoint = pair.first;
            auto exceptionHandle = pair.second;
            // We need to clobber all potential pinned registers since we might be leaving the instance.
            // We pessimistically assume we could be calling to something that is bounds checking.
            // FIXME: We shouldn't have to do this: https://bugs.webkit.org/show_bug.cgi?id=172181
            patchpoint->clobberLate(PinnedRegisterInfo::get().toSave(MemoryMode::BoundsChecking));

            patchpoint->setGenerator([=, this] (CCallHelpers& jit, const B3::StackmapGenerationParams& params) {
                AllowMacroScratchRegisterUsage allowScratch(jit);
                exceptionHandle.generate(jit, params, this);
                CCallHelpers::Call call = jit.threadSafePatchableNearCall();
                jit.addLinkTask([unlinkedWasmToWasmCalls, call, functionIndex] (LinkBuffer& linkBuffer) {
                    unlinkedWasmToWasmCalls->append({ linkBuffer.locationOfNearCall<WasmEntryPtrTag>(call), functionIndex });
                });
            });

            append(isWasmBlock, Jump);
            isWasmBlock->setSuccessors(continuation);
        }

        {
            auto jumpDestination = self().gPtr();
            append(isEmbedderBlock, Move, Arg::bigImm(Instance::offsetOfWasmToEmbedderStub(functionIndex)), jumpDestination);
            append(isEmbedderBlock, Derived::AddPtr, instanceValue(), jumpDestination);
            append(isEmbedderBlock, Move, Arg::addr(jumpDestination), jumpDestination);

            Vector<ConstrainedTmp> jumpArgs;
            jumpArgs.append({ jumpDestination, B3::ValueRep::SomeRegister });
            auto pair = self().emitCallPatchpoint(isEmbedderBlock, signature, results, args, WTFMove(jumpArgs));
            auto* patchpoint = pair.first;
            auto exceptionHandle = pair.second;

            // We need to clobber all potential pinned registers since we might be leaving the instance.
            // We pessimistically assume we could be calling to something that is bounds checking.
            // FIXME: We shouldn't have to do this: https://bugs.webkit.org/show_bug.cgi?id=172181
            patchpoint->clobberLate(PinnedRegisterInfo::get().toSave(MemoryMode::BoundsChecking));
            patchpoint->setGenerator([=, this] (CCallHelpers& jit, const B3::StackmapGenerationParams& params) {
                AllowMacroScratchRegisterUsage allowScratch(jit);
                exceptionHandle.generate(jit, params, this);
                jit.call(params[params.proc().resultCount(params.value()->type())].gpr(), WasmEntryPtrTag);
            });

            append(isEmbedderBlock, Jump);
            isEmbedderBlock->setSuccessors(continuation);
        }

        m_currentBlock = continuation;
        // The call could have been to another WebAssembly instance, and / or could have modified our Memory.
        restoreWebAssemblyGlobalState(RestoreCachedStackLimit::Yes, m_info.memory, currentInstance, continuation);
    } else {
        auto pair = self().emitCallPatchpoint(m_currentBlock, signature, results, args);
        auto* patchpoint = pair.first;
        auto exceptionHandle = pair.second;
        // We need to clobber the size register since the LLInt always bounds checks
        if (self().useSignalingMemory() || m_info.memory.isShared())
            patchpoint->clobberLate(RegisterSet { PinnedRegisterInfo::get().boundsCheckingSizeRegister });
        patchpoint->setGenerator([=, this] (CCallHelpers& jit, const B3::StackmapGenerationParams& params) {
            AllowMacroScratchRegisterUsage allowScratch(jit);
            exceptionHandle.generate(jit, params, this);
            CCallHelpers::Call call = jit.threadSafePatchableNearCall();
            jit.addLinkTask([unlinkedWasmToWasmCalls, call, functionIndex] (LinkBuffer& linkBuffer) {
                unlinkedWasmToWasmCalls->append({ linkBuffer.locationOfNearCall<WasmEntryPtrTag>(call), functionIndex });
            });
        });
    }

    return { };
}

template<typename Derived, typename ExpressionType>
auto AirIRGeneratorBase<Derived, ExpressionType>::addCallIndirect(unsigned tableIndex, const TypeDefinition& originalSignature, Vector<ExpressionType>& args, ResultList& results) -> PartialResult
{
    ExpressionType calleeIndex = args.takeLast();
    const TypeDefinition& signature = originalSignature.expand();
    ASSERT(signature.as<FunctionSignature>()->argumentCount() == args.size());
    ASSERT(m_info.tableCount() > tableIndex);
    ASSERT(m_info.tables[tableIndex].type() == TableElementType::Funcref);

    m_makesCalls = true;
    // Note: call indirect can call either WebAssemblyFunction or WebAssemblyWrapperFunction. Because
    // WebAssemblyWrapperFunction is like calling into the embedder, we conservatively assume all call indirects
    // can be to the embedder for our stack check calculation.
    m_maxNumJSCallArguments = std::max(m_maxNumJSCallArguments, static_cast<uint32_t>(args.size()));

    ExpressionType callableFunctionBuffer = self().gPtr();
    ExpressionType instancesBuffer = self().gPtr();
    ExpressionType callableFunctionBufferLength = self().gPtr();
    {
        RELEASE_ASSERT(Arg::isValidAddrForm(FuncRefTable::offsetOfFunctions(), B3::pointerWidth()));
        RELEASE_ASSERT(Arg::isValidAddrForm(FuncRefTable::offsetOfInstances(), B3::pointerWidth()));
        RELEASE_ASSERT(Arg::isValidAddrForm(FuncRefTable::offsetOfLength(), B3::pointerWidth()));

        self().emitLoad(instanceValue().tmp(), Instance::offsetOfTablePtr(m_numImportFunctions, tableIndex), callableFunctionBufferLength);
        append(Move, Arg::addr(callableFunctionBufferLength, FuncRefTable::offsetOfFunctions()), callableFunctionBuffer);
        append(Move, Arg::addr(callableFunctionBufferLength, FuncRefTable::offsetOfInstances()), instancesBuffer);
        append(Move32, Arg::addr(callableFunctionBufferLength, Table::offsetOfLength()), callableFunctionBufferLength);
    }

    append(Move32, calleeIndex, calleeIndex);

    // Check the index we are looking for is valid.
    emitCheck([&] {
        return Inst(Branch32, nullptr, Arg::relCond(MacroAssembler::AboveOrEqual), calleeIndex, callableFunctionBufferLength);
    }, [=, this] (CCallHelpers& jit, const B3::StackmapGenerationParams&) {
        this->emitThrowException(jit, ExceptionType::OutOfBoundsCallIndirect);
    });

    ExpressionType calleeCode = self().gPtr();
    {
        static_assert(sizeof(TypeIndex) == sizeof(void*));
        ExpressionType calleeSignatureIndex = self().gPtr();
        // Compute the offset in the table index space we are looking for.
        append(Move, Arg::imm(sizeof(WasmToWasmImportableFunction)), calleeSignatureIndex);
        append(Derived::MulPtr, calleeIndex, calleeSignatureIndex);
        append(Derived::AddPtr, callableFunctionBuffer, calleeSignatureIndex);
        
        append(Move, Arg::addr(calleeSignatureIndex, WasmToWasmImportableFunction::offsetOfEntrypointLoadLocation()), calleeCode); // Pointer to callee code.

        // FIXME: This seems wasteful to do two checks just for a nicer error message.
        // We should move just to use a single branch and then figure out what
        // error to use in the exception handler.

        append(Move, Arg::addr(calleeSignatureIndex, WasmToWasmImportableFunction::offsetOfSignatureIndex()), calleeSignatureIndex);

        emitCheck([&] {
            static_assert(!TypeDefinition::invalidIndex, "");
            return Inst(Derived::BranchTestPtr, nullptr, Arg::resCond(MacroAssembler::Zero), calleeSignatureIndex, calleeSignatureIndex);
        }, [=, this] (CCallHelpers& jit, const B3::StackmapGenerationParams&) {
            this->emitThrowException(jit, ExceptionType::NullTableEntry);
        });

        ExpressionType expectedSignatureIndex = self().gPtr();
        append(Move, Arg::bigImm(TypeInformation::get(originalSignature)), expectedSignatureIndex);
        emitCheck([&] {
            return Inst(Derived::BranchPtr, nullptr, Arg::relCond(MacroAssembler::NotEqual), calleeSignatureIndex, expectedSignatureIndex);
        }, [=, this] (CCallHelpers& jit, const B3::StackmapGenerationParams&) {
            this->emitThrowException(jit, ExceptionType::BadSignature);
        });
    }

    auto calleeInstance = self().gPtr();
    append(Move, Arg::index(instancesBuffer, calleeIndex, sizeof(void*), 0), calleeInstance);

    return self().emitIndirectCall(calleeInstance, calleeCode, signature, args, results);
}

template<typename Derived, typename ExpressionType>
auto AirIRGeneratorBase<Derived, ExpressionType>::emitIndirectCall(ExpressionType calleeInstance, ExpressionType calleeCode, const TypeDefinition& signature, const Vector<ExpressionType>& args, ResultList& results) -> PartialResult
{
    auto currentInstance = self().gPtr();
    append(Move, instanceValue(), currentInstance);

    // Do a context switch if needed.
    {
        BasicBlock* doContextSwitch = m_code.addBlock();
        BasicBlock* continuation = m_code.addBlock();

        append(Derived::BranchPtr, Arg::relCond(MacroAssembler::Equal), calleeInstance, currentInstance);
        m_currentBlock->setSuccessors(continuation, doContextSwitch);

        auto* patchpoint = addPatchpoint(B3::Void);
        patchpoint->effects.writesPinned = true;
        // We pessimistically assume we're calling something with BoundsChecking memory.
        // FIXME: We shouldn't have to do this: https://bugs.webkit.org/show_bug.cgi?id=172181
        patchpoint->clobber(PinnedRegisterInfo::get().toSave(MemoryMode::BoundsChecking));
        patchpoint->clobber(RegisterSet::macroScratchRegisters());
        patchpoint->numGPScratchRegisters = 1;

        patchpoint->setGenerator([=] (CCallHelpers& jit, const B3::StackmapGenerationParams& params) {
            AllowMacroScratchRegisterUsage allowScratch(jit);
            GPRReg calleeInstance = params[0].gpr();
            GPRReg oldContextInstance = params[1].gpr();
            GPRReg scratch = params.gpScratch(0);
            ASSERT(scratch != calleeInstance);
            jit.loadPtr(CCallHelpers::Address(oldContextInstance, Instance::offsetOfCachedStackLimit()), scratch);
            jit.storePtr(scratch, CCallHelpers::Address(calleeInstance, Instance::offsetOfCachedStackLimit()));
            jit.storeWasmContextInstance(calleeInstance);

            if constexpr (Derived::supportsPinnedStateRegisters) {
                const PinnedRegisterInfo& pinnedRegs = PinnedRegisterInfo::get();
                // FIXME: We should support more than one memory size register
                //   see: https://bugs.webkit.org/show_bug.cgi?id=162952
                ASSERT(pinnedRegs.boundsCheckingSizeRegister != calleeInstance);
                ASSERT(pinnedRegs.baseMemoryPointer != calleeInstance);
                jit.loadPtr(CCallHelpers::Address(calleeInstance, Instance::offsetOfCachedBoundsCheckingSize()), pinnedRegs.boundsCheckingSizeRegister); // Bound checking size.
                jit.loadPtr(CCallHelpers::Address(calleeInstance, Instance::offsetOfCachedMemory()), pinnedRegs.baseMemoryPointer); // Memory::void*.
                jit.cageConditionallyAndUntag(Gigacage::Primitive, pinnedRegs.baseMemoryPointer, pinnedRegs.boundsCheckingSizeRegister, scratch);
            }
        });

        emitPatchpoint(doContextSwitch, patchpoint, ExpressionType(), calleeInstance, currentInstance);
        append(doContextSwitch, Jump);
        doContextSwitch->setSuccessors(continuation);

        m_currentBlock = continuation;
    }

    append(Move, Arg::addr(calleeCode), calleeCode);

    Vector<ConstrainedTmp> extraArgs;
    extraArgs.append(calleeCode);

    for (unsigned i = 0; i < signature.as<FunctionSignature>()->returnCount(); ++i)
        results.append(tmpForType(signature.as<FunctionSignature>()->returnType(i)));

    auto pair = self().emitCallPatchpoint(m_currentBlock, signature, results, args, WTFMove(extraArgs));
    auto* patchpoint = pair.first;
    auto exceptionHandle = pair.second;

    // We need to clobber all potential pinned registers since we might be leaving the instance.
    // We pessimistically assume we're always calling something that is bounds checking so
    // because the wasm->wasm thunk unconditionally overrides the size registers.
    // FIXME: We should not have to do this, but the wasm->wasm stub assumes it can
    // use all the pinned registers as scratch: https://bugs.webkit.org/show_bug.cgi?id=172181

    patchpoint->clobberLate(PinnedRegisterInfo::get().toSave(MemoryMode::BoundsChecking));

    patchpoint->setGenerator([=, this] (CCallHelpers& jit, const B3::StackmapGenerationParams& params) {
        AllowMacroScratchRegisterUsage allowScratch(jit);
        exceptionHandle.generate(jit, params, this);
        jit.call(params[params.proc().resultCount(params.value()->type())].gpr(), WasmEntryPtrTag);
    });

    // The call could have been to another WebAssembly instance, and / or could have modified our Memory.
    restoreWebAssemblyGlobalState(RestoreCachedStackLimit::Yes, m_info.memory, currentInstance, m_currentBlock);

    return { };
}

template <typename Derived, typename ExpressionType>
auto AirIRGeneratorBase<Derived, ExpressionType>::addCallRef(const TypeDefinition& originalSignature, Vector<ExpressionType>& args, ResultList& results) -> PartialResult
{
    m_makesCalls = true;
    // Note: call ref can call either WebAssemblyFunction or WebAssemblyWrapperFunction. Because
    // WebAssemblyWrapperFunction is like calling into the embedder, we conservatively assume all call indirects
    // can be to the embedder for our stack check calculation.
    ExpressionType calleeFunction = args.takeLast();
    m_maxNumJSCallArguments = std::max(m_maxNumJSCallArguments, static_cast<uint32_t>(args.size()));
    const TypeDefinition& signature = originalSignature.expand();

    emitThrowOnNullReference(calleeFunction);

    ExpressionType calleeCode = self().gPtr();
    append(Move, Arg::addr(self().extractJSValuePointer(calleeFunction), WebAssemblyFunctionBase::offsetOfEntrypointLoadLocation()), calleeCode); // Pointer to callee code.

    auto calleeInstance = self().g64();
    append(Move, Arg::addr(self().extractJSValuePointer(calleeFunction), WebAssemblyFunctionBase::offsetOfInstance()), calleeInstance);
    append(Move, Arg::addr(calleeInstance, JSWebAssemblyInstance::offsetOfInstance()), calleeInstance);

    return emitIndirectCall(calleeInstance, calleeCode, signature, args, results);
}



template <typename Derived, typename ExpressionType>
auto AirIRGeneratorBase<Derived, ExpressionType>::addUnreachable() -> PartialResult
{
    B3::PatchpointValue* unreachable = addPatchpoint(B3::Void);
    unreachable->setGenerator([this](CCallHelpers& jit, const B3::StackmapGenerationParams&) {
        this->emitThrowException(jit, ExceptionType::Unreachable);
    });
    unreachable->effects.terminal = true;
    emitPatchpoint(unreachable, Tmp());
    return {};
}
} } // namespace JSC::Wasm

#endif // ENABLE(WEBASSEMBLY_B3JIT)
