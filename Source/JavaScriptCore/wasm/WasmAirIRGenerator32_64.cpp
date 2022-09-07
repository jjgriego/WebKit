/*
 * Copyright (C) 2022 Igalia SL. All rights reserved.
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
#include "WasmAirIRGeneratorBase.h"

#if USE(JSVALUE32_64) && ENABLE(WEBASSEMBLY_B3JIT)

namespace JSC { namespace Wasm {

// This inline namespace is mostly to ensure that the canonical
// namespace of identifiers in this file is *obviously* different from
// those in the 64-bit AirIRGenerator
inline namespace Air32 {

namespace {

static bool typeNeedsGPPair(Type type) {
    switch (type.kind) {
    case TypeKind::I64:
    case TypeKind::Funcref:
    case TypeKind::Externref:
    case TypeKind::RefNull:
    case TypeKind::Ref:
        return true;
    default:
        return false;
    }
}

}

struct TypedTmp {
    constexpr TypedTmp()
        : m_tmps{Tmp { }, Tmp { }}
        , m_type(Types::Void)
    {
    }

    constexpr TypedTmp(std::array<Tmp, 2> tmps, Type type)
        : m_tmps(tmps)
        , m_type(type)
    {
    }

    constexpr TypedTmp(Tmp tmp, Type type)
        : TypedTmp({tmp, { }}, type)
    {
    }

    static TypedTmp word(Tmp tmp, Type type)
    {
        ASSERT(!typeNeedsGPPair(type));
        return {
            {tmp, Tmp { }},
            type
        };
    }

    bool operator==(const TypedTmp& other) const
    {
        return m_tmps[0] == other.m_tmps[0]
            && m_tmps[1] == other.m_tmps[1]
            && m_type == other.m_type;
    }

    bool operator!=(const TypedTmp& other) const
    {
        return !(*this == other);
    }

    bool isGPPair() const {
        return static_cast<bool>(m_tmps[1]);
    }

    void dump(PrintStream& out) const
    {
        if (isGPPair()) {
            out.print("({", m_tmps[0], ", ", m_tmps[1], "},", m_type.kind, ", ", m_type.index, ")");
        } else{
            out.print("(", m_tmps[0], ", ", m_type.kind, ", ", m_type.index, ")");
        }
    }

private:
    std::array<Tmp, 2> m_tmps;
    Type m_type;
};

} // inline namespace Air32

class AirIRGenerator32_64 : public AirIRGeneratorBase<AirIRGenerator32_64, TypedTmp> {
public:
    friend AirIRGeneratorBase<AirIRGenerator32_64, TypedTmp>;
    using ExpressionType = TypedTmp;

    AirIRGenerator32_64(const ModuleInformation& info, B3::Procedure& procedure, InternalFunction* compilation, Vector<UnlinkedWasmToWasmCall>& unlinkedWasmToWasmCalls, MemoryMode mode, unsigned functionIndex, std::optional<bool> hasExceptionHandlers, TierUpCount* tierUp, const TypeDefinition& originalSignature, unsigned& osrEntryScratchBufferSize)
        : AirIRGeneratorBase(info, procedure, compilation, unlinkedWasmToWasmCalls, mode, functionIndex, hasExceptionHandlers, tierUp, originalSignature, osrEntryScratchBufferSize)
    {
    }


    static constexpr bool generatesB3OriginData = false;

private:
    TypedTmp gNewWord(Type t) { return TypedTmp({ newTmp(B3::GP), {} }, t); }
    TypedTmp gNewPair(Type t) { return TypedTmp({ newTmp(B3::GP), newTmp(B3::GP) }, t); }
    TypedTmp g32() { return gNewWord(Types::I32); }
    TypedTmp g64() { return gNewPair(Types::I64); }
    TypedTmp gPtr() { return g32(); }
    TypedTmp gExternref() { return gNewPair(Types::Externref); }
    TypedTmp gFuncref() { return gNewPair(Types::Funcref); }
    TypedTmp gRef(Type type) { return gNewPair(type); }
    TypedTmp f32() { return TypedTmp({ newTmp(B3::FP), { } }, Types::F32 ); }
    TypedTmp f64() { return TypedTmp({ newTmp(B3::FP), { } }, Types::F64 ); }

    // TODO(jgriego) these are a mega-kludge and should be fixed
    static Arg extractArg(const TypedTmp& tmp) { CRASH(); }
    static Arg extractArg(const Tmp& tmp) { return Arg(tmp); }
    static Arg extractArg(const Arg& arg) { return arg; }

    void emitZeroInitialize(ExpressionType value);

public:
    // kludge while we add everything
#define X(name, id, b3op, inc, ...)                                             \
    PartialResult WARN_UNUSED_RETURN add##name(ExpressionType, ExpressionType&) \
    {                                                                           \
        CRASH();                                                                \
    }

    FOR_EACH_WASM_UNARY_OP(X)
#undef X
#define X(name, id, b3op, inc, ...)                                                             \
    PartialResult WARN_UNUSED_RETURN add##name(ExpressionType, ExpressionType, ExpressionType&) \
    {                                                                                           \
        CRASH();                                                                                \
    }

    FOR_EACH_WASM_BINARY_OP(X)
#undef X

    ExpressionType addConstant(Type, uint64_t){ CRASH(); }
    ExpressionType addConstant(BasicBlock*, Type, uint64_t){ CRASH(); }
    ExpressionType addBottom(BasicBlock*, Type){ CRASH(); }
    static ExpressionType emptyExpression() { return {}; }

    // References
    PartialResult WARN_UNUSED_RETURN addRefIsNull(ExpressionType value, ExpressionType& result){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN addRefFunc(uint32_t index, ExpressionType& result){ CRASH(); }

    // Tables
    PartialResult WARN_UNUSED_RETURN addTableGet(unsigned, ExpressionType index, ExpressionType& result){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN addTableSet(unsigned, ExpressionType index, ExpressionType value){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN addTableInit(unsigned, unsigned, ExpressionType dstOffset, ExpressionType srcOffset, ExpressionType length){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN addElemDrop(unsigned){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN addTableSize(unsigned, ExpressionType& result){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN addTableGrow(unsigned, ExpressionType fill, ExpressionType delta, ExpressionType& result){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN addTableFill(unsigned, ExpressionType offset, ExpressionType fill, ExpressionType count){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN addTableCopy(unsigned, unsigned, ExpressionType dstOffset, ExpressionType srcOffset, ExpressionType length){ CRASH(); }

    // Locals
    PartialResult WARN_UNUSED_RETURN getLocal(uint32_t index, ExpressionType& result){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN setLocal(uint32_t index, ExpressionType value){ CRASH(); }

    // Globals
    PartialResult WARN_UNUSED_RETURN getGlobal(uint32_t index, ExpressionType& result){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN setGlobal(uint32_t index, ExpressionType value){ CRASH(); }

    // Memory
    PartialResult WARN_UNUSED_RETURN load(LoadOpType, ExpressionType pointer, ExpressionType& result, uint32_t offset){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN store(StoreOpType, ExpressionType pointer, ExpressionType value, uint32_t offset){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN addGrowMemory(ExpressionType delta, ExpressionType& result){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN addCurrentMemory(ExpressionType& result){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN addMemoryFill(ExpressionType dstAddress, ExpressionType targetValue, ExpressionType count){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN addMemoryCopy(ExpressionType dstAddress, ExpressionType srcAddress, ExpressionType count){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN addMemoryInit(unsigned, ExpressionType dstAddress, ExpressionType srcAddress, ExpressionType length){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN addDataDrop(unsigned){ CRASH(); }

    // Atomics
    PartialResult WARN_UNUSED_RETURN atomicLoad(ExtAtomicOpType, Type, ExpressionType pointer, ExpressionType& result, uint32_t offset){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN atomicStore(ExtAtomicOpType, Type, ExpressionType pointer, ExpressionType value, uint32_t offset){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN atomicBinaryRMW(ExtAtomicOpType, Type, ExpressionType pointer, ExpressionType value, ExpressionType& result, uint32_t offset){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN atomicCompareExchange(ExtAtomicOpType, Type, ExpressionType pointer, ExpressionType expected, ExpressionType value, ExpressionType& result, uint32_t offset){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN atomicWait(ExtAtomicOpType, ExpressionType pointer, ExpressionType value, ExpressionType timeout, ExpressionType& result, uint32_t offset){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN atomicNotify(ExtAtomicOpType, ExpressionType pointer, ExpressionType value, ExpressionType& result, uint32_t offset){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN atomicFence(ExtAtomicOpType, uint8_t flags){ CRASH(); }

    // Saturated truncation.
    PartialResult WARN_UNUSED_RETURN truncSaturated(Ext1OpType, ExpressionType operand, ExpressionType& result, Type returnType, Type operandType){ CRASH(); }

    // GC
    PartialResult WARN_UNUSED_RETURN addI31New(ExpressionType value, ExpressionType& result){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN addI31GetS(ExpressionType ref, ExpressionType& result){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN addI31GetU(ExpressionType ref, ExpressionType& result){ CRASH(); }


    PartialResult WARN_UNUSED_RETURN addSelect(ExpressionType condition, ExpressionType nonZero, ExpressionType zero, ExpressionType& result){ CRASH(); }

    // Control flow
    ControlData WARN_UNUSED_RETURN addTopLevel(BlockSignature){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN addBlock(BlockSignature, Stack& enclosingStack, ControlType& newBlock, Stack& newStack){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN addLoop(BlockSignature, Stack& enclosingStack, ControlType& block, Stack& newStack, uint32_t loopIndex){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN addIf(ExpressionType condition, BlockSignature, Stack& enclosingStack, ControlType& result, Stack& newStack){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN addElse(ControlData&, const Stack&){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN addElseToUnreachable(ControlData&){ CRASH(); }

    PartialResult WARN_UNUSED_RETURN addTry(BlockSignature, Stack& enclosingStack, ControlType& result, Stack& newStack){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN addCatch(unsigned exceptionIndex, const TypeDefinition&, Stack&, ControlType&, ResultList&){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN addCatchToUnreachable(unsigned exceptionIndex, const TypeDefinition&, ControlType&, ResultList&){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN addCatchAll(Stack&, ControlType&){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN addCatchAllToUnreachable(ControlType&){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN addDelegate(ControlType&, ControlType&){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN addDelegateToUnreachable(ControlType&, ControlType&){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN addThrow(unsigned exceptionIndex, Vector<ExpressionType>& args, Stack&){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN addRethrow(unsigned, ControlType&){ CRASH(); }

    PartialResult WARN_UNUSED_RETURN addReturn(const ControlData&, const Stack& returnValues){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN addBranch(ControlData&, ExpressionType condition, const Stack& returnValues){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN addSwitch(ExpressionType condition, const Vector<ControlData*>& targets, ControlData& defaultTargets, const Stack& expressionStack){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN endBlock(ControlEntry&, Stack& expressionStack){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN addEndToUnreachable(ControlEntry&, const Stack& expressionStack = { }){ CRASH(); }


    // Calls
    PartialResult WARN_UNUSED_RETURN addCall(uint32_t calleeIndex, const TypeDefinition&, Vector<ExpressionType>& args, ResultList& results){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN addCallIndirect(unsigned tableIndex, const TypeDefinition&, Vector<ExpressionType>& args, ResultList& results){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN addCallRef(const TypeDefinition&, Vector<ExpressionType>& args, ResultList& results){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN addUnreachable(){ CRASH(); }

    PartialResult addShift(Type, B3::Air::Opcode, ExpressionType value, ExpressionType shift, ExpressionType& result){ CRASH(); }
    PartialResult addIntegerSub(B3::Air::Opcode, ExpressionType lhs, ExpressionType rhs, ExpressionType& result){ CRASH(); }
    PartialResult addFloatingPointAbs(B3::Air::Opcode, ExpressionType value, ExpressionType& result){ CRASH(); }
    PartialResult addFloatingPointBinOp(Type, B3::Air::Opcode, ExpressionType lhs, ExpressionType rhs, ExpressionType& result){ CRASH(); }

    void emitLoad(Tmp base, size_t offset, const TypedTmp& result){ CRASH(); }

    template <typename ... Args>
    void emitPatchpoint(Args&& ...) {
        CRASH();
    }
};

void AirIRGenerator32_64::emitZeroInitialize(ExpressionType value)
{
    CRASH(); // TODO(jgriego)
}

Expected<std::unique_ptr<InternalFunction>, String> parseAndCompileAir(CompilationContext& compilationContext, const FunctionData& function, const TypeDefinition& signature, Vector<UnlinkedWasmToWasmCall>& unlinkedWasmToWasmCalls, const ModuleInformation& info, MemoryMode mode, uint32_t functionIndex, std::optional<bool> hasExceptionHandlers, TierUpCount* tierUp)
{
    return parseAndCompileAirImpl<AirIRGenerator32_64>(compilationContext, function, signature, unlinkedWasmToWasmCalls, info, mode, functionIndex, hasExceptionHandlers, tierUp);
}

}} // namespace JSC::Wasm

#endif
