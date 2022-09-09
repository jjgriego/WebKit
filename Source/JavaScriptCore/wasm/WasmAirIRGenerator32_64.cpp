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
        ASSERT(typeNeedsGPPair(type));
    }

    constexpr TypedTmp(Tmp tmp, Type type)
        : TypedTmp({tmp, { }}, type)
    {
        ASSERT(!typeNeedsGPPair(type));
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

    Type type() const { return m_type; }

    bool isGPPair() const {
        return static_cast<bool>(m_tmps[1]);
    }

    operator Tmp() const { return tmp(); }
    operator Arg() const { return Arg(tmp()); }

    explicit operator bool() const
    {
        return static_cast<bool>(m_tmps[0]);
    }

    Tmp tmp() const {
        ASSERT(!isGPPair());
        return m_tmps[0];
    }

    Tmp lo() const {
        ASSERT(isGPPair());
        return m_tmps[0];
    }

    Tmp hi() const
    {
        ASSERT(isGPPair());
        return m_tmps[1];
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
    static constexpr bool supportsPinnedStateRegisters = false;

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

    static auto constexpr AddPtr = Add32;
    static auto constexpr UrshiftPtr = Urshift32;

    // TODO(jgriego) these are a mega-kludge and should be fixed
    static Arg extractArg(const TypedTmp& tmp) { return tmp.tmp(); }
    static Arg extractArg(const Tmp& tmp) { return Arg(tmp); }
    static Arg extractArg(const Arg& arg) { return arg; }

    void emitZeroInitialize(ExpressionType value);
    template <typename Taken>
    void emitCheckI64Zero(ExpressionType value, Taken&& taken);

    void appendCCallArg(B3::Air::Inst& inst, const TypedTmp& tmp);

    static B3::Air::Opcode moveOpForValueType(Type type);
    void emitLoad(Tmp base, size_t offset, const TypedTmp& result);
    void emitStore(const TypedTmp& value, Tmp base, size_t offset);
    void emitMove(const TypedTmp& src, const TypedTmp& dst);
    ExpressionType emitCheckAndPreparePointer(ExpressionType pointer, uint32_t offset, uint32_t sizeOfOp);
    ExpressionType emitLoadOp(LoadOpType, ExpressionType pointer, uint32_t offset);
    void emitStoreOp(StoreOpType, ExpressionType pointer, ExpressionType value, uint32_t offset);

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
    PartialResult WARN_UNUSED_RETURN addRefIsNull(ExpressionType value, ExpressionType& result);

    // Globals
    PartialResult WARN_UNUSED_RETURN getGlobal(uint32_t index, ExpressionType& result){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN setGlobal(uint32_t index, ExpressionType value){ CRASH(); }

    // Memory
    PartialResult WARN_UNUSED_RETURN load(LoadOpType, ExpressionType pointer, ExpressionType& result, uint32_t offset);
    PartialResult WARN_UNUSED_RETURN store(StoreOpType, ExpressionType pointer, ExpressionType value, uint32_t offset);

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
};

B3::Air::Opcode AirIRGenerator32_64::moveOpForValueType(Type type)
{
    switch (type.kind) {
    case TypeKind::I32:
    case TypeKind::I64:
    case TypeKind::Externref:
    case TypeKind::Funcref:
    case TypeKind::Ref:
    case TypeKind::RefNull:
        return Move;
    case TypeKind::F32:
        return MoveFloat;
    case TypeKind::F64:
        return MoveDouble;
    default:
        RELEASE_ASSERT_NOT_REACHED();
    }
}

void AirIRGenerator32_64::emitZeroInitialize(ExpressionType value)
{
    const auto type = value.type();
    switch (type.kind) {
    case TypeKind::Externref:
    case TypeKind::Funcref:
    case TypeKind::Ref:
    case TypeKind::RefNull: {
        auto const immValue = JSValue::encode(jsNull());
        append(Move, Arg::bigImmLo32(immValue), value.lo());
        append(Move, Arg::bigImmHi32(immValue), value.hi());
        break;
    }
    case TypeKind::I32:
    case TypeKind::I64: {
        append(Move, Arg::imm(0), value);
        break;
    }
    case TypeKind::F32:
    case TypeKind::F64: {
        auto temp = gPtr();
        // IEEE 754 "0" is just int32/64 zero.
        append(Move, Arg::imm(0), temp);
        append(type.isF32() ? Move32ToFloat : Move64ToDouble, temp, value);
        break;
    }
    default:
        RELEASE_ASSERT_NOT_REACHED();
    }

}

template<typename Taken>
void AirIRGenerator32_64::emitCheckI64Zero(ExpressionType value, Taken&& taken)
{
    BasicBlock* continuation = nullptr;
    emitCheck([&] {
        BasicBlock* checkLo = m_code.addBlock();
        continuation = m_code.addBlock();
        append(BranchTest32, Arg::resCond(MacroAssembler::NonZero), value.hi(), value.hi());
        m_currentBlock->setSuccessors(continuation, checkLo);
        m_currentBlock = checkLo;
        return Inst(BranchTest32, nullptr, Arg::resCond(MacroAssembler::Zero), value.lo(), value.lo());
    }, std::forward<Taken>(taken));

    ASSERT(continuation);
    append(Jump);
    m_currentBlock->setSuccessors(continuation);
    m_currentBlock = continuation;
}

void AirIRGenerator32_64::emitLoad(Tmp base, size_t offset, const TypedTmp& result)
{
    auto const largestOffsetUsed = result.isGPPair() ? offset + 4 : offset;
    if (!Arg::isValidAddrForm(largestOffsetUsed, B3::widthForType(toB3Type(result.type())))) {
        auto address = gPtr();
        append(Move, Arg::bigImm(offset), address);
        append(Add32, base, address, address);
        base = address.tmp();
        offset = 0;
    }

    if (result.isGPPair()) {
        append(Move, Arg::addr(base, offset), result.lo());
        append(Move, Arg::addr(base, offset + 4), result.lo());
    } else {
        append(moveOpForValueType(result.type()), Arg::addr(base, offset), result);
    }
}

void AirIRGenerator32_64::emitStore(const TypedTmp& value, Tmp base, size_t offset)
{
    auto const largestOffsetUsed = value.isGPPair() ? offset + 4 : offset;
    if (!Arg::isValidAddrForm(largestOffsetUsed, B3::widthForType(toB3Type(value.type())))) {
        auto address = gPtr();
        append(Move, Arg::bigImm(offset), address);
        append(Add32, base, address, address);
        base = address.tmp();
        offset = 0;
    }

    if (value.isGPPair()) {
        append(Move, value.lo(), Arg::addr(base, offset));
        append(Move, value.hi(), Arg::addr(base, offset + 4));
    } else {
        append(moveOpForValueType(value.type()), value, Arg::addr(base, offset));
    }
}

void AirIRGenerator32_64::emitMove(const TypedTmp& src, const TypedTmp& dst)
{
    if (src == dst)
        return;
    ASSERT(isSubtype(src.type(), dst.type()));
    if (src.isGPPair()) {
        append(Move, src.lo(), dst.lo());
        append(Move, src.hi(), dst.hi());
    } else {
        append(moveOpForValueType(src.type()), src, dst);
    }
}

void AirIRGenerator32_64::appendCCallArg(B3::Air::Inst& inst, const TypedTmp& tmp)
{
    if (tmp.isGPPair()) {
        inst.args.append(tmp.lo());
        inst.args.append(tmp.hi());
    } else {
        inst.args.append(tmp.tmp());
    }
}

auto AirIRGenerator32_64::addRefIsNull(ExpressionType value, ExpressionType& result) -> PartialResult
{
    ASSERT(value.tmp());
    result = tmpForType(Types::I32);
    auto tmp = g32();

    append(Move, Arg::bigImm(JSValue::NullTag), tmp);
    append(Compare32, Arg::relCond(MacroAssembler::Equal), value.hi(), tmp, result);

    return {};
}

auto AirIRGenerator32_64::emitCheckAndPreparePointer(ExpressionType pointer, uint32_t offset, uint32_t sizeOfOperation) -> ExpressionType
{
    ASSERT(m_memoryBaseGPR);

    auto result = gPtr();
    append(Move32, pointer, result);

    switch (m_mode) {
    case MemoryMode::BoundsChecking: {
        // In bound checking mode, while shared wasm memory partially relies on signal handler too, we need to perform bound checking
        // to ensure that no memory access exceeds the current memory size.
        ASSERT(m_boundsCheckingSizeGPR);
        ASSERT(sizeOfOperation + offset > offset);
        auto temp = gPtr();
        if (offset) {
            append(Move, Arg::bigImm(offset), temp);
            append(AddPtr, result, temp);
            emitCheck([&] { return Inst(Branch32, nullptr, Arg::relCond(MacroAssembler::Below), temp, result); }, [=, this](CCallHelpers& jit, const B3::StackmapGenerationParams&) { this->emitThrowException(jit, ExceptionType::OutOfBoundsMemoryAccess); });
        }
        if (sizeOfOperation > 1) {
            append(AddPtr, Arg::imm(sizeOfOperation - 1), offset ? temp : result, temp);
            emitCheck([&] { return Inst(Branch32, nullptr, Arg::relCond(MacroAssembler::Below), temp, result); }, [=, this](CCallHelpers& jit, const B3::StackmapGenerationParams&) { this->emitThrowException(jit, ExceptionType::OutOfBoundsMemoryAccess); });
        }
        break;
    }

    }

    append(AddPtr, Tmp(m_memoryBaseGPR), result);
    return result;
}

inline TypedTmp AirIRGenerator32_64::emitLoadOp(LoadOpType op, ExpressionType pointer, uint32_t uoffset)
{
    uint32_t offset = fixupPointerPlusOffset(pointer, uoffset);

    TypedTmp immTmp;
    TypedTmp newPtr;
    TypedTmp result;

    auto getAddr = [&](uint32_t offset) {
        if (Arg::isValidAddrForm(offset, B3::widthForBytes(sizeOfLoadOp(op))))
            return Arg::addr(pointer, offset);
        immTmp = gPtr();
        newPtr = gPtr();
        append(Move, Arg::bigImm(offset), immTmp);
        append(AddPtr, immTmp, pointer, newPtr);
        return Arg::addr(newPtr);
    };

    Arg addrArg = getAddr(offset);

    switch (op) {
    case LoadOpType::I32Load8S: {
        result = g32();
        appendEffectful(Load8SignedExtendTo32, addrArg, result);
        break;
    }

    case LoadOpType::I64Load8S: {
        result = g64();
        appendEffectful(Load8SignedExtendTo32, addrArg, result.lo());
        append(Rshift32, result.lo(), Arg::imm(31), result.hi());
        break;
    }

    case LoadOpType::I32Load8U: {
        result = g32();
        appendEffectful(Load8, addrArg, result);
        break;
    }

    case LoadOpType::I64Load8U: {
        result = g64();
        appendEffectful(Load8, addrArg, result.lo());
        append(Move, Arg::imm(0), result.hi());
        break;
    }

    case LoadOpType::I32Load16S: {
        result = g32();
        appendEffectful(Load16SignedExtendTo32, addrArg, result);
        break;
    }

    case LoadOpType::I64Load16S: {
        result = g64();
        appendEffectful(Load16SignedExtendTo32, addrArg, result.lo());
        append(Rshift32, result.lo(), Arg::imm(31), result.hi());
        break;
    }

    case LoadOpType::I32Load16U: {
        result = g32();
        appendEffectful(Load16, addrArg, result);
        break;
    }

    case LoadOpType::I64Load16U: {
        result = g64();
        appendEffectful(Load16, addrArg, result.lo());
        append(Move, Arg::imm(0), result.hi());
        break;
    }

    case LoadOpType::I32Load:
        result = g32();
        appendEffectful(Move32, addrArg, result);
        break;

    case LoadOpType::I64Load32U: {
        result = g64();
        appendEffectful(Move32, addrArg, result.lo());
        append(Move, Arg::imm(0), result.hi());
        break;
    }

    case LoadOpType::I64Load32S: {
        result = g64();
        appendEffectful(Move32, addrArg, result.lo());
        append(Rshift32, result.lo(), Arg::imm(31), result.hi());
        break;
    }

    case LoadOpType::I64Load: {
        result = g64();
        // Might be unaligned so can't use LoadPair32
        appendEffectful(Move, addrArg, result.lo());
        appendEffectful(Move, getAddr(offset + 4), result.hi());
        break;
    }

    case LoadOpType::F32Load: {
        result = f32();
#if !CPU(ARM_THUMB2)
        appendEffectful(MoveFloat, addrArg, result);
#else
        // Might be unaligned so can't use MoveFloat
        auto tmp = g32();
        appendEffectful(Move, addrArg, tmp);
        append(Move32ToFloat, tmp, result);
#endif
        break;
    }

    case LoadOpType::F64Load: {
        result = f64();
#if !CPU(ARM_THUMB2)
        appendEffectful(MoveDouble, addrArg, result);
#else
        // Might be unaligned so can't use MoveDouble
        auto tmp = g64();
        appendEffectful(Move, addrArg, tmp.lo());
        appendEffectful(Move, getAddr(offset + 4), tmp.hi());
        append(Move64ToDouble, tmp.hi(), tmp.lo(), result);
#endif
        break;
    }
    }

    return result;
}

auto AirIRGenerator32_64::load(LoadOpType op, ExpressionType pointer, ExpressionType& result, uint32_t offset) -> PartialResult
{
    ASSERT(pointer.tmp().isGP());

    if (UNLIKELY(sumOverflows<uint32_t>(offset, sizeOfLoadOp(op)))) {
        // FIXME: Even though this is provably out of bounds, it's not a validation error, so we have to handle it
        // as a runtime exception. However, this may change: https://bugs.webkit.org/show_bug.cgi?id=166435
        auto* patch = addPatchpoint(B3::Void);
        patch->setGenerator([this] (CCallHelpers& jit, const B3::StackmapGenerationParams&) {
            this->emitThrowException(jit, ExceptionType::OutOfBoundsMemoryAccess);
        });
        emitPatchpoint(patch, Tmp());

        // We won't reach here, so we just pick a random reg.
        switch (op) {
        case LoadOpType::I32Load8S:
        case LoadOpType::I32Load16S:
        case LoadOpType::I32Load:
        case LoadOpType::I32Load16U:
        case LoadOpType::I32Load8U:
            result = g32();
            break;
        case LoadOpType::I64Load8S:
        case LoadOpType::I64Load8U:
        case LoadOpType::I64Load16S:
        case LoadOpType::I64Load32U:
        case LoadOpType::I64Load32S:
        case LoadOpType::I64Load:
        case LoadOpType::I64Load16U:
            result = g64();
            break;
        case LoadOpType::F32Load:
            result = f32();
            break;
        case LoadOpType::F64Load:
            result = f64();
            break;
        }
    } else
        result = emitLoadOp(op, emitCheckAndPreparePointer(pointer, offset, sizeOfLoadOp(op)), offset);

    return { };
}

inline void AirIRGenerator32_64::emitStoreOp(StoreOpType op, ExpressionType pointer, ExpressionType value, uint32_t uoffset)
{
    uint32_t offset = fixupPointerPlusOffset(pointer, uoffset);

    TypedTmp immTmp;
    TypedTmp newPtr;

    auto const getAddr = [&](uint32_t offset) {
        if (Arg::isValidAddrForm(offset, B3::widthForBytes(sizeOfStoreOp(op))))
            return Arg::addr(pointer, offset);
        else {
            immTmp = gPtr();
            newPtr = gPtr();
            append(Move, Arg::bigImm(offset), immTmp);
            append(AddPtr, immTmp, pointer, newPtr);
            return Arg::addr(newPtr);
        }
    };

    auto const addrArg = getAddr(offset);

    switch (op) {
    case StoreOpType::I64Store8:
        append(Store8, value.lo(), addrArg);
        return;
    case StoreOpType::I32Store8:
        append(Store8, value, addrArg);
        return;
    case StoreOpType::I64Store16:
        append(Store16, value.lo(), addrArg);
        return;
    case StoreOpType::I32Store16:
        append(Store16, value, addrArg);
        return;
    case StoreOpType::I64Store32:
        append(Move32, value.lo(), addrArg);
        return;
    case StoreOpType::I32Store:
        append(Move32, value, addrArg);
        return;
    case StoreOpType::I64Store:
        append(Move, value.lo(), addrArg);
        append(Move, value.hi(), getAddr(offset + 4));
        return;
    case StoreOpType::F32Store: {
#if !CPU(ARM_THUMB2)
        append(MoveFloat, value, addrArg);
#else
        // Might be unaligned so can't use MoveFloat
        auto tmp = g32();
        append(MoveFloatTo32, value, tmp);
        append(Move, tmp, addrArg);
#endif
        return;
    }
    case StoreOpType::F64Store: {
#if !CPU(ARM_THUMB2)
        append(MoveDouble, value, addrArg);
#else
        // Might be unaligned so can't use MoveDouble
        auto tmp = g64();
        append(MoveDoubleTo64, value, tmp.hi(), tmp.lo());
        appendEffectful(Move, tmp.lo(), addrArg);
        appendEffectful(Move, tmp.hi(), getAddr(offset + 4));
#endif
        return;
    }
    }
        RELEASE_ASSERT_NOT_REACHED();
}

auto AirIRGenerator32_64::store(StoreOpType op, ExpressionType pointer, ExpressionType value, uint32_t offset) -> PartialResult
{
    ASSERT(pointer.tmp().isGP());

    if (UNLIKELY(sumOverflows<uint32_t>(offset, sizeOfStoreOp(op)))) {
        // FIXME: Even though this is provably out of bounds, it's not a validation error, so we have to handle it
        // as a runtime exception. However, this may change: https://bugs.webkit.org/show_bug.cgi?id=166435
        auto* throwException = addPatchpoint(B3::Void);
        throwException->setGenerator([this](CCallHelpers& jit, const B3::StackmapGenerationParams&) {
            this->emitThrowException(jit, ExceptionType::OutOfBoundsMemoryAccess);
        });
        emitPatchpoint(throwException, Tmp());
    } else
        emitStoreOp(op, emitCheckAndPreparePointer(pointer, offset, sizeOfStoreOp(op)), value, offset);

    return {};
}

Expected<std::unique_ptr<InternalFunction>, String> parseAndCompileAir(CompilationContext& compilationContext, const FunctionData& function, const TypeDefinition& signature, Vector<UnlinkedWasmToWasmCall>& unlinkedWasmToWasmCalls, const ModuleInformation& info, MemoryMode mode, uint32_t functionIndex, std::optional<bool> hasExceptionHandlers, TierUpCount* tierUp)
{
    return parseAndCompileAirImpl<AirIRGenerator32_64>(compilationContext, function, signature, unlinkedWasmToWasmCalls, info, mode, functionIndex, hasExceptionHandlers, tierUp);
}

}
} // namespace JSC::Wasm

#endif
