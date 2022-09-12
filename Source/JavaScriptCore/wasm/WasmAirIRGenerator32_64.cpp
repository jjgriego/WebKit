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

    bool useSignalingMemory() const { return false; }

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
    static auto constexpr MulPtr = Mul32;
    static auto constexpr UrshiftPtr = Urshift32;
    static auto constexpr LeaPtr = Lea32;
    static auto constexpr BranchTestPtr = BranchTest32;
    static auto constexpr BranchPtr = Branch32;

    // TODO(jgriego) these are a mega-kludge and should be fixed
    static Arg extractArg(const TypedTmp& tmp) { return tmp.tmp(); }
    static Arg extractArg(const Tmp& tmp) { return Arg(tmp); }
    static Arg extractArg(const Arg& arg) { return arg; }

    Tmp extractJSValuePointer(const TypedTmp& tmp) const { return tmp.lo(); }

    void emitZeroInitialize(ExpressionType value);
    template <typename Taken>
    void emitCheckI64Zero(ExpressionType value, Taken&& taken);
    template<typename Taken>
    void emitCheckForNullReference(const ExpressionType& ref, Taken&& then);

    void appendCCallArg(B3::Air::Inst& inst, const TypedTmp& tmp);

    static B3::Air::Opcode moveOpForValueType(Type type);
    void emitLoad(Tmp base, size_t offset, const TypedTmp& result);
    void emitStore(const TypedTmp& value, Tmp base, size_t offset);
    void emitMove(const TypedTmp& src, const TypedTmp& dst);
    ExpressionType emitCheckAndPreparePointer(ExpressionType pointer, uint32_t offset, uint32_t sizeOfOp);
    ExpressionType emitLoadOp(LoadOpType, ExpressionType pointer, uint32_t offset);
    void emitStoreOp(StoreOpType, ExpressionType pointer, ExpressionType value, uint32_t offset);
    Tmp emitCatchImpl(CatchKind, ControlType&, unsigned exceptionIndex = 0);

    void sanitizeAtomicResult(ExtAtomicOpType, ExpressionType source, ExpressionType dest);
    void sanitizeAtomicResult(ExtAtomicOpType, ExpressionType result);
    template<typename InputType>
    TypedTmp appendGeneralAtomic(ExtAtomicOpType op, B3::Air::Opcode opcode, B3::Commutativity commutativity, InputType input, Arg address, TypedTmp oldValue);
    TypedTmp appendStrongCAS(ExtAtomicOpType, TypedTmp expected, TypedTmp value, Arg addrArg, TypedTmp result);

    template<size_t inlineCapacity>
    PatchpointExceptionHandle preparePatchpointForExceptions(B3::PatchpointValue*, Vector<ConstrainedTmp, inlineCapacity>& args);

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

    // Memory
    PartialResult WARN_UNUSED_RETURN load(LoadOpType, ExpressionType pointer, ExpressionType& result, uint32_t offset);
    PartialResult WARN_UNUSED_RETURN store(StoreOpType, ExpressionType pointer, ExpressionType value, uint32_t offset);

    // Saturated truncation.
    PartialResult WARN_UNUSED_RETURN truncSaturated(Ext1OpType, ExpressionType operand, ExpressionType& result, Type returnType, Type operandType){ CRASH(); }

    // GC
    PartialResult WARN_UNUSED_RETURN addI31New(ExpressionType value, ExpressionType& result){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN addI31GetS(ExpressionType ref, ExpressionType& result){ CRASH(); }
    PartialResult WARN_UNUSED_RETURN addI31GetU(ExpressionType ref, ExpressionType& result){ CRASH(); }


    PartialResult WARN_UNUSED_RETURN addSelect(ExpressionType condition, ExpressionType nonZero, ExpressionType zero, ExpressionType& result){ CRASH(); }

    // Control flow
    PartialResult WARN_UNUSED_RETURN addReturn(const ControlData&, const Stack& returnValues);
    PartialResult WARN_UNUSED_RETURN addThrow(unsigned exceptionIndex, Vector<ExpressionType>& args, Stack&);
    PartialResult WARN_UNUSED_RETURN addRethrow(unsigned, ControlType&);

    // Calls
    std::pair<B3::PatchpointValue*, PatchpointExceptionHandle> WARN_UNUSED_RETURN emitCallPatchpoint(BasicBlock*, const TypeDefinition&, const ResultList& results, const Vector<ExpressionType>& args, Vector<ConstrainedTmp> extraArgs = {});

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

template<typename Taken>
void AirIRGenerator32_64::emitCheckForNullReference(const ExpressionType& ref, Taken&& taken)
{
    auto tmpForNullTag = g32();
    append(Move, Arg::bigImm(JSValue::NullTag), tmpForNullTag);
    emitCheck([&] {
        return Inst(Branch32, nullptr, Arg::relCond(MacroAssembler::Equal), ref.hi(), tmpForNullTag);
    }, std::forward<Taken>(taken));
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

template<size_t inlineCapacity>
PatchpointExceptionHandle AirIRGenerator32_64::preparePatchpointForExceptions(B3::PatchpointValue* patch, Vector<ConstrainedTmp, inlineCapacity>& args)
{
    ++m_callSiteIndex;
    if (!m_tryCatchDepth)
        return { m_hasExceptionHandlers };

    unsigned numLiveValues = 0;
    forEachLiveValue([&](TypedTmp tmp) {
        ++numLiveValues;
        if (tmp.isGPPair()) {
            ++numLiveValues;
            args.append(ConstrainedTmp(tmp.lo(), B3::ValueRep::LateColdAny));
            args.append(ConstrainedTmp(tmp.hi(), B3::ValueRep::LateColdAny));
            return;
        }
        args.append(ConstrainedTmp(tmp.tmp(), B3::ValueRep::LateColdAny));
    });

    patch->effects.exitsSideways = true;

    return { m_hasExceptionHandlers, m_callSiteIndex, numLiveValues };
}

Tmp AirIRGenerator32_64::emitCatchImpl(CatchKind kind, ControlType& data, unsigned exceptionIndex)
{
    m_currentBlock = m_code.addBlock();
    m_catchEntrypoints.append(m_currentBlock);

    if (ControlType::isTry(data)) {
        if (kind == CatchKind::Catch)
            data.convertTryToCatch(++m_callSiteIndex, g64());
        else
            data.convertTryToCatchAll(++m_callSiteIndex, g64());
    }
    // We convert from "try" to "catch" ControlType above. This doesn't
    // happen if ControlType is already a "catch". This can happen when
    // we have multiple catches like "try {} catch(A){} catch(B){}...CatchAll(E){}".
    // We just convert the first ControlType to a catch, then the others will
    // use its fields.
    ASSERT(ControlType::isAnyCatch(data));

    HandlerType handlerType = kind == CatchKind::Catch ? HandlerType::Catch : HandlerType::CatchAll;
    m_exceptionHandlers.append({ handlerType, data.tryStart(), data.tryEnd(), 0, m_tryCatchDepth, exceptionIndex });

    restoreWebAssemblyGlobalState(RestoreCachedStackLimit::Yes, m_info.memory, instanceValue(), m_currentBlock);

    unsigned indexInBuffer = 0;
    auto loadFromScratchBuffer = [&] (TypedTmp result) {
        Tmp bufferPtr = Tmp(GPRInfo::argumentGPR0);
        if (result.isGPPair()) {
            emitLoad(bufferPtr, sizeof(uint64_t) * indexInBuffer++, TypedTmp(result.lo(), Types::I32));
            emitLoad(bufferPtr, sizeof(uint64_t) * indexInBuffer++, TypedTmp(result.hi(), Types::I32));
            return;
        }
        emitLoad(bufferPtr, sizeof(uint64_t) * indexInBuffer++, result);
        return;
    };
    forEachLiveValue([&] (TypedTmp tmp) {
        // We set our current ControlEntry's exception below after the patchpoint, it's
        // not in the incoming buffer of live values.
        if (tmp != data.exception())
            loadFromScratchBuffer(tmp);
    });

    Vector<B3::Type> resultTypes {B3::pointerType(), B3::Int32, B3::Int32};
    B3::PatchpointValue* patch = addPatchpoint(m_proc.addTuple(WTFMove(resultTypes)));
    patch->effects.exitsSideways = true;
    patch->clobber(RegisterSet::macroScratchRegisters());
    RegisterSet clobberLate = RegisterSet::volatileRegistersForCCall();
    clobberLate.add(GPRInfo::argumentGPR0);
    clobberLate.add(GPRInfo::argumentGPR1);
    patch->clobberLate(clobberLate);
    patch->resultConstraints.append(B3::ValueRep::reg(GPRInfo::returnValueGPR));
    patch->resultConstraints.append(B3::ValueRep::SomeRegister);
    patch->resultConstraints.append(B3::ValueRep::SomeRegister); // result Tag
    patch->setGenerator([=] (CCallHelpers& jit, const B3::StackmapGenerationParams& params) {
        AllowMacroScratchRegisterUsage allowScratch(jit);
        // Returning one EncodedJSValue on the stack
        constexpr int32_t resultSpace = WTF::roundUpToMultipleOf<stackAlignmentBytes()>(static_cast<int32_t>(sizeof(EncodedJSValue)));
        jit.subPtr(CCallHelpers::TrustedImm32(resultSpace), MacroAssembler::stackPointerRegister);
        jit.move(params[3].gpr(), GPRInfo::argumentGPR0);
        jit.move(MacroAssembler::stackPointerRegister, GPRInfo::argumentGPR1);
        CCallHelpers::Call call = jit.call(OperationPtrTag);
        jit.addLinkTask([call] (LinkBuffer& linkBuffer) {
            linkBuffer.link<OperationPtrTag>(call, operationWasmRetrieveAndClearExceptionIfCatchable);
        });
        jit.load32(CCallHelpers::Address(MacroAssembler::stackPointerRegister, TagOffset), params[2].gpr());
        jit.loadPtr(CCallHelpers::Address(MacroAssembler::stackPointerRegister, PayloadOffset), params[1].gpr());
        jit.addPtr(CCallHelpers::TrustedImm32(resultSpace), MacroAssembler::stackPointerRegister);
    });
    TypedTmp buffer = TypedTmp(Tmp(GPRInfo::returnValueGPR), is64Bit() ? Types::I64 : Types::I32);
    TypedTmp exceptionLo = TypedTmp(data.exception().lo(), Types::I32);
    TypedTmp exceptionHi = TypedTmp(data.exception().hi(), Types::I32);
    emitPatchpoint(m_currentBlock, patch, Vector<TypedTmp, 8>::from(buffer, exceptionLo, exceptionHi), Vector<ConstrainedTmp, 1>::from(instanceValue()));
    return buffer;
}

auto AirIRGenerator32_64::addReturn(const ControlData& data, const Stack& returnValues) -> PartialResult
{
    CallInformation wasmCallInfo = wasmCallingConvention().callInformationFor(*data.signature(), CallRole::Callee);
    if (!wasmCallInfo.results.size()) {
        append(RetVoid);
        return { };
    }

    B3::PatchpointValue* patch = addPatchpoint(B3::Void);
    patch->setGenerator([] (CCallHelpers& jit, const B3::StackmapGenerationParams& params) {
        auto calleeSaves = params.code().calleeSaveRegisterAtOffsetList();
        jit.emitRestore(calleeSaves);
        jit.emitFunctionEpilogue();
        jit.ret();
    });
    patch->effects.terminal = true;

    ASSERT(returnValues.size() >= wasmCallInfo.results.size());
    unsigned offset = returnValues.size() - wasmCallInfo.results.size();
    Vector<ConstrainedTmp, 8> returnConstraints;
    for (unsigned i = 0; i < wasmCallInfo.results.size(); ++i) {
        B3::ValueRep rep = wasmCallInfo.results[i];
        TypedTmp tmp = returnValues[offset + i];

        if (rep.isStack()) {
            append(moveForType(toB3Type(tmp.type())), tmp, Arg::addr(Tmp(GPRInfo::callFrameRegister), rep.offsetFromFP()));
            continue;
        }

        ASSERT(rep.isReg());
        if (tmp.isGPPair()) {
            JSValueRegs jsr = wasmCallInfo.results[i].jsr();
            returnConstraints.append(ConstrainedTmp(tmp.lo(), B3::ValueRep { jsr.payloadGPR() }));
            returnConstraints.append(ConstrainedTmp(tmp.hi(), B3::ValueRep { jsr.tagGPR() }));
        } else
            returnConstraints.append(ConstrainedTmp(tmp, rep));
    }

    emitPatchpoint(m_currentBlock, patch, ResultList { }, WTFMove(returnConstraints));
    return { };
}

auto AirIRGenerator32_64::addThrow(unsigned exceptionIndex, Vector<ExpressionType>& args, Stack&) -> PartialResult
{
    B3::PatchpointValue* patch = addPatchpoint(B3::Void);
    patch->effects.terminal = true;
    patch->clobber(RegisterSet::volatileRegistersForJSCall());

    Vector<ConstrainedTmp, 8> patchArgs;
    patchArgs.append(ConstrainedTmp(instanceValue(), B3::ValueRep::reg(GPRInfo::argumentGPR0)));
    patchArgs.append(ConstrainedTmp(Tmp(GPRInfo::callFrameRegister), B3::ValueRep::reg(GPRInfo::argumentGPR1)));
    for (unsigned i = 0; i < args.size(); ++i) {
        if (args[i].isGPPair()) {
            patchArgs.append(ConstrainedTmp(args[i].lo(), B3::ValueRep::stackArgument(i * sizeof(EncodedJSValue) + PayloadOffset)));
            patchArgs.append(ConstrainedTmp(args[i].hi(), B3::ValueRep::stackArgument(i * sizeof(EncodedJSValue) + TagOffset)));
            continue;
        }
        patchArgs.append(ConstrainedTmp(args[i], B3::ValueRep::stackArgument(i * sizeof(EncodedJSValue))));
    }

    PatchpointExceptionHandle handle = preparePatchpointForExceptions(patch, patchArgs);

    patch->setGenerator([this, exceptionIndex, handle] (CCallHelpers& jit, const B3::StackmapGenerationParams& params) {
        AllowMacroScratchRegisterUsage allowScratch(jit);
        handle.generate(jit, params, this);
        emitThrowImpl(jit, exceptionIndex);
    });

    emitPatchpoint(m_currentBlock, patch, Tmp(), WTFMove(patchArgs));

    return { };
}

auto AirIRGenerator32_64::addRethrow(unsigned, ControlType& data) -> PartialResult
{
    B3::PatchpointValue* patch = addPatchpoint(B3::Void);
    patch->clobber(RegisterSet::volatileRegistersForJSCall());
    patch->effects.terminal = true;

    Vector<ConstrainedTmp, 3> patchArgs;
    patchArgs.append(ConstrainedTmp(instanceValue(), B3::ValueRep::reg(GPRInfo::argumentGPR0)));
    patchArgs.append(ConstrainedTmp(Tmp(GPRInfo::callFrameRegister), B3::ValueRep::reg(GPRInfo::argumentGPR1)));
    patchArgs.append(ConstrainedTmp(data.exception().lo(), B3::ValueRep::reg(GPRInfo::argumentGPR2)));
    patchArgs.append(ConstrainedTmp(data.exception().hi(), B3::ValueRep::reg(GPRInfo::argumentGPR3)));

    PatchpointExceptionHandle handle = preparePatchpointForExceptions(patch, patchArgs);
    patch->setGenerator([this, handle] (CCallHelpers& jit, const B3::StackmapGenerationParams& params) {
        AllowMacroScratchRegisterUsage allowScratch(jit);
        handle.generate(jit, params, this);
        emitRethrowImpl(jit);
    });

    emitPatchpoint(m_currentBlock, patch, Tmp(), WTFMove(patchArgs));

    return { };
}

std::pair<B3::PatchpointValue*, PatchpointExceptionHandle> AirIRGenerator32_64::emitCallPatchpoint(BasicBlock* block, const TypeDefinition& signature, const ResultList& results, const Vector<ExpressionType>& args, Vector<ConstrainedTmp> patchArgs)
{
    auto* patchpoint = addPatchpoint(toB3ResultType(&signature));
    patchpoint->effects.writesPinned = true;
    patchpoint->effects.readsPinned = true;
    patchpoint->clobberEarly(RegisterSet::macroScratchRegisters());
    patchpoint->clobberLate(RegisterSet::volatileRegistersForJSCall());

    CallInformation locations = wasmCallingConvention().callInformationFor(signature);
    m_code.requestCallArgAreaSizeInBytes(WTF::roundUpToMultipleOf(stackAlignmentBytes(), locations.headerAndArgumentStackSizeInBytes));

    ASSERT(locations.params.size() == args.size());
    ASSERT(locations.results.size() == results.size());

    // On 32-bit platforms, 64-bit integer types are passed as two 32-bit values
    size_t offset = patchArgs.size();
    size_t passedArgs = args.size();
    for (unsigned i = 0; i < args.size(); ++i) {
        if (args[i].isGPPair())
            ++passedArgs;
    }
    Checked<size_t> newSize = checkedSum<size_t>(patchArgs.size(), passedArgs);
    RELEASE_ASSERT(!newSize.hasOverflowed());
    patchArgs.grow(newSize);
    unsigned j = 0;
    for (unsigned i = 0; i < args.size(); ++i) {
        const TypedTmp& arg = args[i];
        ValueLocation& loc = locations.params[i];
        if (arg.isGPPair()) {
            B3::ValueRep valueRepLo = loc.isGPR() ? B3::ValueRep(loc.jsr().payloadGPR()) : B3::ValueRep::stackArgument(loc.offsetFromSP());
            B3::ValueRep valueRepHi = loc.isGPR() ? B3::ValueRep(loc.jsr().tagGPR()) : B3::ValueRep::stackArgument(loc.offsetFromSP() + 4);
            patchArgs[offset + j++] = ConstrainedTmp(arg.lo(), valueRepLo);
            patchArgs[offset + j++] = ConstrainedTmp(arg.hi(), valueRepHi);
            continue;
        }
        patchArgs[offset + j++] = ConstrainedTmp(arg, loc);
    }
    ASSERT(j == passedArgs);

    // On 32-bit platforms, 64-bit integer types are returned as two 32-bit values
    ResultList patchResults;
    if (patchpoint->type() != B3::Void) {
        Vector<B3::ValueRep, 1> resultConstraints;
        for (unsigned i = 0; i < results.size(); ++i) {
            const TypedTmp& result = results[i];
            ValueLocation& loc = locations.results[i];
            if (result.isGPPair()) {
                patchResults.append(TypedTmp { result.lo(), Types::I32 });
                patchResults.append(TypedTmp { result.hi(), Types::I32 });
                resultConstraints.append(loc.isGPR() ? B3::ValueRep(loc.jsr().payloadGPR()) : B3::ValueRep::stackArgument(loc.offsetFromSP()));
                resultConstraints.append(loc.isGPR() ? B3::ValueRep(loc.jsr().tagGPR()) : B3::ValueRep::stackArgument(loc.offsetFromSP() + 4));
                continue;
            }
            patchResults.append(result);
            resultConstraints.append(B3::ValueRep(loc));
        }
        patchpoint->resultConstraints = WTFMove(resultConstraints);
    } else
        ASSERT(!results.size());
    PatchpointExceptionHandle exceptionHandle = preparePatchpointForExceptions(patchpoint, patchArgs);
    emitPatchpoint(block, patchpoint, patchResults, WTFMove(patchArgs));
    return { patchpoint, exceptionHandle };
}

void AirIRGenerator32_64::sanitizeAtomicResult(ExtAtomicOpType op, TypedTmp source, TypedTmp dest)
{
    ASSERT(source.type() == dest.type());
    switch (source.type().kind) {
    case TypeKind::I64: {
        switch (accessWidth(op)) {
        case B3::Width8:
            append(ZeroExtend8To32, source.lo(), dest.lo());
            append(Move, Arg::imm(0), dest.hi());
            return;
        case B3::Width16:
            append(ZeroExtend16To32, source.lo(), dest.lo());
            append(Move, Arg::imm(0), dest.hi());
            return;
        case B3::Width32:
            append(Move, source.lo(), dest.lo());
            append(Move, Arg::imm(0), dest.hi());
            return;
        case B3::Width64:
            emitMove(source, dest);
            return;
        }
        return;
    }
    case TypeKind::I32:
        switch (accessWidth(op)) {
        case B3::Width8:
            append(ZeroExtend8To32, source, dest);
            return;
        case B3::Width16:
            append(ZeroExtend16To32, source, dest);
            return;
        case B3::Width32:
        case B3::Width64:
            emitMove(source, dest);
            return;
        }
        return;
    default:
        RELEASE_ASSERT_NOT_REACHED();
        return;
    }
}

void AirIRGenerator32_64::sanitizeAtomicResult(ExtAtomicOpType op, TypedTmp result)
{
    sanitizeAtomicResult(op, result, result);
}

template<typename InputType>
TypedTmp AirIRGenerator32_64::appendGeneralAtomic(ExtAtomicOpType op, B3::Air::Opcode opcode, B3::Commutativity commutativity, InputType input, Arg address, TypedTmp oldValue)
{
    static_assert(std::is_same_v<InputType, TypedTmp> || std::is_same_v<InputType, Arg>);

    B3::Width accessWidth = Wasm::accessWidth(op);

    auto newTmp = [&]() {
        if (accessWidth == B3::Width64)
            return g64();
        return g32();
    };

    auto tmp = [&]() -> TypedTmp {
        if constexpr (std::is_same_v<InputType, Arg>) {
            TypedTmp result = newTmp();
            if (result.isGPPair()) {
                append(Move, input, result.lo());
                append(Move, Arg::imm(0), result.hi());
                return result;
            }
            append(Move, input, result);
            return result;
        } else
            return input;
    };

    auto imm = [&]() -> Arg {
        if constexpr (std::is_same_v<InputType, Arg>) {
            if (input.isImm())
                return input;
        }
        return Arg();
    };

    auto bitImm = [&]() -> Arg {
        if constexpr (std::is_same_v<InputType, Arg>) {
            if (input.isBitImm())
                return input;
        }
        return Arg();
    };

    TypedTmp newValue = opcode == B3::Air::Nop ? tmp() : newTmp();

    // We need a CAS loop or a LL/SC loop. Using prepare/attempt jargon, we want:
    //
    // Block #reloop:
    //     Prepare
    //     opcode
    //     Attempt
    //   Successors: Then:#done, Else:#reloop
    // Block #done:
    //     Move oldValue, result

    auto* beginBlock = m_currentBlock;
    auto* reloopBlock = m_code.addBlock();
    auto* doneBlock = m_code.addBlock();

    appendEffectful(MemoryFence);
    append(B3::Air::Jump);
    beginBlock->setSuccessors(reloopBlock);
    m_currentBlock = reloopBlock;

    RELEASE_ASSERT(isARM());

    if (accessWidth == B3::Width64)
        appendEffectful(LoadLinkPair32, address, oldValue.lo(), oldValue.hi());
    else if (oldValue.isGPPair())
        appendEffectful(OPCODE_FOR_WIDTH(LoadLink, accessWidth), address, oldValue.lo());
    else
        appendEffectful(OPCODE_FOR_WIDTH(LoadLink, accessWidth), address, oldValue);

    if (opcode != B3::Air::Nop) {
        // FIXME: see note in WasmAirGenerator64::appendGeneralAtomic also
        TypedTmp inTmp = tmp();
        if (accessWidth == B3::Width64) {
            switch (opcode) {
            case Add64:
                append(Add64, oldValue.hi(), oldValue.lo(), inTmp.hi(), inTmp.lo(), newValue.hi(), newValue.lo());
                break;
            case Sub64:
                append(Sub64, oldValue.hi(), oldValue.lo(), inTmp.hi(), inTmp.lo(), newValue.hi(), newValue.lo());
                break;
            case And64:
                append(And32, oldValue.hi(), inTmp.hi(), newValue.hi());
                append(And32, oldValue.lo(), inTmp.lo(), newValue.lo());
                break;
            case Or64:
                append(Or32, oldValue.hi(), inTmp.hi(), newValue.hi());
                append(Or32, oldValue.lo(), inTmp.lo(), newValue.lo());
                break;
            case Xor64:
                append(Xor32, oldValue.hi(), inTmp.hi(), newValue.hi());
                append(Xor32, oldValue.lo(), inTmp.lo(), newValue.lo());
                break;
            default:
                RELEASE_ASSERT_NOT_REACHED();
                break;
            }
        } else {
            Tmp oldVal = oldValue.isGPPair() ? oldValue.lo() : oldValue.tmp();
            Tmp newVal = newValue.isGPPair() ? newValue.lo() : newValue.tmp();
            Tmp inVal = inTmp.isGPPair() ? inTmp.lo() : inTmp.tmp();
            if (commutativity == B3::Commutative && imm() && isValidForm(opcode, Arg::Imm, Arg::Tmp, Arg::Tmp))
                append(opcode, imm(), oldVal, newVal);
            else if (imm() && isValidForm(opcode, Arg::Tmp, Arg::Imm, Arg::Tmp))
                append(opcode, oldVal, imm(), newVal);
            else if (commutativity == B3::Commutative && bitImm() && isValidForm(opcode, Arg::BitImm, Arg::Tmp, Arg::Tmp))
                append(opcode, bitImm(), oldVal, newVal);
            else if (isValidForm(opcode, Arg::Tmp, Arg::Tmp, Arg::Tmp))
                append(opcode, oldVal, inVal, newVal);
            else {
                append(Move, oldVal, newVal);
                if (imm() && isValidForm(opcode, Arg::Imm, Arg::Tmp))
                    append(opcode, imm(), newVal);
                else
                    append(opcode, inVal, newVal);
            }
        }
    }

    TypedTmp boolResult = g32();
    if (accessWidth == B3::Width64)
        appendEffectful(StoreCondPair32, newValue.lo(), newValue.hi(), address, boolResult);
    else if (newValue.isGPPair())
        appendEffectful(OPCODE_FOR_WIDTH(StoreCond, accessWidth), newValue.lo(), address, boolResult);
    else
        appendEffectful(OPCODE_FOR_WIDTH(StoreCond, accessWidth), newValue, address, boolResult);
    append(BranchTest32, Arg::resCond(MacroAssembler::Zero), boolResult, boolResult);
    reloopBlock->setSuccessors(doneBlock, reloopBlock);
    m_currentBlock = doneBlock;
    appendEffectful(MemoryFence);
    return oldValue;
}

TypedTmp AirIRGenerator32_64::appendStrongCAS(ExtAtomicOpType op, TypedTmp expected, TypedTmp newValue, Arg address, TypedTmp oldValue)
{
    B3::Width accessWidth = Wasm::accessWidth(op);

    // We wish to emit:
    //
    // Block #reloop:
    //     LoadLink
    //     Branch NotEqual
    //   Successors: Then:#fail, Else: #store
    // Block #store:
    //     StoreCond
    //     Xor $1, %result    <--- only if !invert
    //     Jump
    //   Successors: #done
    // Block #fail:
    //     Move $invert, %result
    //     Jump
    //   Successors: #done
    // Block #done:

    auto* reloopBlock = m_code.addBlock();
    auto* storeBlock = m_code.addBlock();
    auto* strongFailBlock = m_code.addBlock();
    auto* doneBlock = m_code.addBlock();
    auto* beginBlock = m_currentBlock;

    appendEffectful(MemoryFence);
    append(B3::Air::Jump);
    beginBlock->setSuccessors(reloopBlock);

    m_currentBlock = reloopBlock;
    if (accessWidth == B3::Width64) {
        appendEffectful(LoadLinkPair32, address, oldValue.lo(), oldValue.hi());
        append(Branch32, Arg::relCond(MacroAssembler::NotEqual), oldValue.lo(), expected.lo());
        auto* checkHiBlock = m_code.addBlock();
        reloopBlock->setSuccessors(B3::Air::FrequentedBlock(strongFailBlock), checkHiBlock);
        m_currentBlock = checkHiBlock;
        append(Branch32, Arg::relCond(MacroAssembler::NotEqual), oldValue.hi(), expected.hi());
    } else if (oldValue.isGPPair()) {
        appendEffectful(OPCODE_FOR_WIDTH(LoadLink, accessWidth), address, oldValue.lo());
        append(OPCODE_FOR_CANONICAL_WIDTH(Branch, accessWidth), Arg::relCond(MacroAssembler::NotEqual), oldValue.lo(), expected.lo());
    } else {
        appendEffectful(OPCODE_FOR_WIDTH(LoadLink, accessWidth), address, oldValue);
        append(OPCODE_FOR_CANONICAL_WIDTH(Branch, accessWidth), Arg::relCond(MacroAssembler::NotEqual), oldValue, expected);
    }
    reloopBlock->setSuccessors(B3::Air::FrequentedBlock(strongFailBlock), storeBlock);

    m_currentBlock = storeBlock;
    {
        TypedTmp tmp = g32();
        if (accessWidth == B3::Width64)
            appendEffectful(StoreCondPair32, newValue.lo(), newValue.hi(), address, tmp);
        else if (newValue.isGPPair())
            appendEffectful(OPCODE_FOR_WIDTH(StoreCond, accessWidth), newValue.lo(), address, tmp);
        else
            appendEffectful(OPCODE_FOR_WIDTH(StoreCond, accessWidth), newValue, address, tmp);
        append(BranchTest32, Arg::resCond(MacroAssembler::Zero), tmp, tmp);
    }
    storeBlock->setSuccessors(doneBlock, reloopBlock);

    m_currentBlock = strongFailBlock;
    {
        TypedTmp tmp = g32();
        if (accessWidth == B3::Width64)
            appendEffectful(StoreCondPair32, oldValue.lo(), oldValue.hi(), address, tmp);
        else if (oldValue.isGPPair())
            appendEffectful(OPCODE_FOR_WIDTH(StoreCond, accessWidth), oldValue.lo(), address, tmp);
        else
            appendEffectful(OPCODE_FOR_WIDTH(StoreCond, accessWidth), oldValue, address, tmp);
        append(BranchTest32, Arg::resCond(MacroAssembler::Zero), tmp, tmp);
    }
    strongFailBlock->setSuccessors(B3::Air::FrequentedBlock(doneBlock), reloopBlock);

    m_currentBlock = doneBlock;
    appendEffectful(MemoryFence);
    return oldValue;
}




Expected<std::unique_ptr<InternalFunction>, String> parseAndCompileAir(CompilationContext& compilationContext, const FunctionData& function, const TypeDefinition& signature, Vector<UnlinkedWasmToWasmCall>& unlinkedWasmToWasmCalls, const ModuleInformation& info, MemoryMode mode, uint32_t functionIndex, std::optional<bool> hasExceptionHandlers, TierUpCount* tierUp)
{
    return parseAndCompileAirImpl<AirIRGenerator32_64>(compilationContext, function, signature, unlinkedWasmToWasmCalls, info, mode, functionIndex, hasExceptionHandlers, tierUp);
}

}
} // namespace JSC::Wasm

#endif
