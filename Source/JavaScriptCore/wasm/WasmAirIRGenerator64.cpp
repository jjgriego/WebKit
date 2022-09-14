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

#if USE(JSVALUE64) && ENABLE(WEBASSEMBLY_B3JIT)

namespace JSC { namespace Wasm {

////////////////////////////////////////////////////////////////////////////////
// 64-bit AirIRGenerator
////////////////////////////////////////////////////////////////////////////////

class TypedTmp {
public:
    constexpr TypedTmp()
        : m_tmp()
        , m_type(Types::Void)
    {
    }

    TypedTmp(Tmp tmp, Type type)
        : m_tmp(tmp)
        , m_type(type)
    {
    }

    TypedTmp(const TypedTmp&) = default;
    TypedTmp(TypedTmp&&) = default;
    TypedTmp& operator=(TypedTmp&&) = default;
    TypedTmp& operator=(const TypedTmp&) = default;

    bool operator==(const TypedTmp& other) const
    {
        return m_tmp == other.m_tmp && m_type == other.m_type;
    }
    bool operator!=(const TypedTmp& other) const
    {
        return !(*this == other);
    }

    explicit operator bool() const { return !!tmp(); }

    operator Tmp() const { return tmp(); }
    operator Arg() const { return Arg(tmp()); }
    Tmp tmp() const { return m_tmp; }
    Type type() const { return m_type; }

    void dump(PrintStream& out) const
    {
        out.print("(", m_tmp, ", ", m_type.kind, ", ", m_type.index, ")");
    }

private:
    Tmp m_tmp;
    Type m_type;
};

class AirIRGenerator64 : public AirIRGeneratorBase<AirIRGenerator64, TypedTmp> {
public:
    friend AirIRGeneratorBase<AirIRGenerator64, TypedTmp>;
    using ExpressionType = TypedTmp;

    static ExpressionType emptyExpression() { return { }; };

    AirIRGenerator64(const ModuleInformation&, B3::Procedure&, InternalFunction*, Vector<UnlinkedWasmToWasmCall>&, MemoryMode, unsigned functionIndex, std::optional<bool> hasExceptionHandlers, TierUpCount*, const TypeDefinition&, unsigned& osrEntryScratchBufferSize);

    ExpressionType addConstant(Type, uint64_t);
    ExpressionType addConstant(BasicBlock*, Type, uint64_t);

    // References
    PartialResult WARN_UNUSED_RETURN addRefIsNull(ExpressionType value, ExpressionType& result);

    // Memory
    PartialResult WARN_UNUSED_RETURN load(LoadOpType, ExpressionType pointer, ExpressionType& result, uint32_t offset);
    PartialResult WARN_UNUSED_RETURN store(StoreOpType, ExpressionType pointer, ExpressionType value, uint32_t offset);

    // Saturated truncation.
    PartialResult WARN_UNUSED_RETURN truncSaturated(Ext1OpType, ExpressionType operand, ExpressionType& result, Type returnType, Type operandType);

    // GC
    PartialResult WARN_UNUSED_RETURN addI31New(ExpressionType value, ExpressionType& result);
    PartialResult WARN_UNUSED_RETURN addI31GetS(ExpressionType ref, ExpressionType& result);
    PartialResult WARN_UNUSED_RETURN addI31GetU(ExpressionType ref, ExpressionType& result);

    PartialResult WARN_UNUSED_RETURN addSelect(ExpressionType condition, ExpressionType nonZero, ExpressionType zero, ExpressionType& result);

    // Control flow
    PartialResult WARN_UNUSED_RETURN addReturn(const ControlData&, const Stack& returnValues);
    PartialResult WARN_UNUSED_RETURN addThrow(unsigned exceptionIndex, Vector<ExpressionType>& args, Stack&);
    PartialResult WARN_UNUSED_RETURN addRethrow(unsigned, ControlType&);

    // Calls
    std::pair<B3::PatchpointValue*, PatchpointExceptionHandle> WARN_UNUSED_RETURN emitCallPatchpoint(BasicBlock*, const TypeDefinition&, const ResultList& results, const Vector<TypedTmp>& args, Vector<ConstrainedTmp> extraArgs = { });

    PartialResult addShift(Type, B3::Air::Opcode, ExpressionType value, ExpressionType shift, ExpressionType& result);
    PartialResult addIntegerSub(B3::Air::Opcode, ExpressionType lhs, ExpressionType rhs, ExpressionType& result);
    PartialResult addFloatingPointAbs(B3::Air::Opcode, ExpressionType value, ExpressionType& result);
    PartialResult addFloatingPointBinOp(Type, B3::Air::Opcode, ExpressionType lhs, ExpressionType rhs, ExpressionType& result);

    Tmp emitCatchImpl(CatchKind, ControlType&, unsigned exceptionIndex = 0);
    template <size_t inlineCapacity>
    PatchpointExceptionHandle preparePatchpointForExceptions(B3::PatchpointValue*, Vector<ConstrainedTmp, inlineCapacity>& args);

private:
    TypedTmp g32() { return { newTmp(B3::GP), Types::I32 }; }
    TypedTmp g64() { return { newTmp(B3::GP), Types::I64 }; }
    decltype(auto) gPtr() { return g64(); }
    TypedTmp gExternref() { return { newTmp(B3::GP), Types::Externref }; }
    TypedTmp gFuncref() { return { newTmp(B3::GP), Types::Funcref }; }
    TypedTmp gRef(Type type) { return { newTmp(B3::GP), type }; }
    TypedTmp f32() { return { newTmp(B3::FP), Types::F32 }; }
    TypedTmp f64() { return { newTmp(B3::FP), Types::F64 }; }

    static auto constexpr AddPtr = Add64;
    static auto constexpr MulPtr = Mul64;
    static auto constexpr UrshiftPtr = Urshift64;
    static auto constexpr LeaPtr = Lea64;
    static auto constexpr BranchTestPtr = BranchTest64;
    static auto constexpr BranchPtr = Branch64;

    static Arg extractArg(const TypedTmp& tmp) { return tmp.tmp(); }
    static Arg extractArg(const Tmp& tmp) { return Arg(tmp); }
    static Arg extractArg(const Arg& arg) { return arg; }

    Tmp extractJSValuePointer(const TypedTmp& tmp) const { return tmp.tmp(); }

    void emitZeroInitialize(ExpressionType t);
    template <typename Taken>
    void emitCheckI64Zero(ExpressionType, Taken&& taken);
    template<typename Then>
    void emitCheckForNullReference(const ExpressionType& ref, Then&& then);

    static B3::Air::Opcode moveOpForValueType(Type type)
    {
        switch (type.kind) {
        case TypeKind::I32:
            return Move32;
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

    void emitLoad(B3::Air::Opcode op, B3::Type type, Tmp base, size_t offset, Tmp result)
    {
        if (Arg::isValidAddrForm(offset, B3::widthForType(type)))
            append(op, Arg::addr(base, offset), result);
        else {
            auto temp2 = g64();
            append(Move, Arg::bigImm(offset), temp2);
            append(Add64, temp2, base, temp2);
            append(op, Arg::addr(temp2), result);
        }
    }

    void emitStore(const TypedTmp& value, Tmp base, size_t offset)
    {
        if (!Arg::isValidAddrForm(offset, B3::widthForType(toB3Type(value.type())))) {
            auto address = g64();
            append(Move, Arg::bigImm(offset), address);
            append(Add64, base, address, address);
            base = address.tmp();
            offset = 0;
        }

        append(moveOpForValueType(value.type()), value, Arg::addr(base, offset));
    }

    void appendCCallArg(B3::Air::Inst& inst, const TypedTmp& tmp) {
        inst.args.append(tmp.tmp());
    }

    void emitLoad(Tmp base, size_t offset, const TypedTmp& result)
    {
        emitLoad(moveOpForValueType(result.type()), toB3Type(result.type()), base, offset, result.tmp());
    }

    void emitMove(const TypedTmp& src, const TypedTmp& dst) {
        if (src == dst)
            return;
        ASSERT(isSubtype(src.type(), dst.type()));
        append(moveOpForValueType(src.type()), src, dst);
    }

    ExpressionType emitCheckAndPreparePointer(ExpressionType pointer, uint32_t offset, uint32_t sizeOfOp);
    ExpressionType emitLoadOp(LoadOpType, ExpressionType pointer, uint32_t offset);
    void emitStoreOp(StoreOpType, ExpressionType pointer, ExpressionType value, uint32_t offset);

    void sanitizeAtomicResult(ExtAtomicOpType, TypedTmp source, TypedTmp dest);
    void sanitizeAtomicResult(ExtAtomicOpType, TypedTmp result);
    TypedTmp appendGeneralAtomic(ExtAtomicOpType, B3::Air::Opcode nonAtomicOpcode, B3::Commutativity, Arg input, Arg addrArg, TypedTmp result);
    TypedTmp appendStrongCAS(ExtAtomicOpType, TypedTmp expected, TypedTmp value, Arg addrArg, TypedTmp result);

    template <typename IntType>
    void emitChecksForModOrDiv(bool isSignedDiv, ExpressionType left, ExpressionType right);

    template <typename IntType>
    void emitModOrDiv(bool isDiv, ExpressionType lhs, ExpressionType rhs, ExpressionType& result);

    enum class MinOrMax { Min, Max };

    PartialResult addFloatingPointMinOrMax(Type, MinOrMax, ExpressionType lhs, ExpressionType rhs, ExpressionType& result);


    bool useSignalingMemory() const
    {
#if ENABLE(WEBASSEMBLY_SIGNALING_MEMORY)
        return m_mode == MemoryMode::Signaling;
#else
        return false;
#endif
    }

};

AirIRGenerator64::AirIRGenerator64(const ModuleInformation& info, B3::Procedure& procedure, InternalFunction* compilation, Vector<UnlinkedWasmToWasmCall>& unlinkedWasmToWasmCalls, MemoryMode mode, unsigned functionIndex, std::optional<bool> hasExceptionHandlers, TierUpCount* tierUp, const TypeDefinition& originalSignature, unsigned& osrEntryScratchBufferSize)
    : AirIRGeneratorBase(info, procedure, compilation, unlinkedWasmToWasmCalls, mode, functionIndex, hasExceptionHandlers, tierUp, originalSignature, osrEntryScratchBufferSize)
{
}

void AirIRGenerator64::emitZeroInitialize(ExpressionType value)
{
    auto const type = value.type();
    switch (type.kind) {
    case TypeKind::Externref:
    case TypeKind::Funcref:
    case TypeKind::Ref:
    case TypeKind::RefNull:
        append(Move, Arg::imm(JSValue::encode(jsNull())), value);
        break;
    case TypeKind::I32:
    case TypeKind::I64: {
        append(Xor64, value, value);
        break;
    }
    case TypeKind::F32:
    case TypeKind::F64: {
        auto temp = g64();
        // IEEE 754 "0" is just int32/64 zero.
        append(Xor64, temp, temp);
        append(type.isF32() ? Move32ToFloat : Move64ToDouble, temp, value);
        break;
    }
    default:
        RELEASE_ASSERT_NOT_REACHED();
    }
}

template<typename Taken>
void AirIRGenerator64::emitCheckI64Zero(ExpressionType value, Taken&& taken) {
    emitCheck([&] {
        return Inst(BranchTest64, nullptr, Arg::resCond(MacroAssembler::Zero), value, value);
    }, std::forward<Taken>(taken));
}

template<typename Taken>
void AirIRGenerator64::emitCheckForNullReference(const TypedTmp& ref, Taken&& taken)
{
    auto tmpForNull = g64();
    append(Move, Arg::bigImm(JSValue::encode(jsNull())), tmpForNull);
    emitCheck([&] {
        return Inst(Branch64, nullptr, Arg::relCond(MacroAssembler::Equal), ref, tmpForNull);
    }, std::forward<Taken>(taken));
}

auto AirIRGenerator64::addConstant(Type type, uint64_t value) -> ExpressionType
{
    return addConstant(m_currentBlock, type, value);
}

auto AirIRGenerator64::addConstant(BasicBlock* block, Type type, uint64_t value) -> ExpressionType
{
    auto result = tmpForType(type);
    switch (type.kind) {
    case TypeKind::I32:
    case TypeKind::I64:
    case TypeKind::Externref:
    case TypeKind::Funcref:
    case TypeKind::Ref:
    case TypeKind::RefNull:
        append(block, Move, Arg::bigImm(value), result);
        break;
    case TypeKind::F32:
    case TypeKind::F64: {
        auto tmp = g64();
        append(block, Move, Arg::bigImm(value), tmp);
        append(block, type.isF32() ? Move32ToFloat : Move64ToDouble, tmp, result);
        break;
    }

    default:
        RELEASE_ASSERT_NOT_REACHED();
    }

    return result;
}

auto AirIRGenerator64::addRefIsNull(ExpressionType value, ExpressionType& result) -> PartialResult
{
    ASSERT(value.tmp());
    result = tmpForType(Types::I32);
    auto tmp = g64();

    append(Move, Arg::bigImm(JSValue::encode(jsNull())), tmp);
    append(Compare64, Arg::relCond(MacroAssembler::Equal), value, tmp, result);

    return { };
}

inline AirIRGenerator64::ExpressionType AirIRGenerator64::emitCheckAndPreparePointer(ExpressionType pointer, uint32_t offset, uint32_t sizeOfOperation)
{
    ASSERT(m_memoryBaseGPR);

    auto result = g64();
    append(Move32, pointer, result);

    switch (m_mode) {
    case MemoryMode::BoundsChecking: {
        // In bound checking mode, while shared wasm memory partially relies on signal handler too, we need to perform bound checking
        // to ensure that no memory access exceeds the current memory size.
        ASSERT(m_boundsCheckingSizeGPR);
        ASSERT(sizeOfOperation + offset > offset);
        auto temp = g64();
        append(Move, Arg::bigImm(static_cast<uint64_t>(sizeOfOperation) + offset - 1), temp);
        append(Add64, result, temp);

        emitCheck([&] {
            return Inst(Branch64, nullptr, Arg::relCond(MacroAssembler::AboveOrEqual), temp, Tmp(m_boundsCheckingSizeGPR));
        }, [=, this] (CCallHelpers& jit, const B3::StackmapGenerationParams&) {
            this->emitThrowException(jit, ExceptionType::OutOfBoundsMemoryAccess);
        });
        break;
    }

#if ENABLE(WEBASSEMBLY_SIGNALING_MEMORY)
    case MemoryMode::Signaling: {
        // We've virtually mapped 4GiB+redzone for this memory. Only the user-allocated pages are addressable, contiguously in range [0, current],
        // and everything above is mapped PROT_NONE. We don't need to perform any explicit bounds check in the 4GiB range because WebAssembly register
        // memory accesses are 32-bit. However WebAssembly register + offset accesses perform the addition in 64-bit which can push an access above
        // the 32-bit limit (the offset is unsigned 32-bit). The redzone will catch most small offsets, and we'll explicitly bounds check any
        // register + large offset access. We don't think this will be generated frequently.
        //
        // We could check that register + large offset doesn't exceed 4GiB+redzone since that's technically the limit we need to avoid overflowing the
        // PROT_NONE region, but it's better if we use a smaller immediate because it can codegens better. We know that anything equal to or greater
        // than the declared 'maximum' will trap, so we can compare against that number. If there was no declared 'maximum' then we still know that
        // any access equal to or greater than 4GiB will trap, no need to add the redzone.
        if (offset >= Memory::fastMappedRedzoneBytes()) {
            uint64_t maximum = m_info.memory.maximum() ? m_info.memory.maximum().bytes() : std::numeric_limits<uint32_t>::max();
            auto temp = g64();
            append(Move, Arg::bigImm(static_cast<uint64_t>(sizeOfOperation) + offset - 1), temp);
            append(Add64, result, temp);
            auto sizeMax = addConstant(Types::I64, maximum);

            emitCheck([&] {
                return Inst(Branch64, nullptr, Arg::relCond(MacroAssembler::AboveOrEqual), temp, sizeMax);
            }, [=, this] (CCallHelpers& jit, const B3::StackmapGenerationParams&) {
                this->emitThrowException(jit, ExceptionType::OutOfBoundsMemoryAccess);
            });
        }
        break;
    }
#endif
    }

    append(Add64, Tmp(m_memoryBaseGPR), result);
    return result;
}

inline TypedTmp AirIRGenerator64::emitLoadOp(LoadOpType op, ExpressionType pointer, uint32_t uoffset)
{
    uint32_t offset = fixupPointerPlusOffset(pointer, uoffset);

    TypedTmp immTmp;
    TypedTmp newPtr;
    TypedTmp result;

    Arg addrArg;
    if (Arg::isValidAddrForm(offset, B3::widthForBytes(sizeOfLoadOp(op))))
        addrArg = Arg::addr(pointer, offset);
    else {
        immTmp = g64();
        newPtr = g64();
        append(Move, Arg::bigImm(offset), immTmp);
        append(Add64, immTmp, pointer, newPtr);
        addrArg = Arg::addr(newPtr);
    }

    switch (op) {
    case LoadOpType::I32Load8S: {
        result = g32();
        appendEffectful(Load8SignedExtendTo32, addrArg, result);
        break;
    }

    case LoadOpType::I64Load8S: {
        result = g64();
        appendEffectful(Load8SignedExtendTo32, addrArg, result);
        append(SignExtend32ToPtr, result, result);
        break;
    }

    case LoadOpType::I32Load8U: {
        result = g32();
        appendEffectful(Load8, addrArg, result);
        break;
    }

    case LoadOpType::I64Load8U: {
        result = g64();
        appendEffectful(Load8, addrArg, result);
        break;
    }

    case LoadOpType::I32Load16S: {
        result = g32();
        appendEffectful(Load16SignedExtendTo32, addrArg, result);
        break;
    }

    case LoadOpType::I64Load16S: {
        result = g64();
        appendEffectful(Load16SignedExtendTo32, addrArg, result);
        append(SignExtend32ToPtr, result, result);
        break;
    }

    case LoadOpType::I32Load16U: {
        result = g32();
        appendEffectful(Load16, addrArg, result);
        break;
    }

    case LoadOpType::I64Load16U: {
        result = g64();
        appendEffectful(Load16, addrArg, result);
        break;
    }

    case LoadOpType::I32Load:
        result = g32();
        appendEffectful(Move32, addrArg, result);
        break;

    case LoadOpType::I64Load32U: {
        result = g64();
        appendEffectful(Move32, addrArg, result);
        break;
    }

    case LoadOpType::I64Load32S: {
        result = g64();
        appendEffectful(Move32, addrArg, result);
        append(SignExtend32ToPtr, result, result);
        break;
    }

    case LoadOpType::I64Load: {
        result = g64();
        appendEffectful(Move, addrArg, result);
        break;
    }

    case LoadOpType::F32Load: {
        result = f32();
        appendEffectful(MoveFloat, addrArg, result);
        break;
    }

    case LoadOpType::F64Load: {
        result = f64();
        appendEffectful(MoveDouble, addrArg, result);
        break;
    }
    }

    return result;
}

auto AirIRGenerator64::load(LoadOpType op, ExpressionType pointer, ExpressionType& result, uint32_t offset) -> PartialResult
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

inline void AirIRGenerator64::emitStoreOp(StoreOpType op, ExpressionType pointer, ExpressionType value, uint32_t uoffset)
{
    uint32_t offset = fixupPointerPlusOffset(pointer, uoffset);

    TypedTmp immTmp;
    TypedTmp newPtr;

    Arg addrArg;
    if (Arg::isValidAddrForm(offset, B3::widthForBytes(sizeOfStoreOp(op))))
        addrArg = Arg::addr(pointer, offset);
    else {
        immTmp = g64();
        newPtr = g64();
        append(Move, Arg::bigImm(offset), immTmp);
        append(Add64, immTmp, pointer, newPtr);
        addrArg = Arg::addr(newPtr);
    }

    switch (op) {
    case StoreOpType::I64Store8:
    case StoreOpType::I32Store8:
        append(Store8, value, addrArg);
        return;

    case StoreOpType::I64Store16:
    case StoreOpType::I32Store16:
        append(Store16, value, addrArg);
        return;

    case StoreOpType::I64Store32:
    case StoreOpType::I32Store:
        append(Move32, value, addrArg);
        return;

    case StoreOpType::I64Store:
        append(Move, value, addrArg);
        return;

    case StoreOpType::F32Store:
        append(MoveFloat, value, addrArg);
        return;

    case StoreOpType::F64Store:
        append(MoveDouble, value, addrArg);
        return;
    }

    RELEASE_ASSERT_NOT_REACHED();
}

auto AirIRGenerator64::store(StoreOpType op, ExpressionType pointer, ExpressionType value, uint32_t offset) -> PartialResult
{
    ASSERT(pointer.tmp().isGP());

    if (UNLIKELY(sumOverflows<uint32_t>(offset, sizeOfStoreOp(op)))) {
        // FIXME: Even though this is provably out of bounds, it's not a validation error, so we have to handle it
        // as a runtime exception. However, this may change: https://bugs.webkit.org/show_bug.cgi?id=166435
        auto* throwException = addPatchpoint(B3::Void);
        throwException->setGenerator([this] (CCallHelpers& jit, const B3::StackmapGenerationParams&) {
            this->emitThrowException(jit, ExceptionType::OutOfBoundsMemoryAccess);
        });
        emitPatchpoint(throwException, Tmp());
    } else
        emitStoreOp(op, emitCheckAndPreparePointer(pointer, offset, sizeOfStoreOp(op)), value, offset);

    return { };
}

void AirIRGenerator64::sanitizeAtomicResult(ExtAtomicOpType op, TypedTmp source, TypedTmp dest)
{
    ASSERT(source.type() == dest.type());
    switch (source.type().kind) {
    case TypeKind::I64: {
        switch (accessWidth(op)) {
        case B3::Width8:
            append(ZeroExtend8To32, source, dest);
            return;
        case B3::Width16:
            append(ZeroExtend16To32, source, dest);
            return;
        case B3::Width32:
            append(Move32, source, dest);
            return;
        case B3::Width64:
            if (source == dest)
                return;
            append(Move, source, dest);
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
            if (source == dest)
                return;
            append(Move, source, dest);
            return;
        }
        return;
    default:
        RELEASE_ASSERT_NOT_REACHED();
        return;
    }
}

void AirIRGenerator64::sanitizeAtomicResult(ExtAtomicOpType op, TypedTmp result)
{
    sanitizeAtomicResult(op, result, result);
}

TypedTmp AirIRGenerator64::appendGeneralAtomic(ExtAtomicOpType op, B3::Air::Opcode opcode, B3::Commutativity commutativity, Arg input, Arg address, TypedTmp oldValue)
{
    B3::Width accessWidth = Wasm::accessWidth(op);

    auto newTmp = [&]() {
        if (accessWidth == B3::Width64)
            return g64();
        return g32();
    };

    auto tmp = [&](Arg arg) -> TypedTmp {
        if (arg.isTmp())
            return TypedTmp(arg.tmp(), accessWidth == B3::Width64 ? Types::I64 : Types::I32);
        TypedTmp result = newTmp();
        append(Move, arg, result);
        return result;
    };

    auto imm = [&](Arg arg) {
        if (arg.isImm())
            return arg;
        return Arg();
    };

    auto bitImm = [&](Arg arg) {
        if (arg.isBitImm())
            return arg;
        return Arg();
    };

    Tmp newValue = opcode == B3::Air::Nop ? tmp(input) : newTmp();

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

    append(B3::Air::Jump);
    beginBlock->setSuccessors(reloopBlock);
    m_currentBlock = reloopBlock;

    B3::Air::Opcode prepareOpcode;
    if (isX86()) {
        switch (accessWidth) {
        case B3::Width8:
            prepareOpcode = Load8SignedExtendTo32;
            break;
        case B3::Width16:
            prepareOpcode = Load16SignedExtendTo32;
            break;
        case B3::Width32:
            prepareOpcode = Move32;
            break;
        case B3::Width64:
            prepareOpcode = Move;
            break;
        }
    } else {
        RELEASE_ASSERT(isARM64());
        prepareOpcode = OPCODE_FOR_WIDTH(LoadLinkAcq, accessWidth);
    }
    appendEffectful(prepareOpcode, address, oldValue);

    if (opcode != B3::Air::Nop) {
        // FIXME: If we ever have to write this again, we need to find a way to share the code with
        // appendBinOp.
        // https://bugs.webkit.org/show_bug.cgi?id=169249
        if (commutativity == B3::Commutative && imm(input) && isValidForm(opcode, Arg::Imm, Arg::Tmp, Arg::Tmp))
            append(opcode, imm(input), oldValue, newValue);
        else if (imm(input) && isValidForm(opcode, Arg::Tmp, Arg::Imm, Arg::Tmp))
            append(opcode, oldValue, imm(input), newValue);
        else if (commutativity == B3::Commutative && bitImm(input) && isValidForm(opcode, Arg::BitImm, Arg::Tmp, Arg::Tmp))
            append(opcode, bitImm(input), oldValue, newValue);
        else if (isValidForm(opcode, Arg::Tmp, Arg::Tmp, Arg::Tmp))
            append(opcode, oldValue, tmp(input), newValue);
        else {
            append(Move, oldValue, newValue);
            if (imm(input) && isValidForm(opcode, Arg::Imm, Arg::Tmp))
                append(opcode, imm(input), newValue);
            else
                append(opcode, tmp(input), newValue);
        }
    }

    if (isX86()) {
#if CPU(X86) || CPU(X86_64)
        Tmp eax(X86Registers::eax);
        B3::Air::Opcode casOpcode = OPCODE_FOR_WIDTH(BranchAtomicStrongCAS, accessWidth);
        append(Move, oldValue, eax);
        appendEffectful(casOpcode, Arg::statusCond(MacroAssembler::Success), eax, newValue, address);
#endif
    } else {
        RELEASE_ASSERT(isARM64());
        TypedTmp boolResult = newTmp();
        appendEffectful(OPCODE_FOR_WIDTH(StoreCondRel, accessWidth), newValue, address, boolResult);
        append(BranchTest32, Arg::resCond(MacroAssembler::Zero), boolResult, boolResult);
    }
    reloopBlock->setSuccessors(doneBlock, reloopBlock);
    m_currentBlock = doneBlock;
    return oldValue;
}

TypedTmp AirIRGenerator64::appendStrongCAS(ExtAtomicOpType op, TypedTmp expected, TypedTmp value, Arg address, TypedTmp valueResultTmp)
{
    B3::Width accessWidth = Wasm::accessWidth(op);

    auto newTmp = [&]() {
        if (accessWidth == B3::Width64)
            return g64();
        return g32();
    };

    auto tmp = [&](Arg arg) -> TypedTmp {
        if (arg.isTmp())
            return TypedTmp(arg.tmp(), accessWidth == B3::Width64 ? Types::I64 : Types::I32);
        TypedTmp result = newTmp();
        append(Move, arg, result);
        return result;
    };

    Tmp successBoolResultTmp = newTmp();

    Tmp expectedValueTmp = tmp(expected);
    Tmp newValueTmp = tmp(value);

    if (isX86()) {
#if CPU(X86) || CPU(X86_64)
        Tmp eax(X86Registers::eax);
        append(Move, expectedValueTmp, eax);
        appendEffectful(OPCODE_FOR_WIDTH(AtomicStrongCAS, accessWidth), eax, newValueTmp, address);
        append(Move, eax, valueResultTmp);
#endif
        return valueResultTmp;
    }

    if (isARM64E()) {
        append(Move, expectedValueTmp, valueResultTmp);
        appendEffectful(OPCODE_FOR_WIDTH(AtomicStrongCAS, accessWidth), valueResultTmp, newValueTmp, address);
        return valueResultTmp;
    }


    RELEASE_ASSERT(isARM64());
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

    append(B3::Air::Jump);
    beginBlock->setSuccessors(reloopBlock);

    m_currentBlock = reloopBlock;
    appendEffectful(OPCODE_FOR_WIDTH(LoadLinkAcq, accessWidth), address, valueResultTmp);
    append(OPCODE_FOR_CANONICAL_WIDTH(Branch, accessWidth), Arg::relCond(MacroAssembler::NotEqual), valueResultTmp, expectedValueTmp);
    reloopBlock->setSuccessors(B3::Air::FrequentedBlock(strongFailBlock), storeBlock);

    m_currentBlock = storeBlock;
    appendEffectful(OPCODE_FOR_WIDTH(StoreCondRel, accessWidth), newValueTmp, address, successBoolResultTmp);
    append(BranchTest32, Arg::resCond(MacroAssembler::Zero), successBoolResultTmp, successBoolResultTmp);
    storeBlock->setSuccessors(doneBlock, reloopBlock);

    m_currentBlock = strongFailBlock;
    {
        TypedTmp tmp = newTmp();
        appendEffectful(OPCODE_FOR_WIDTH(StoreCondRel, accessWidth), valueResultTmp, address, tmp);
        append(BranchTest32, Arg::resCond(MacroAssembler::Zero), tmp, tmp);
    }
    strongFailBlock->setSuccessors(B3::Air::FrequentedBlock(doneBlock), reloopBlock);

    m_currentBlock = doneBlock;
    return valueResultTmp;
}

auto AirIRGenerator64::truncSaturated(Ext1OpType op, ExpressionType arg, ExpressionType& result, Type returnType, Type operandType) -> PartialResult
{
    TypedTmp maxFloat;
    TypedTmp minFloat;
    TypedTmp signBitConstant;
    bool requiresMacroScratchRegisters = false;
    switch (op) {
    case Ext1OpType::I32TruncSatF32S:
        maxFloat = addConstant(Types::F32, bitwise_cast<uint32_t>(-static_cast<float>(std::numeric_limits<int32_t>::min())));
        minFloat = addConstant(Types::F32, bitwise_cast<uint32_t>(static_cast<float>(std::numeric_limits<int32_t>::min())));
        break;
    case Ext1OpType::I32TruncSatF32U:
        maxFloat = addConstant(Types::F32, bitwise_cast<uint32_t>(static_cast<float>(std::numeric_limits<int32_t>::min()) * static_cast<float>(-2.0)));
        minFloat = addConstant(Types::F32, bitwise_cast<uint32_t>(static_cast<float>(-1.0)));
        break;
    case Ext1OpType::I32TruncSatF64S:
        maxFloat = addConstant(Types::F64, bitwise_cast<uint64_t>(-static_cast<double>(std::numeric_limits<int32_t>::min())));
        minFloat = addConstant(Types::F64, bitwise_cast<uint64_t>(static_cast<double>(std::numeric_limits<int32_t>::min()) - 1.0));
        break;
    case Ext1OpType::I32TruncSatF64U:
        maxFloat = addConstant(Types::F64, bitwise_cast<uint64_t>(static_cast<double>(std::numeric_limits<int32_t>::min()) * -2.0));
        minFloat = addConstant(Types::F64, bitwise_cast<uint64_t>(-1.0));
        break;
    case Ext1OpType::I64TruncSatF32S:
        maxFloat = addConstant(Types::F32, bitwise_cast<uint32_t>(-static_cast<float>(std::numeric_limits<int64_t>::min())));
        minFloat = addConstant(Types::F32, bitwise_cast<uint32_t>(static_cast<float>(std::numeric_limits<int64_t>::min())));
        break;
    case Ext1OpType::I64TruncSatF32U:
        maxFloat = addConstant(Types::F32, bitwise_cast<uint32_t>(static_cast<float>(std::numeric_limits<int64_t>::min()) * static_cast<float>(-2.0)));
        minFloat = addConstant(Types::F32, bitwise_cast<uint32_t>(static_cast<float>(-1.0)));
        if (isX86())
            signBitConstant = addConstant(Types::F32, bitwise_cast<uint32_t>(static_cast<float>(std::numeric_limits<uint64_t>::max() - std::numeric_limits<int64_t>::max())));
        requiresMacroScratchRegisters = true;
        break;
    case Ext1OpType::I64TruncSatF64S:
        maxFloat = addConstant(Types::F64, bitwise_cast<uint64_t>(-static_cast<double>(std::numeric_limits<int64_t>::min())));
        minFloat = addConstant(Types::F64, bitwise_cast<uint64_t>(static_cast<double>(std::numeric_limits<int64_t>::min())));
        break;
    case Ext1OpType::I64TruncSatF64U:
        maxFloat = addConstant(Types::F64, bitwise_cast<uint64_t>(static_cast<double>(std::numeric_limits<int64_t>::min()) * -2.0));
        minFloat = addConstant(Types::F64, bitwise_cast<uint64_t>(-1.0));
        if (isX86())
            signBitConstant = addConstant(Types::F64, bitwise_cast<uint64_t>(static_cast<double>(std::numeric_limits<uint64_t>::max() - std::numeric_limits<int64_t>::max())));
        requiresMacroScratchRegisters = true;
        break;
    default:
        RELEASE_ASSERT_NOT_REACHED();
        break;
    }

    uint64_t minResult = 0;
    uint64_t maxResult = 0;
    switch (op) {
    case Ext1OpType::I32TruncSatF32S:
    case Ext1OpType::I32TruncSatF64S:
        maxResult = bitwise_cast<uint32_t>(INT32_MAX);
        minResult = bitwise_cast<uint32_t>(INT32_MIN);
        break;
    case Ext1OpType::I32TruncSatF32U:
    case Ext1OpType::I32TruncSatF64U:
        maxResult = bitwise_cast<uint32_t>(UINT32_MAX);
        minResult = bitwise_cast<uint32_t>(0U);
        break;
    case Ext1OpType::I64TruncSatF32S:
    case Ext1OpType::I64TruncSatF64S:
        maxResult = bitwise_cast<uint64_t>(INT64_MAX);
        minResult = bitwise_cast<uint64_t>(INT64_MIN);
        break;
    case Ext1OpType::I64TruncSatF32U:
    case Ext1OpType::I64TruncSatF64U:
        maxResult = bitwise_cast<uint64_t>(UINT64_MAX);
        minResult = bitwise_cast<uint64_t>(0ULL);
        break;
    default:
        RELEASE_ASSERT_NOT_REACHED();
        break;
    }

    result = tmpForType(returnType);

    BasicBlock* minCase = m_code.addBlock();
    BasicBlock* maxCheckCase = m_code.addBlock();
    BasicBlock* maxCase = m_code.addBlock();
    BasicBlock* inBoundsCase = m_code.addBlock();
    BasicBlock* continuation = m_code.addBlock();

    auto branchOp = operandType == Types::F32 ? BranchFloat : BranchDouble;
    append(m_currentBlock, branchOp, Arg::doubleCond(MacroAssembler::DoubleLessThanOrEqualOrUnordered), arg, minFloat);
    m_currentBlock->setSuccessors(minCase, maxCheckCase);

    append(maxCheckCase, branchOp, Arg::doubleCond(MacroAssembler::DoubleGreaterThanOrEqualOrUnordered), arg, maxFloat);
    maxCheckCase->setSuccessors(maxCase, inBoundsCase);

    if (!minResult) {
        append(minCase, Move, Arg::bigImm(minResult), result);
        append(minCase, Jump);
        minCase->setSuccessors(continuation);
    } else {
        BasicBlock* minMaterializeCase = m_code.addBlock();
        BasicBlock* nanCase = m_code.addBlock();
        append(minCase, branchOp, Arg::doubleCond(MacroAssembler::DoubleEqualAndOrdered), arg, arg);
        minCase->setSuccessors(minMaterializeCase, nanCase);

        append(minMaterializeCase, Move, Arg::bigImm(minResult), result);
        append(minMaterializeCase, Jump);
        minMaterializeCase->setSuccessors(continuation);

        append(nanCase, Move, Arg::bigImm(0), result);
        append(nanCase, Jump);
        nanCase->setSuccessors(continuation);
    }

    append(maxCase, Move, Arg::bigImm(maxResult), result);
    append(maxCase, Jump);
    maxCase->setSuccessors(continuation);

    Vector<ConstrainedTmp, 2> args;
    auto* patchpoint = addPatchpoint(toB3Type(returnType));
    patchpoint->effects = B3::Effects::none();
    args.append(arg);
    if (requiresMacroScratchRegisters) {
        patchpoint->clobber(RegisterSet::macroScratchRegisters());
        if (isX86()) {
            args.append(signBitConstant);
            patchpoint->numFPScratchRegisters = 1;
        }
    }

    patchpoint->effects = B3::Effects::none();
    patchpoint->setGenerator([=] (CCallHelpers& jit, const B3::StackmapGenerationParams& params) {
        switch (op) {
        case Ext1OpType::I32TruncSatF32S:
            jit.truncateFloatToInt32(params[1].fpr(), params[0].gpr());
            break;
        case Ext1OpType::I32TruncSatF32U:
            jit.truncateFloatToUint32(params[1].fpr(), params[0].gpr());
            break;
        case Ext1OpType::I32TruncSatF64S:
            jit.truncateDoubleToInt32(params[1].fpr(), params[0].gpr());
            break;
        case Ext1OpType::I32TruncSatF64U:
            jit.truncateDoubleToUint32(params[1].fpr(), params[0].gpr());
            break;
        case Ext1OpType::I64TruncSatF32S:
            jit.truncateFloatToInt64(params[1].fpr(), params[0].gpr());
            break;
        case Ext1OpType::I64TruncSatF32U: {
            AllowMacroScratchRegisterUsage allowScratch(jit);
            ASSERT(requiresMacroScratchRegisters);
            FPRReg scratch = InvalidFPRReg;
            FPRReg constant = InvalidFPRReg;
            if (isX86()) {
                scratch = params.fpScratch(0);
                constant = params[2].fpr();
            }
            jit.truncateFloatToUint64(params[1].fpr(), params[0].gpr(), scratch, constant);
            break;
        }
        case Ext1OpType::I64TruncSatF64S:
            jit.truncateDoubleToInt64(params[1].fpr(), params[0].gpr());
            break;
        case Ext1OpType::I64TruncSatF64U: {
            AllowMacroScratchRegisterUsage allowScratch(jit);
            ASSERT(requiresMacroScratchRegisters);
            FPRReg scratch = InvalidFPRReg;
            FPRReg constant = InvalidFPRReg;
            if (isX86()) {
                scratch = params.fpScratch(0);
                constant = params[2].fpr();
            }
            jit.truncateDoubleToUint64(params[1].fpr(), params[0].gpr(), scratch, constant);
            break;
        }
        default:
            RELEASE_ASSERT_NOT_REACHED();
            break;
        }
    });

    emitPatchpoint(inBoundsCase, patchpoint, Vector<TypedTmp, 8> { result }, WTFMove(args));
    append(inBoundsCase, Jump);
    inBoundsCase->setSuccessors(continuation);

    m_currentBlock = continuation;

    return { };
}

auto AirIRGenerator64::addI31New(ExpressionType value, ExpressionType& result) -> PartialResult
{
    auto tmp1 = g32();
    result = gRef(Type { TypeKind::Ref, Nullable::No, static_cast<TypeIndex>(TypeKind::I31ref) });

    append(Move, Arg::bigImm(0x7fffffff), tmp1);
    append(And32, tmp1, value, tmp1);
    append(Move, Arg::bigImm(JSValue::NumberTag), result);
    append(Or64, result, tmp1, result);

    return { };
}

auto AirIRGenerator64::addI31GetS(ExpressionType ref, ExpressionType& result) -> PartialResult
{
    // Trap on null reference.
    auto tmpForNull = g64();
    append(Move, Arg::bigImm(JSValue::encode(jsNull())), tmpForNull);
    emitCheck([&] {
        return Inst(Branch64, nullptr, Arg::relCond(MacroAssembler::Equal), ref, tmpForNull);
    }, [=, this] (CCallHelpers& jit, const B3::StackmapGenerationParams&) {
        this->emitThrowException(jit, ExceptionType::NullI31Get);
    });

    auto tmpForShift = g32();
    result = g32();

    append(Move, Arg::imm(1), tmpForShift);
    append(Move32, ref, result);
    addShift(Types::I32, Lshift32, result, tmpForShift, result);
    addShift(Types::I32, Rshift32, result, tmpForShift, result);

    return { };
}

auto AirIRGenerator64::addI31GetU(ExpressionType ref, ExpressionType& result) -> PartialResult
{
    // Trap on null reference.
    auto tmpForNull = g64();
    append(Move, Arg::bigImm(JSValue::encode(jsNull())), tmpForNull);
    emitCheck([&] {
        return Inst(Branch64, nullptr, Arg::relCond(MacroAssembler::Equal), ref, tmpForNull);
    }, [=, this] (CCallHelpers& jit, const B3::StackmapGenerationParams&) {
        this->emitThrowException(jit, ExceptionType::NullI31Get);
    });

    result = g32();
    append(Move32, ref, result);

    return { };
}

auto AirIRGenerator64::addSelect(ExpressionType condition, ExpressionType nonZero, ExpressionType zero, ExpressionType& result) -> PartialResult
{
    ASSERT(nonZero.type() == zero.type());
    result = tmpForType(nonZero.type());
    append(moveOpForValueType(nonZero.type()), nonZero, result);

    BasicBlock* isZero = m_code.addBlock();
    BasicBlock* continuation = m_code.addBlock();

    append(BranchTest32, Arg::resCond(MacroAssembler::Zero), condition, condition);
    m_currentBlock->setSuccessors(isZero, continuation);

    append(isZero, moveOpForValueType(zero.type()), zero, result);
    append(isZero, Jump);
    isZero->setSuccessors(continuation);

    m_currentBlock = continuation;

    return { };
}

Tmp AirIRGenerator64::emitCatchImpl(CatchKind kind, ControlType& data, unsigned exceptionIndex)
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
        size_t offset = sizeof(uint64_t) * indexInBuffer;
        ++indexInBuffer;
        Tmp bufferPtr = Tmp(GPRInfo::argumentGPR0);
        emitLoad(bufferPtr, offset, result);
    };
    forEachLiveValue([&] (TypedTmp tmp) {
        // We set our current ControlEntry's exception below after the patchpoint, it's
        // not in the incoming buffer of live values.
        auto toIgnore = data.exception();
        if (tmp.tmp() != toIgnore.tmp())
            loadFromScratchBuffer(tmp);
    });

    B3::PatchpointValue* patch = addPatchpoint(m_proc.addTuple({ B3::pointerType(), B3::pointerType() }));
    patch->effects.exitsSideways = true;
    patch->clobber(RegisterSet::macroScratchRegisters());
    RegisterSet clobberLate = RegisterSet::volatileRegistersForJSCall();
    clobberLate.add(GPRInfo::argumentGPR0);
    patch->clobberLate(clobberLate);
    patch->resultConstraints.append(B3::ValueRep::reg(GPRInfo::returnValueGPR));
    patch->resultConstraints.append(B3::ValueRep::reg(GPRInfo::returnValueGPR2));
    patch->setGenerator([=] (CCallHelpers& jit, const B3::StackmapGenerationParams& params) {
        AllowMacroScratchRegisterUsage allowScratch(jit);
        jit.move(params[2].gpr(), GPRInfo::argumentGPR0);
        CCallHelpers::Call call = jit.call(OperationPtrTag);
        jit.addLinkTask([call] (LinkBuffer& linkBuffer) {
            linkBuffer.link<OperationPtrTag>(call, operationWasmRetrieveAndClearExceptionIfCatchable);
        });
    });

    Tmp exception = Tmp(GPRInfo::returnValueGPR);
    Tmp buffer = Tmp(GPRInfo::returnValueGPR2);
    emitPatchpoint(m_currentBlock, patch, Vector<Tmp, 8>::from(exception, buffer), Vector<ConstrainedTmp, 1>::from(instanceValue()));
    append(Move, exception, data.exception());

    return buffer;
}

auto AirIRGenerator64::addReturn(const ControlData& data, const Stack& returnValues) -> PartialResult
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
        if (data.signature()->as<FunctionSignature>()->returnType(i).isI32())
            append(Move32, tmp, tmp);
        returnConstraints.append(ConstrainedTmp(tmp, wasmCallInfo.results[i]));
    }

    emitPatchpoint(m_currentBlock, patch, ResultList { }, WTFMove(returnConstraints));
    return { };
}

auto AirIRGenerator64::addThrow(unsigned exceptionIndex, Vector<ExpressionType>& args, Stack&) -> PartialResult
{
    B3::PatchpointValue* patch = addPatchpoint(B3::Void);
    patch->effects.terminal = true;
    patch->clobber(RegisterSet::volatileRegistersForJSCall());

    Vector<ConstrainedTmp, 8> patchArgs;
    patchArgs.append(ConstrainedTmp(instanceValue(), B3::ValueRep::reg(GPRInfo::argumentGPR0)));
    patchArgs.append(ConstrainedTmp(Tmp(GPRInfo::callFrameRegister), B3::ValueRep::reg(GPRInfo::argumentGPR1)));
    for (unsigned i = 0; i < args.size(); ++i)
        patchArgs.append(ConstrainedTmp(args[i], B3::ValueRep::stackArgument(i * sizeof(EncodedJSValue))));

    PatchpointExceptionHandle handle = preparePatchpointForExceptions(patch, patchArgs);

    patch->setGenerator([this, exceptionIndex, handle] (CCallHelpers& jit, const B3::StackmapGenerationParams& params) {
        AllowMacroScratchRegisterUsage allowScratch(jit);
        handle.generate(jit, params, this);
        emitThrowImpl(jit, exceptionIndex); 
    });

    emitPatchpoint(m_currentBlock, patch, Tmp(), WTFMove(patchArgs));

    return { };
}

auto AirIRGenerator64::addRethrow(unsigned, ControlType& data) -> PartialResult
{
    B3::PatchpointValue* patch = addPatchpoint(B3::Void);
    patch->clobber(RegisterSet::volatileRegistersForJSCall());
    patch->effects.terminal = true;

    Vector<ConstrainedTmp, 3> patchArgs;
    patchArgs.append(ConstrainedTmp(instanceValue(), B3::ValueRep::reg(GPRInfo::argumentGPR0)));
    patchArgs.append(ConstrainedTmp(Tmp(GPRInfo::callFrameRegister), B3::ValueRep::reg(GPRInfo::argumentGPR1)));
    patchArgs.append(ConstrainedTmp(data.exception(), B3::ValueRep::reg(GPRInfo::argumentGPR2)));

    PatchpointExceptionHandle handle = preparePatchpointForExceptions(patch, patchArgs);
    patch->setGenerator([this, handle] (CCallHelpers& jit, const B3::StackmapGenerationParams& params) {
        AllowMacroScratchRegisterUsage allowScratch(jit);
        handle.generate(jit, params, this);
        emitRethrowImpl(jit);
    });

    emitPatchpoint(m_currentBlock, patch, Tmp(), WTFMove(patchArgs));

    return { };
}

std::pair<B3::PatchpointValue*, PatchpointExceptionHandle> AirIRGenerator64::emitCallPatchpoint(BasicBlock* block, const TypeDefinition& signature, const ResultList& results, const Vector<TypedTmp>& args, Vector<ConstrainedTmp> patchArgs)
{
    auto* patchpoint = addPatchpoint(toB3ResultType(&signature));
    patchpoint->effects.writesPinned = true;
    patchpoint->effects.readsPinned = true;
    patchpoint->clobberEarly(RegisterSet::macroScratchRegisters());
    patchpoint->clobberLate(RegisterSet::volatileRegistersForJSCall());

    CallInformation locations = wasmCallingConvention().callInformationFor(signature);
    m_code.requestCallArgAreaSizeInBytes(WTF::roundUpToMultipleOf(stackAlignmentBytes(), locations.headerAndArgumentStackSizeInBytes));

    size_t offset = patchArgs.size();
    Checked<size_t> newSize = checkedSum<size_t>(patchArgs.size(), args.size());
    RELEASE_ASSERT(!newSize.hasOverflowed());

    patchArgs.grow(newSize);
    for (unsigned i = 0; i < args.size(); ++i)
        patchArgs[i + offset] = ConstrainedTmp(args[i], locations.params[i]);

    if (patchpoint->type() != B3::Void) {
        Vector<B3::ValueRep, 1> resultConstraints;
        for (auto valueLocation : locations.results)
            resultConstraints.append(B3::ValueRep(valueLocation));
        patchpoint->resultConstraints = WTFMove(resultConstraints);
    }
    PatchpointExceptionHandle exceptionHandle = preparePatchpointForExceptions(patchpoint, patchArgs);
    emitPatchpoint(block, patchpoint, results, WTFMove(patchArgs));
    return { patchpoint, exceptionHandle };
}

template <typename IntType>
void AirIRGenerator64::emitChecksForModOrDiv(bool isSignedDiv, ExpressionType left, ExpressionType right)
{
    static_assert(sizeof(IntType) == 4 || sizeof(IntType) == 8);

    emitCheck([&] {
        return Inst(sizeof(IntType) == 4 ? BranchTest32 : BranchTest64, nullptr, Arg::resCond(MacroAssembler::Zero), right, right);
    }, [=, this] (CCallHelpers& jit, const B3::StackmapGenerationParams&) {
        this->emitThrowException(jit, ExceptionType::DivisionByZero);
    });

    if (isSignedDiv) {
        ASSERT(std::is_signed<IntType>::value);
        IntType min = std::numeric_limits<IntType>::min();

        // FIXME: Better isel for compare with imms here.
        // https://bugs.webkit.org/show_bug.cgi?id=193999
        auto minTmp = sizeof(IntType) == 4 ? g32() : g64();
        auto negOne = sizeof(IntType) == 4 ? g32() : g64();

        B3::Air::Opcode op = sizeof(IntType) == 4 ? Compare32 : Compare64;
        append(Move, Arg::bigImm(static_cast<uint64_t>(min)), minTmp);
        append(op, Arg::relCond(MacroAssembler::Equal), left, minTmp, minTmp);

        append(Move, Arg::isValidImmForm(-1) ? Arg::imm(-1) : Arg::bigImm(-1) , negOne);
        append(op, Arg::relCond(MacroAssembler::Equal), right, negOne, negOne);

        emitCheck([&] {
            return Inst(BranchTest32, nullptr, Arg::resCond(MacroAssembler::NonZero), minTmp, negOne);
        },
        [=, this] (CCallHelpers& jit, const B3::StackmapGenerationParams&) {
            this->emitThrowException(jit, ExceptionType::IntegerOverflow);
        });
    }
}

template <typename IntType>
void AirIRGenerator64::emitModOrDiv(bool isDiv, ExpressionType lhs, ExpressionType rhs, ExpressionType& result)
{
    static_assert(sizeof(IntType) == 4 || sizeof(IntType) == 8);

    result = sizeof(IntType) == 4 ? g32() : g64();

    bool isSigned = std::is_signed<IntType>::value;

    if (isARM64()) {
        B3::Air::Opcode div;
        switch (sizeof(IntType)) {
        case 4:
            div = isSigned ? Div32 : UDiv32;
            break;
        case 8:
            div = isSigned ? Div64 : UDiv64;
            break;
        }

        append(div, lhs, rhs, result);

        if (!isDiv) {
            append(sizeof(IntType) == 4 ? Mul32 : Mul64, result, rhs, result);
            append(sizeof(IntType) == 4 ? Sub32 : Sub64, lhs, result, result);
        }

        return;
    }

#if CPU(X86_64)
    Tmp eax(X86Registers::eax);
    Tmp edx(X86Registers::edx);

    if (isSigned) {
        B3::Air::Opcode convertToDoubleWord;
        B3::Air::Opcode div;
        switch (sizeof(IntType)) {
        case 4:
            convertToDoubleWord = X86ConvertToDoubleWord32;
            div = X86Div32;
            break;
        case 8:
            convertToDoubleWord = X86ConvertToQuadWord64;
            div = X86Div64;
            break;
        default:
            RELEASE_ASSERT_NOT_REACHED();
        }

        // We implement "res = Div<Chill>/Mod<Chill>(num, den)" as follows:
        //
        //     if (den + 1 <=_unsigned 1) {
        //         if (!den) {
        //             res = 0;
        //             goto done;
        //         }
        //         if (num == -2147483648) {
        //             res = isDiv ? num : 0;
        //             goto done;
        //         }
        //     }
        //     res = num (/ or %) dev;
        // done:

        BasicBlock* denIsGood = m_code.addBlock();
        BasicBlock* denMayBeBad = m_code.addBlock();
        BasicBlock* denNotZero = m_code.addBlock();
        BasicBlock* continuation = m_code.addBlock();

        auto temp = sizeof(IntType) == 4 ? g32() : g64();
        auto one = addConstant(sizeof(IntType) == 4 ? Types::I32 : Types::I64, 1);

        append(sizeof(IntType) == 4 ? Add32 : Add64, rhs, one, temp);
        append(sizeof(IntType) == 4 ? Branch32 : Branch64, Arg::relCond(MacroAssembler::Above), temp, one);
        m_currentBlock->setSuccessors(denIsGood, denMayBeBad);

        append(denMayBeBad, Xor64, result, result);
        append(denMayBeBad, sizeof(IntType) == 4 ? BranchTest32 : BranchTest64, Arg::resCond(MacroAssembler::Zero), rhs, rhs);
        denMayBeBad->setSuccessors(continuation, denNotZero);

        auto min = addConstant(denNotZero, sizeof(IntType) == 4 ? Types::I32 : Types::I64, std::numeric_limits<IntType>::min());
        if (isDiv)
            append(denNotZero, sizeof(IntType) == 4 ? Move32 : Move, min, result);
        else {
            // Result is zero, as set above...
        }
        append(denNotZero, sizeof(IntType) == 4 ? Branch32 : Branch64, Arg::relCond(MacroAssembler::Equal), lhs, min);
        denNotZero->setSuccessors(continuation, denIsGood);

        auto divResult = isDiv ? eax : edx;
        append(denIsGood, Move, lhs, eax);
        append(denIsGood, convertToDoubleWord, eax, edx);
        append(denIsGood, div, eax, edx, rhs);
        append(denIsGood, sizeof(IntType) == 4 ? Move32 : Move, divResult, result);
        append(denIsGood, Jump);
        denIsGood->setSuccessors(continuation);

        m_currentBlock = continuation;
        return;
    }

    B3::Air::Opcode div = sizeof(IntType) == 4 ? X86UDiv32 : X86UDiv64;

    Tmp divResult = isDiv ? eax : edx;

    append(Move, lhs, eax);
    append(Xor64, edx, edx);
    append(div, eax, edx, rhs);
    append(sizeof(IntType) == 4 ? Move32 : Move, divResult, result);
#else
    RELEASE_ASSERT_NOT_REACHED();
#endif
}

auto AirIRGenerator64::addShift(Type type, B3::Air::Opcode op, ExpressionType value, ExpressionType shift, ExpressionType& result) -> PartialResult
{
    ASSERT(type.isI64() || type.isI32());
    result = tmpForType(type);

    if (isValidForm(op, Arg::Tmp, Arg::Tmp, Arg::Tmp)) {
        append(op, value, shift, result);
        return { };
    }
    
#if CPU(X86_64)
    Tmp ecx = Tmp(X86Registers::ecx);
    append(Move, value, result);
    append(Move, shift, ecx);
    append(op, ecx, result);
#else
    RELEASE_ASSERT_NOT_REACHED();
#endif
    return { };
}

auto AirIRGenerator64::addIntegerSub(B3::Air::Opcode op, ExpressionType lhs, ExpressionType rhs, ExpressionType& result) -> PartialResult
{
    ASSERT(op == Sub32 || op == Sub64);

    result = op == Sub32 ? g32() : g64();

    if (isValidForm(op, Arg::Tmp, Arg::Tmp, Arg::Tmp)) {
        append(op, lhs, rhs, result);
        return { };
    }

    RELEASE_ASSERT(isX86());
    // Sub a, b
    // means
    // b = b Sub a
    append(Move, lhs, result);
    append(op, rhs, result);
    return { };
}

auto AirIRGenerator64::addFloatingPointAbs(B3::Air::Opcode op, ExpressionType value, ExpressionType& result) -> PartialResult
{
    RELEASE_ASSERT(op == AbsFloat || op == AbsDouble);

    result = op == AbsFloat ? f32() : f64();

    if (isValidForm(op, Arg::Tmp, Arg::Tmp)) {
        append(op, value, result);
        return { };
    }

    RELEASE_ASSERT(isX86());

    if (op == AbsFloat) {
        auto constant = g32();
        append(Move, Arg::imm(static_cast<uint32_t>(~(1ull << 31))), constant);
        append(Move32ToFloat, constant, result);
        append(AndFloat, value, result);
    } else {
        auto constant = g64();
        append(Move, Arg::bigImm(~(1ull << 63)), constant);
        append(Move64ToDouble, constant, result);
        append(AndDouble, value, result);
    }
    return { };
}

auto AirIRGenerator64::addFloatingPointBinOp(Type type, B3::Air::Opcode op, ExpressionType lhs, ExpressionType rhs, ExpressionType& result) -> PartialResult
{
    ASSERT(type.isF32() || type.isF64());
    result = tmpForType(type);

    if (isValidForm(op, Arg::Tmp, Arg::Tmp, Arg::Tmp)) {
        append(op, lhs, rhs, result);
        return { };
    }

    RELEASE_ASSERT(isX86());

    // Op a, b
    // means
    // b = b Op a
    append(moveOpForValueType(type), lhs, result);
    append(op, rhs, result);
    return { };
}

auto AirIRGenerator64::addFloatingPointMinOrMax(Type floatType, MinOrMax minOrMax, ExpressionType arg0, ExpressionType arg1, ExpressionType& result) -> PartialResult
{
    ASSERT(floatType.isF32() || floatType.isF64());
    result = tmpForType(floatType);

    if (isARM64()) {
        if (floatType.isF32())
            append(m_currentBlock, minOrMax == MinOrMax::Max ? FloatMax : FloatMin, arg0, arg1, result);
        else
            append(m_currentBlock, minOrMax == MinOrMax::Max ? DoubleMax : DoubleMin, arg0, arg1, result);
        return { };
    }

    BasicBlock* isEqual = m_code.addBlock();
    BasicBlock* notEqual = m_code.addBlock();
    BasicBlock* isLessThan = m_code.addBlock();
    BasicBlock* notLessThan = m_code.addBlock();
    BasicBlock* isGreaterThan = m_code.addBlock();
    BasicBlock* isNaN = m_code.addBlock();
    BasicBlock* continuation = m_code.addBlock();

    auto branchOp = floatType.isF32() ? BranchFloat : BranchDouble;
    append(m_currentBlock, branchOp, Arg::doubleCond(MacroAssembler::DoubleEqualAndOrdered), arg0, arg1);
    m_currentBlock->setSuccessors(isEqual, notEqual);

    append(notEqual, branchOp, Arg::doubleCond(MacroAssembler::DoubleLessThanAndOrdered), arg0, arg1);
    notEqual->setSuccessors(isLessThan, notLessThan);

    append(notLessThan, branchOp, Arg::doubleCond(MacroAssembler::DoubleGreaterThanAndOrdered), arg0, arg1);
    notLessThan->setSuccessors(isGreaterThan, isNaN);

    auto andOp = floatType.isF32() ? AndFloat : AndDouble;
    auto orOp = floatType.isF32() ? OrFloat : OrDouble;
    append(isEqual, minOrMax == MinOrMax::Max ? andOp : orOp, arg0, arg1, result);
    append(isEqual, Jump);
    isEqual->setSuccessors(continuation);

    auto isLessThanResult = minOrMax == MinOrMax::Max ? arg1 : arg0;
    append(isLessThan, moveOpForValueType(floatType), isLessThanResult, result);
    append(isLessThan, Jump);
    isLessThan->setSuccessors(continuation);

    auto isGreaterThanResult = minOrMax == MinOrMax::Max ? arg0 : arg1;
    append(isGreaterThan, moveOpForValueType(floatType), isGreaterThanResult, result);
    append(isGreaterThan, Jump);
    isGreaterThan->setSuccessors(continuation);

    auto addOp = floatType.isF32() ? AddFloat : AddDouble;
    append(isNaN, addOp, arg0, arg1, result);
    append(isNaN, Jump);
    isNaN->setSuccessors(continuation);

    m_currentBlock = continuation;

    return { };
}

template <size_t inlineCapacity>
PatchpointExceptionHandle AirIRGenerator64::preparePatchpointForExceptions(B3::PatchpointValue* patch, Vector<ConstrainedTmp, inlineCapacity>& args)
{
    ++m_callSiteIndex;
    if (!m_tryCatchDepth)
        return { m_hasExceptionHandlers };

    unsigned numLiveValues = 0;
    forEachLiveValue([&] (Tmp tmp) {
        ++numLiveValues;
        args.append(ConstrainedTmp(tmp, B3::ValueRep::LateColdAny));
    });

    patch->effects.exitsSideways = true;

    return { m_hasExceptionHandlers, m_callSiteIndex, numLiveValues };
}

Expected<std::unique_ptr<InternalFunction>, String> parseAndCompileAir(CompilationContext& compilationContext, const FunctionData& function, const TypeDefinition& signature, Vector<UnlinkedWasmToWasmCall>& unlinkedWasmToWasmCalls, const ModuleInformation& info, MemoryMode mode, uint32_t functionIndex, std::optional<bool> hasExceptionHandlers, TierUpCount* tierUp)
{
    return parseAndCompileAirImpl<AirIRGenerator64>(compilationContext, function, signature, unlinkedWasmToWasmCalls, info, mode, functionIndex, hasExceptionHandlers, tierUp);
}

} } // namespace JSC::Wasm

#endif // USE(JSVALUE64)
