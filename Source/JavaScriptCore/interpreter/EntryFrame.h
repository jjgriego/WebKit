/*
 * Copyright (C) 2018 Apple Inc. All rights reserved.
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

#pragma once

#include "GPRInfo.h"
#include "StackAlignment.h"
#include "VMEntryScope.h"

namespace JSC {

class CallFrame;
class JSGlobalObject;
class JSObject;
class VM;

struct EntryFrame {
    CallFrame* prevTopCallFrame() const { return entryScope->m_prevTopCallFrame; }
    SUPPRESS_ASAN CallFrame* unsafePrevTopCallFrame() const { return entryScope->m_prevTopCallFrame; }

    EntryFrame* prevTopEntryFrame() const { return entryScope->m_prevTopEntryFrame; }
    SUPPRESS_ASAN EntryFrame* unsafePrevTopEntryFrame() const { return entryScope->m_prevTopEntryFrame; }

#if ENABLE(ASSEMBLER)
#if NUMBER_OF_CALLEE_SAVES_REGISTERS > 0
    static ptrdiff_t calleeSaveRegistersBufferOffset()
    {
        return OBJECT_OFFSETOF(EntryFrame, calleeSaveRegistersBuffer);
    }
#endif
#endif

    // This record is stored in a vmEntryTo{JavaScript,Native} allocated frame.
    CallerFrameAndPC callerFrameAndPC;
    VMEntryScope* entryScope;
    JSGlobalObject* globalObject;

#if ENABLE(ASSEMBLER)
#if NUMBER_OF_CALLEE_SAVES_REGISTERS > 0

#if 1 || ASSERT_ENABLED // mlam TEST
    CPURegister calleeSaveRegistersValidationBuffer[NUMBER_OF_CALLEE_SAVES_REGISTERS];
#endif
    CPURegister calleeSaveRegistersBuffer[NUMBER_OF_CALLEE_SAVES_REGISTERS];

#endif // NUMBER_OF_CALLEE_SAVES_REGISTERS > 0
#endif // ENABLE(ASSEMBLER)

#define VM_ENTRY_CALLEE_SAVES_COUNT vmEntryCalleeSavesCount
#if CPU(ARM) && !CPU(ARM64)
    static constexpr unsigned vmEntryCalleeSavesCount = 5 + 2 * 1; // 5 32-bit GPRs + 1 64-bit FPR
#elif CPU(MIPS)
    static constexpr unsigned vmEntryCalleeSavesCount = 3;
#elif CPU(X86)
    static constexpr unsigned vmEntryCalleeSavesCount = 3;
#else
    static constexpr unsigned vmEntryCalleeSavesCount = 0;
#undef VM_ENTRY_CALLEE_SAVES_COUNT
#endif

#ifdef VM_ENTRY_CALLEE_SAVES_COUNT
    // See preserveCalleeSavesInEntryFrame() and restoreCalleeSavesFromEntryFrame().
    CPURegister vmEntryCalleeSavesBuffer[vmEntryCalleeSavesCount];
#endif

#if CPU(X86) || CPU(X86_64)
    alignas(stackAlignmentBytes()) CallerFrameAndPC copyOfReturnPCForReturning;
#endif
};

static constexpr intptr_t kVMEntryFrameAlignedSize = WTF::roundUpToMultipleOf<stackAlignmentBytes()>(sizeof(EntryFrame));

} // namespace JSC
