/*
 * Copyright (C) 2022 Apple Inc. All rights reserved.
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

#include "CLoopStackInlines.h"
#include "CallFrame.h"
#include "EntryFrame.h"
#include "VMInlines.h"
#include "VMEntryScope.h"
#include <wtf/StackPointer.h>

namespace JSC {

inline JSValue* VMEntryScope::firstArgPosition() const
{
    ASSERT(m_stackBuffer);
    auto* callFrame = reinterpret_cast<CallFrame*>(m_stackBuffer);
    return callFrame->addressOfArgumentsStart();
}

inline void VMEntryScope::clearArguments()
{
    m_nextArgToAppend = firstArgPosition();
}

inline void VMEntryScope::appendArgument(JSValue value)
{
    *m_nextArgToAppend++ = value;
}

inline unsigned VMEntryScope::numberOfAppendedArguments() const
{
    return m_nextArgToAppend - firstArgPosition();
}

inline bool VMEntryScope::isSafeToRecurseSoft(VM& vm) const
{
#if ENABLE(C_LOOP)
    // Make sure that there is enough room on the CLoopStack.
    CLoopStack& cloopStack = vm.interpreter.cloopStack();
    auto* newTopOfCLoopStack = bitwise_cast<Register*>(cloopStack.currentStackPointer<uint8_t*>() - m_stackBufferSize);
    if (!cloopStack.ensureCapacityFor(newTopOfCLoopStack))
        return false;

    // Make sure that there is enough room on the native stack.
    void* newTopOfStack = currentStackPointer();
#else
    void* newTopOfStack = currentStackPointer<uint8_t*>() - m_stackBufferSize;
#endif
    return vm.isSafeToRecurseSoft(newTopOfStack);
}

#if ENABLE(C_LOOP)
inline void* VMEntryScope::currentCLoopStackPointer()
{
    VM& vm = globalObject()->vm();
    CLoopStack& cloopStack = vm.interpreter.cloopStack();
    return cloopStack.currentStackPointer();
}

inline void VMEntryScope::allocateEntryFrameOnCLoopStack()
{
    VM& vm = globalObject()->vm();
    CLoopStack& cloopStack = vm.interpreter.cloopStack();
    void* newTopOfCLoopStack = cloopStack.currentStackPointer<uint8_t*>() - m_stackBufferSize;
    cloopStack.setCurrentStackPointer(newTopOfCLoopStack);
    setStackBuffer(newTopOfCLoopStack);
}
#endif

inline void VMEntryScope::updateCodeBlock(CodeBlock* codeBlock)
{
    auto* callFrame = reinterpret_cast<CallFrame*>(m_stackBuffer);
    callFrame->setCodeBlock(codeBlock);
}


} // namespace JSC
