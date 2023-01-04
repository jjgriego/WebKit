/*
 * Copyright (C) 2013-2022 Apple Inc. All rights reserved.
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

#include <functional>
#include <wtf/ForbidHeapAllocation.h>
#include <wtf/Vector.h>

namespace JSC {

class CodeBlock;
class JSGlobalObject;
class VM;

struct EntryFrame;

using EntryTrampolineFn = EncodedJSValue (*)(void*, VM*, EntryFrame*);

class VMEntryScope {
    WTF_MAKE_NONCOPYABLE(VMEntryScope);
    WTF_FORBID_HEAP_ALLOCATION;
public:
    JS_EXPORT_PRIVATE VMEntryScope(JSGlobalObject*);
    JS_EXPORT_PRIVATE ~VMEntryScope();

    JSGlobalObject* globalObject() const { return m_globalObject; }
    CodeBlock* codeBlock() const { return m_codeBlock; }

    void addDidPopListener(Function<void ()>&&);

    void initializeCall(CodeBlock*, unsigned incomingArgCount);
    void finalizeCall(JSObject*, JSValue thisValue, JSValue* incomingArgs = nullptr);
    void updateCodeBlock(CodeBlock*);

    void clearArguments();
    void appendArgument(JSValue);
    bool hasAppendedArguments() const { return m_nextArgToAppend; }
    unsigned numberOfAppendedArguments() const;

    bool isSafeToRecurseSoft(VM&) const;

    // We return the stackBufferSize and let the caller do the alloca because the
    // stackBuffer must be allocated in the caller's frame.
    unsigned stackBufferSize() const { return m_stackBufferSize; }
    void setStackBuffer(void* stackBuffer) { m_stackBuffer = stackBuffer; }

    EntryFrame* vmEntryFrame() const { return m_vmEntryFrame; }

    __attribute__((noinline)) void initializeBuffer();
    __attribute__((noinline)) EncodedJSValue go(EntryTrampolineFn, VM&, void*);

#if ENABLE(C_LOOP)
    inline void* currentCLoopStackPointer();
    inline void allocateEntryFrameOnCLoopStack();
#endif

private:
    JSValue* firstArgPosition() const;

    JSGlobalObject* m_globalObject;
    Vector<Function<void ()>> m_didPopListeners;
    EntryFrame* m_prevTopEntryFrame;
    CallFrame* m_prevTopCallFrame;

    // Initialized in by client for call.
    CodeBlock* m_codeBlock { nullptr };
    unsigned m_incomingArgCount { 0 };

    JSObject* m_callee;
    JSValue m_thisValue;
    JSValue* m_incomingArgs;

    // Computed for call after the above has been initialized.
    void* m_stackBuffer { nullptr };
    EntryFrame* m_vmEntryFrame { nullptr };
    JSValue* m_nextArgToAppend { nullptr };
    unsigned m_arityCheckedArgsCountIncludingThis { 0 };
    unsigned m_stackBufferSize { 0 };

    friend struct EntryFrame;
};

#if ENABLE(C_LOOP)

#define CURRENT_STACK_POINTER_FOR_VM_ENTRY_STACK_CHECK(entryScope) \
    entryScope.currentCLoopStackPointer()

#define ALLOCATE_ENTRY_FRAME_ON_STACK(entryScope) \
    entryScope.allocateEntryFrameOnCLoopStack()

#else // not ENABLE(C_LOOP)

#define CURRENT_STACK_POINTER_FOR_VM_ENTRY_STACK_CHECK(entryScope) \
    currentStackPointer()

// This has to be a macro (and not an inline function) because we need to do
// alloca in the caller of vmEntryToJavaScript (and friends) in order to make
// room on the stack for the EntryFrame. vmEntryToJavaScript (and friends)
// will pop off the stack memory allocated by alloca on returning.
#define ALLOCATE_ENTRY_FRAME_ON_STACK(entryScope) \
    entryScope.setStackBuffer(alloca(entryScope.stackBufferSize()))

#endif // ENABLE(C_LOOP)

} // namespace JSC
