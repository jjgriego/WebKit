/*
 * Copyright (C) 2009-2018 Apple Inc. All rights reserved.
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

#include "JSCJSValue.h"
#include "VMEntryScope.h"

namespace JSC {

class JSFunction;
class JSGlobalObject;

struct EntryFrame;

    class CachedCall {
        WTF_MAKE_NONCOPYABLE(CachedCall);
        WTF_FORBID_HEAP_ALLOCATION;
    public:
        CachedCall(JSGlobalObject*, JSFunction*, unsigned argumentCount);

        ALWAYS_INLINE VMEntryScope& entryScope() { return m_entryScope; }

        ALWAYS_INLINE void finalizeCall(JSValue thisValue)
        {
            m_entryScope.finalizeCall(m_function, thisValue);
        }

        template<typename Functor>
        ALWAYS_INLINE JSValue call(Functor initalizeArgs);

        ALWAYS_INLINE void clearArguments() { m_entryScope.clearArguments(); }
        ALWAYS_INLINE void appendArgument(JSValue v) { m_entryScope.appendArgument(v); }
        ALWAYS_INLINE unsigned numberOfAppendedArguments() const { return m_entryScope.numberOfAppendedArguments(); }

        EntryFrame* vmEntryFrame() const { return m_entryScope.vmEntryFrame(); }

        VM& vm() const { return m_vm; }
        JSFunction* function() const { return m_function; }
        FunctionExecutable* functionExecutable() const { return m_functionExecutable; };

    private:
#if ASSERT_ENABLED
        bool m_valid { false };
#endif
        VM& m_vm;
        JSFunction* m_function { nullptr };
        FunctionExecutable* m_functionExecutable { nullptr };
        VMEntryScope m_entryScope;
    };

} // namespace JSC
