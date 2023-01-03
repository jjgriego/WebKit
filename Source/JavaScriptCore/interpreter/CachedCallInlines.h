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

#include "CachedCall.h"
#include "ExceptionHelpers.h"
#include "Interpreter.h"
#include "JSFunction.h"
#include "ThrowScope.h"
#include "VMEntryScopeInlines.h"
#include "VMInlines.h"

namespace JSC {

inline CachedCall::CachedCall(JSGlobalObject* globalObject, JSFunction* function, unsigned argumentCount)
    : m_vm(globalObject->vm())
    , m_function(function)
    , m_functionExecutable(function->jsExecutable())
    , m_entryScope(function->scope()->globalObject())
{
    VM& vm = m_vm;
    auto throwScope = DECLARE_THROW_SCOPE(vm);

    ASSERT(!function->isHostFunctionNonInline());

    DeferTraps deferTraps(vm); // We can't jettison this code if we're about to run it.

    auto* executable = function->jsExecutable();
    CodeBlock* codeBlock;
    executable->prepareForExecution<FunctionExecutable>(vm, function, function->scope(), CodeForCall, codeBlock);
    if (UNLIKELY(throwScope.exception()))
        return;

    ASSERT(codeBlock);
    codeBlock->m_shouldAlwaysBeInlined = false;

    m_entryScope.initializeCall(codeBlock, argumentCount);
    if (UNLIKELY(!m_entryScope.isSafeToRecurseSoft(vm) || argumentCount > maxArguments)) {
        throwStackOverflowError(globalObject, throwScope);
        return;
    }

#if ASSERT_ENABLED
    m_valid = !throwScope.exception();
#endif
}

template<typename Functor>
ALWAYS_INLINE JSValue CachedCall::call(Functor initalizeArgs)
{
    ASSERT(m_valid);
    return vm().interpreter.executeCachedCall(*this, initalizeArgs);
}

} // namespace JSC
