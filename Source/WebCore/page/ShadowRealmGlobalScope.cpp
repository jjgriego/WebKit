/*
 * Copyright (C) 2021 Igalia S.L.
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
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "ShadowRealmGlobalScope.h"

#include "JSShadowRealmGlobalScope.h"
#include "JSDOMGlobalObject.h"
#include "ScriptModuleLoader.h"
#include <wtf/IsoMallocInlines.h>

namespace WebCore {

WTF_MAKE_ISO_ALLOCATED_IMPL(ShadowRealmGlobalScope);

RefPtr<ShadowRealmGlobalScope> ShadowRealmGlobalScope::tryCreate(JSC::VM& vm, JSDOMGlobalObject* wrapper) {
    return adoptRef(new ShadowRealmGlobalScope(vm, wrapper));
}

ShadowRealmGlobalScope::ShadowRealmGlobalScope(JSC::VM& vm, JSDOMGlobalObject* wrapper)
    : m_vm(&vm)
    , m_incubatingWrapper(vm, wrapper) {}

ScriptExecutionContext* ShadowRealmGlobalScope::enclosingContext() const
{
    return m_incubatingWrapper->scriptExecutionContext();
}

JSC::RuntimeFlags ShadowRealmGlobalScope::javaScriptRuntimeFlags() const
{
    auto const incubatingGlobalObj = m_incubatingWrapper;
    return incubatingGlobalObj->globalObjectMethodTable()->javaScriptRuntimeFlags(incubatingGlobalObj.get());
}

JSShadowRealmGlobalScopeBase* ShadowRealmGlobalScope::wrapper() {
    return m_wrapper.get();
}

ShadowRealmGlobalScope::~ShadowRealmGlobalScope() {}

} // namespace WebCore
