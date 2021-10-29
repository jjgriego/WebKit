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

#pragma once

#include <JavaScriptCore/RuntimeFlags.h>
#include <JavaScriptCore/Strong.h>
#include <JavaScriptCore/Weak.h>
#include <wtf/IsoMalloc.h>
#include <wtf/RefCounted.h>
#include <wtf/RefPtr.h>
#include <memory>

namespace JSC { class VM; }

namespace WebCore {

class JSShadowRealmGlobalScopeBase;
class JSDOMGlobalObject;
class ScriptModuleLoader;
class ScriptExecutionContext;

class ShadowRealmGlobalScope : public RefCounted<ShadowRealmGlobalScope>
{
    friend class JSShadowRealmGlobalScopeBase;
    WTF_MAKE_ISO_ALLOCATED(ShadowRealmGlobalScope);

public:
    static RefPtr<ShadowRealmGlobalScope> tryCreate(JSC::VM& vm, JSDOMGlobalObject*);
    ~ShadowRealmGlobalScope();

    JSC::RuntimeFlags javaScriptRuntimeFlags() const;
    ScriptExecutionContext* enclosingContext() const;

    ShadowRealmGlobalScope& self() { return *this; }
    ScriptModuleLoader& moduleLoader() { return *m_moduleLoader; }
    JSShadowRealmGlobalScopeBase* wrapper();

protected:
    ShadowRealmGlobalScope(JSC::VM& vm, JSDOMGlobalObject*);

private:
    RefPtr<JSC::VM> m_vm;
    JSC::Strong<JSDOMGlobalObject> m_incubatingWrapper;
    JSC::Weak<JSShadowRealmGlobalScopeBase> m_wrapper{};
    std::unique_ptr<ScriptModuleLoader> m_moduleLoader{};
};

} // namespace WebCore
