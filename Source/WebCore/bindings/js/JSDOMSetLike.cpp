/*
 * Copyright (C) 2019-2021 Apple Inc. All rights reserved.
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
#include "JSDOMSetLike.h"

#include "WebCoreJSBuiltinInternals.h"
#include "WebCoreJSClientData.h"
#include <JavaScriptCore/CatchScope.h>
#include <JavaScriptCore/JSSet.h>
#include <JavaScriptCore/JSSetInlines.h>
#include <JavaScriptCore/VMTrapsInlines.h>

namespace WebCore {

void DOMSetAdapter::clear()
{
    clearBackingSet(m_lexicalGlobalObject, m_backingSet);
}

std::pair<bool, std::reference_wrapper<JSC::JSObject>> getBackingSet(JSC::JSGlobalObject& lexicalGlobalObject, JSC::JSObject& setLike)
{
    Ref vm = lexicalGlobalObject.vm();
    auto backingSet = setLike.getDirect(vm, builtinNames(vm).backingSetPrivateName());
    if (!backingSet) {
        backingSet = JSC::JSSet::create(vm, lexicalGlobalObject.setStructure());
        setLike.putDirect(vm, builtinNames(vm).backingSetPrivateName(), backingSet, enumToUnderlyingType(JSC::PropertyAttribute::DontEnum));
        return { true, *JSC::asObject(backingSet) };
    }
    return { false, *JSC::asObject(backingSet) };
}

void clearBackingSet(JSC::JSGlobalObject& lexicalGlobalObject, JSC::JSObject& backingSet)
{
    Ref vm = JSC::getVM(&lexicalGlobalObject);
    auto function = lexicalGlobalObject.jsSetPrototype()->getDirect(vm, vm->propertyNames->builtinNames().clearPrivateName());
    ASSERT(function);

    auto callData = JSC::getCallData(function);
    ASSERT(callData.type != JSC::CallData::Type::None);
    JSC::MarkedArgumentBuffer arguments;
    JSC::call(&lexicalGlobalObject, function, callData, &backingSet, arguments);
}

void addToBackingSet(JSC::JSGlobalObject& lexicalGlobalObject, JSC::JSObject& backingSet, JSC::JSValue item)
{
    Ref vm = JSC::getVM(&lexicalGlobalObject);
    auto function = lexicalGlobalObject.jsSetPrototype()->getDirect(vm, vm->propertyNames->builtinNames().addPrivateName());
    ASSERT(function);

    auto callData = JSC::getCallData(function);
    ASSERT(callData.type != JSC::CallData::Type::None);
    JSC::MarkedArgumentBuffer arguments;
    arguments.append(item);
    ASSERT(!arguments.hasOverflowed());
    JSC::call(&lexicalGlobalObject, function, callData, &backingSet, arguments);
}

JSC::JSValue forwardAttributeGetterToBackingSet(JSC::JSGlobalObject& lexicalGlobalObject, JSC::JSObject& backingSet, const JSC::Identifier& attributeName)
{
    return backingSet.get(&lexicalGlobalObject, attributeName);
}

JSC::JSValue forwardFunctionCallToBackingSet(JSC::JSGlobalObject& lexicalGlobalObject, JSC::CallFrame& callFrame, JSC::JSObject& backingSet, const JSC::Identifier& functionName)
{
    Ref vm = JSC::getVM(&lexicalGlobalObject);
    auto function = lexicalGlobalObject.jsSetPrototype()->getDirect(vm, functionName);
    ASSERT(function);

    auto callData = JSC::getCallData(function);
    ASSERT(callData.type != JSC::CallData::Type::None);
    JSC::MarkedArgumentBuffer arguments;
    arguments.ensureCapacity(callFrame.argumentCount());
    for (size_t cptr = 0; cptr < callFrame.argumentCount(); ++cptr)
        arguments.append(callFrame.uncheckedArgument(cptr));
    ASSERT(!arguments.hasOverflowed());
    return JSC::call(&lexicalGlobalObject, function, callData, &backingSet, arguments);
}

JSC::JSValue forwardForEachCallToBackingSet(JSDOMGlobalObject& globalObject, JSC::CallFrame& callFrame, JSC::JSObject& setLike)
{
    auto result = getBackingSet(globalObject, setLike);
    ASSERT(!result.first);

    auto* function = globalObject.builtinInternalFunctions().jsDOMBindingInternals().m_forEachWrapperFunction.get();
    ASSERT(function);

    auto callData = JSC::getCallData(function);
    ASSERT(callData.type != JSC::CallData::Type::None);

    JSC::MarkedArgumentBuffer arguments;
    arguments.ensureCapacity(callFrame.argumentCount() + 1);
    arguments.append(&result.second.get());
    for (size_t cptr = 0; cptr < callFrame.argumentCount(); ++cptr)
        arguments.append(callFrame.uncheckedArgument(cptr));
    ASSERT(!arguments.hasOverflowed());
    return JSC::call(&globalObject, function, callData, &setLike, arguments);
}

}
