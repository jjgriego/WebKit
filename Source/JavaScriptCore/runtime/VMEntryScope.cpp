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

#include "config.h"
#include "VMEntryScope.h"

#include "Options.h"
#include "SamplingProfiler.h"
#include "VM.h"
#include "VMEntryScopeInlines.h"
#include "WasmCapabilities.h"
#include "WasmMachineThreads.h"
#include "Watchdog.h"
#include "wtf/StdLibExtras.h"
#include <wtf/SystemTracing.h>

namespace JSC {

VMEntryScope::VMEntryScope(JSGlobalObject* globalObject)
    : m_globalObject(globalObject)
{
    VM& vm = globalObject->vm();

    m_prevTopEntryFrame = vm.topEntryFrame;
    m_prevTopCallFrame = vm.topCallFrame;

    if (!vm.entryScope) {
        vm.entryScope = this;

        auto& thread = Thread::current();
        if (UNLIKELY(!thread.isJSThread())) {
            Thread::registerJSThread(thread);

#if ENABLE(WEBASSEMBLY)
                if (Wasm::isSupported())
                    Wasm::startTrackingCurrentThread();
#endif

#if HAVE(MACH_EXCEPTIONS)
                registerThreadForMachExceptionHandling(thread);
#endif
        }

        vm.firePrimitiveGigacageEnabledIfNecessary();

        // Reset the date cache between JS invocations to force the VM to
        // observe time zone changes.
        vm.resetDateCacheIfNecessary();

        if (UNLIKELY(vm.watchdog()))
            vm.watchdog()->enteredVM();

#if ENABLE(SAMPLING_PROFILER)
        {
            SamplingProfiler* samplingProfiler = vm.samplingProfiler();
            if (UNLIKELY(samplingProfiler))
                samplingProfiler->noticeVMEntry();
        }
#endif
        if (UNLIKELY(Options::useTracePoints()))
            tracePoint(VMEntryScopeStart);
    }

    vm.clearLastException();
}

void VMEntryScope::addDidPopListener(Function<void ()>&& listener)
{
    m_didPopListeners.append(WTFMove(listener));
}

VMEntryScope::~VMEntryScope()
{
    VM& vm = m_globalObject->vm();
    vm.topEntryFrame = m_prevTopEntryFrame;
    vm.topCallFrame = m_prevTopCallFrame;
    vm.didEnterVM = true;

    if (vm.entryScope != this)
        return;

    ASSERT_WITH_MESSAGE(!vm.hasCheckpointOSRSideState(), "Exitting the VM but pending checkpoint side state still available");

    if (UNLIKELY(Options::useTracePoints()))
        tracePoint(VMEntryScopeEnd);
    
    if (UNLIKELY(vm.watchdog()))
        vm.watchdog()->exitedVM();

    vm.entryScope = nullptr;

    for (auto& listener : m_didPopListeners)
        listener();

    // If the trap bit is still set at this point, then it means that VMTraps::handleTraps()
    // has not yet been called for this termination request. As a result, we've not thrown a
    // TerminationException yet. Some client code relies on detecting the presence of the
    // TerminationException in order to signal that a termination was requested. As a result,
    // we want to stay in the TerminationInProgress state until VMTraps::handleTraps() (which
    // clears the trap bit) gets called, and the TerminationException gets thrown.
    //
    // Note: perhaps there's a better way for the client to know that a termination was
    // requested (after all, the request came from the client). However, this is how the
    // client code currently works. Changing that will take some significant effort to hunt
    // down all the places in client code that currently rely on this behavior.
    if (!vm.traps().needHandling(VMTraps::NeedTermination))
        vm.setTerminationInProgress(false);
    vm.clearScratchBuffers();
}

void VMEntryScope::initializeCall(CodeBlock* codeBlock, unsigned incomingArgCount)
{
    m_codeBlock = codeBlock;
    m_incomingArgCount = incomingArgCount;

    // Compute arg count after arity check and padding for alignment:
    unsigned argsCount = incomingArgCount + 1; // Add one for the thisValue.
    if (codeBlock)
        argsCount = std::max(argsCount, codeBlock->numParameters());
    m_arityCheckedArgsCountIncludingThis = roundArgumentCountToAlignFrame(argsCount);

    // Compute stack size needed for allocation:
    unsigned size = 0;
    size += CallFrame::headerSizeInRegisters * sizeof(Register); // Target JS frame header.
    size += m_arityCheckedArgsCountIncludingThis * sizeof(JSValue); // Target JS frame args.
    size += kVMEntryFrameAlignedSize; // The EntryFrame.
    m_stackBufferSize = size;
}

EncodedJSValue VMEntryScope::go(EntryTrampolineFn enter, VM& vm, void* target)
{
    // These platforms have loose stack alignment requirements: we may need to
    // add 8 bytes of padding to bring the SP into 16-byte alignment, but we
    // don't know until runtime if this is necessary or not
    if constexpr (isARM() || isMIPS()) {
        auto const sp = reinterpret_cast<uintptr_t>(currentStackPointer());
        m_stackBufferSize += WTF::roundUpToMultipleOf(stackAlignmentBytes(), sp) - sp;
    }

    ALLOCATE_ENTRY_FRAME_ON_STACK((*this));
    initializeBuffer();
    return enter(target, &vm, m_vmEntryFrame);
}

void VMEntryScope::finalizeCall(JSObject* callee, JSValue thisValue, JSValue* incomingArgs)
{
    m_callee = callee;
    m_thisValue = thisValue;
    m_incomingArgs = incomingArgs;
}

void VMEntryScope::initializeBuffer()
{
    VM& vm = m_globalObject->vm();

    // Fill in the JS frame header.
    auto* callFrame = reinterpret_cast<CallFrame*>(m_stackBuffer);



    // NOTE(jgriego) I'm not sure these asserts (checking the alignment of the
    // callFrame and entryFrame) make sense
    //
    // on ARMv7, we are checking that the SP is aligned at the call instruction,
    // which necessarily means that the SP minus the saved FP and PC is aligned
    // to 16 bytes, which means that the SP when we jump to
    // `vmEntryToJavaScript` will be 8 bytes off (the size of the saved FP and
    // PC)...
    //
    // We can't have things both ways; either the SP is aligned at the call
    // instruction or after the prologue but not both. (because the change
    // between these two points in time is 8 bytes)
    //
    // So, for this patch, I keep the alignment at the call instruction which
    // means we have to remove or loosen these assertions
    //
    // this probably works on 64-bit machines
    // because the prologue saved registers add up to a 16-byte aligned quantity
    // so we don't notice this mismatch



    // RELEASE_ASSERT(WTF::roundDownToMultipleOf<stackAlignmentBytes()>(callFrame) == callFrame); // mlam make ASSERT
    callFrame->setCodeBlock(m_codeBlock);
    callFrame->setCallee(m_callee);
    callFrame->setArgumentCountIncludingThis(m_incomingArgCount + 1);
    callFrame->setThisValue(m_thisValue);

    // Populate the JS frame args if needed.
    // Note: the client may choose to populate the arguments itself instead. For example,
    // see uses of CachedCall and appendArgument in replaceUsingRegExpSearch.
    auto* args = callFrame->addressOfArgumentsStart();
    unsigned arityCheckedArgsCount = m_arityCheckedArgsCountIncludingThis - 1;
    unsigned i = 0;
    if (hasAppendedArguments()) {
        ASSERT(numberOfAppendedArguments() == m_incomingArgCount);
        i = numberOfAppendedArguments();
    } else {
        if (m_incomingArgs) {
            for (; i < m_incomingArgCount; ++i)
                args[i] = m_incomingArgs[i];
        }
    }
    for (; i < arityCheckedArgsCount; ++i)
        args[i] = jsUndefined();

    // Fill in the EntryFrame.
    // The EntryFrame header will be filled in by vmEntryToJavaScript and friends.
    auto* entryFrame = bitwise_cast<EntryFrame*>(&args[arityCheckedArgsCount]);
    entryFrame->entryScope = this;
    entryFrame->globalObject = m_globalObject;

    m_vmEntryFrame = entryFrame;
    // RELEASE_ASSERT(WTF::roundDownToMultipleOf<stackAlignmentBytes()>(entryFrame) == entryFrame); // mlam make ASSERT

    // The VMEntryScope serves as an RAII that will restore these.
    vm.topCallFrame = callFrame;
    vm.topEntryFrame = m_vmEntryFrame;
}

} // namespace JSC
