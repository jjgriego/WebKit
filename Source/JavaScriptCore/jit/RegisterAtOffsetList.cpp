/*
 * Copyright (C) 2015-2016 Apple Inc. All rights reserved.
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
#include "RegisterAtOffsetList.h"

#if ENABLE(ASSEMBLER)

#include <wtf/ListDump.h>

namespace JSC {

DEFINE_ALLOCATOR_WITH_HEAP_IDENTIFIER(RegisterAtOffsetList);

RegisterAtOffsetList::RegisterAtOffsetList() { }

RegisterAtOffsetList::RegisterAtOffsetList(RegisterSet registerSet, OffsetBaseType offsetBaseType)
    : m_registers(registerSet.numberOfSetRegisters())
{
    constexpr size_t SizeOfGPR = sizeof(CPURegister);
    constexpr size_t SizeOfFPR = sizeof(double);

#if USE(JSVALUE64)
    static_assert(SizeOfGPR == SizeOfFPR);
    size_t numberOfRegs = registerSet.numberOfSetRegisters();
    m_sizeOfAreaInBytes = numberOfRegs * SizeOfGPR;
#elif USE(JSVALUE32_64)
    static_assert(2 * SizeOfGPR == SizeOfFPR);
    size_t numberOfGPRs = registerSet.numberOfSetGPRs();
    size_t numberOfFPRs = registerSet.numberOfSetFPRs();
    if (numberOfFPRs)
        numberOfGPRs = WTF::roundUpToMultipleOf<2>(numberOfGPRs);
    m_sizeOfAreaInBytes = numberOfGPRs * SizeOfGPR + numberOfFPRs * SizeOfFPR;
#endif

    ptrdiff_t startOffset = 0;
    if (offsetBaseType == FramePointerBased)
        startOffset = -static_cast<ptrdiff_t>(m_sizeOfAreaInBytes);

    ptrdiff_t offset = startOffset;
    unsigned index = 0;
    registerSet.forEach([&] (Reg reg) {
        size_t registerSize = SizeOfGPR;
#if USE(JSVALUE32_64)
        if (reg.isFPR()) {
            registerSize = SizeOfFPR;
            offset = WTF::roundUpToMultipleOf<SizeOfFPR>(offset);
        }
#endif
        m_registers[index] = RegisterAtOffset(reg, offset);
        offset += registerSize;
        ++index;
    });

    ASSERT(static_cast<size_t>(offset - startOffset) == m_sizeOfAreaInBytes);
}

void RegisterAtOffsetList::dump(PrintStream& out) const
{
    out.print(listDump(m_registers));
}

RegisterAtOffset* RegisterAtOffsetList::find(Reg reg) const
{
    return tryBinarySearch<RegisterAtOffset, Reg>(m_registers, m_registers.size(), reg, RegisterAtOffset::getReg);
}

unsigned RegisterAtOffsetList::indexOf(Reg reg) const
{
    if (RegisterAtOffset* pointer = find(reg))
        return pointer - m_registers.begin();
    return UINT_MAX;
}

const RegisterAtOffsetList& RegisterAtOffsetList::llintBaselineCalleeSaveRegisters()
{
    static std::once_flag onceKey;
    static LazyNeverDestroyed<RegisterAtOffsetList> result;
    std::call_once(onceKey, [] {
        result.construct(RegisterSet::llintBaselineCalleeSaveRegisters());
    });
    return result.get();
}

const RegisterAtOffsetList& RegisterAtOffsetList::dfgCalleeSaveRegisters()
{
    static std::once_flag onceKey;
    static LazyNeverDestroyed<RegisterAtOffsetList> result;
    std::call_once(onceKey, [] {
        result.construct(RegisterSet::dfgCalleeSaveRegisters());
    });
    return result.get();
}

} // namespace JSC

#endif // ENABLE(ASSEMBLER)

