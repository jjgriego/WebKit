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

namespace WTF {

#if defined(NDEBUG)

// We can only use the inline asm implementation on release builds because it
// needs to be inlinable in order to be correct.
template<typename T = void*>
ALWAYS_INLINE T currentStackPointer()
{
    void* stackPointer = nullptr;
#if COMPILER(GCC_COMPATIBLE)
#if CPU(X86_64)
    __asm__ volatile ("movq %%rsp, %0" : "=r"(stackPointer) ::);
#elif CPU(X86)
    __asm__ volatile ("movl %%esp, %0" : "=r"(stackPointer) ::);
#elif CPU(ARM64) && defined(__ILP32__)
    uint64_t stackPointerRegister = 0;
    __asm__ volatile ("mov %0, sp" : "=r"(stackPointerRegister) ::);
    stackPointer = reinterpret_cast<void*>(stackPointerRegister);
#elif CPU(ARM64) || CPU(ARM_THUMB2) || CPU(ARM_TRADITIONAL)
    __asm__ volatile ("mov %0, sp" : "=r"(stackPointer) ::);
#endif
#endif // COMPILER(GCC_COMPATIBLE)
    return bitwise_cast<T>(stackPointer);
}

#else // not defined(NDEBUG)

template<typename T = void*>
T currentStackPointer()
{
    void* stackPointer = nullptr;
    constexpr size_t sizeOfFrameHeader = 2 * sizeof(void*);
#if COMPILER(GCC_COMPATIBLE)
    stackPointer = reinterpret_cast<uint8_t*>(__builtin_frame_address(0)) + sizeOfFrameHeader;
#else
    // Make sure that sp is the only local variable declared in this function.
    stackPointer = reinterpret_cast<uint8_t*>(&sp) + sizeOfFrameHeader + sizeof(stackPointer);
#endif
    return bitwise_cast<T>(stackPointer);
}

#endif // defined(NDEBUG)

} // namespace WTF

using WTF::currentStackPointer;
