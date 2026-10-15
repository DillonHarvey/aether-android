/* This file is part of the dynarmic project.
 * Copyright (c) 2022 MerryMage
 * SPDX-License-Identifier: 0BSD
 */

#include <mutex>
#ifdef _WIN32
#include <intrin.h>
#endif

#include <xbyak/xbyak.h>

#include "dynarmic/backend/x64/abi.h"
#include "dynarmic/backend/x64/hostloc.h"
#include "dynarmic/common/spin_lock.h"

namespace Dynarmic {

void EmitSpinLockLock(Xbyak::CodeGenerator& code, Xbyak::Reg64 ptr, Xbyak::Reg32 tmp) {
    Xbyak::Label start, loop;

    code.jmp(start);
    code.L(loop);
    code.pause();
    code.L(start);
    code.mov(tmp, 1);
    code.lock();
    code.xchg(code.dword[ptr], tmp);
    code.test(tmp, tmp);
    code.jnz(loop);
}

void EmitSpinLockUnlock(Xbyak::CodeGenerator& code, Xbyak::Reg64 ptr, Xbyak::Reg32 tmp) {
    code.xor_(tmp, tmp);
    code.xchg(code.dword[ptr], tmp);
    code.mfence();
}

#ifndef _WIN32
namespace {

struct SpinLockImpl {
    void Initialize();

    Xbyak::CodeGenerator code;

    void (*lock)(volatile int*);
    void (*unlock)(volatile int*);
};

std::once_flag flag;
SpinLockImpl impl;

void SpinLockImpl::Initialize() {
    const Xbyak::Reg64 ABI_PARAM1 = Backend::X64::HostLocToReg64(Backend::X64::ABI_PARAM1);

    code.align();
    lock = code.getCurr<void (*)(volatile int*)>();
    EmitSpinLockLock(code, ABI_PARAM1, code.eax);
    code.ret();

    code.align();
    unlock = code.getCurr<void (*)(volatile int*)>();
    EmitSpinLockUnlock(code, ABI_PARAM1, code.eax);
    code.ret();
}

}  // namespace

void SpinLock::Lock() {
    std::call_once(flag, &SpinLockImpl::Initialize, impl);
    impl.lock(&storage);
}

void SpinLock::Unlock() {
    std::call_once(flag, &SpinLockImpl::Initialize, impl);
    impl.unlock(&storage);
}
#else
// Aether Windows integration: do not allocate a process-global RWX code buffer
// during static initialization for two elementary host atomic operations.
// The in-JIT emitters above retain the identical xchg/pause ordering protocol.
void SpinLock::Lock() {
    static_assert(sizeof(storage) == sizeof(long));
    while (_InterlockedExchange(reinterpret_cast<volatile long*>(&storage), 1) != 0) {
        _mm_pause();
    }
}

void SpinLock::Unlock() {
    _InterlockedExchange(reinterpret_cast<volatile long*>(&storage), 0);
    _mm_mfence();
}
#endif

}  // namespace Dynarmic
