#pragma once
#include "aether/a64/guest_cpu.hpp"
#include <array>
namespace aether::bionic {
class NativeThreads;
class NativeMutexes;
class NativeConditions {
  public:
    NativeConditions(a64::GuestMemory &m, NativeThreads &t, NativeMutexes &x) : memory_(m), threads_(t), mutexes_(x) {}
    // wait, signal, broadcast, init, destroy, attr init/destroy/get/set shared/get/set clock.
    a64::Fault invoke(unsigned operation, std::array<std::uint64_t,31> &registers, bool full_frame);
  private:
    struct Waiter {a64::Address condition=0, mutex=0; std::uint32_t tid=0, state=0; bool notified=false;};
    a64::GuestMemory &memory_;
    NativeThreads &threads_;
    NativeMutexes &mutexes_;
    std::array<Waiter,16> waiters_{};
};
}
