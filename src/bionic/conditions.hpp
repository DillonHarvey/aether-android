#pragma once
#include "aether/a64/guest_cpu.hpp"
#include <array>
#include "aether/host/time_service.hpp"
namespace aether::bionic {
class NativeThreads;
class NativeMutexes;
class NativeSignals;
class NativeConditions {
  public:
    NativeConditions(a64::GuestMemory &m, NativeThreads &t, NativeMutexes &x, const host::TimeService &time, NativeSignals &signals, const a64::AppContext &app) : memory_(m), threads_(t), mutexes_(x), time_(time), signals_(signals), app_(app) {}
    // wait, signal, broadcast, init, destroy, attr init/destroy/get/set shared/get/set clock, timed wait.
    a64::Fault invoke(unsigned operation, std::array<std::uint64_t,31> &registers, bool full_frame, a64::ServiceState *frame=nullptr);
  private:
    struct Waiter {a64::Address condition=0, mutex=0; std::uint32_t tid=0, state=0; bool notified=false;};
    a64::GuestMemory &memory_;
    NativeThreads &threads_;
    NativeMutexes &mutexes_;
    const host::TimeService &time_;
    NativeSignals &signals_;
    const a64::AppContext &app_;
    std::array<Waiter,16> waiters_{};
};
}
