#pragma once
#include "aether/bionic/guest_posix.hpp"
#include <array>

namespace aether::bionic {
inline constexpr std::uint32_t native_sigrtmin=42,native_sigrtmax=64;
class NativeThreads;
class NativeSignals {
  public:
    NativeSignals(a64::GuestMemory &memory, NativeThreads &threads) : memory_(memory), threads_(threads) {}
    void runner(GuestPosixServices::SignalRunner value);
    bool terminated() const noexcept { return terminated_; }
    // signal, sigaction, raise, sigpending, sigwait. Only standard-signal generation is supported.
    a64::Fault invoke(unsigned operation, a64::ServiceState &state, bool full_frame);
    a64::Fault deliver_pending(a64::ServiceState &state, bool full_frame);

  private:
    struct Action { std::uint32_t flags = 0; a64::Address handler = 0; std::uint64_t mask = 0; };
    a64::GuestMemory &memory_;
    NativeThreads &threads_;
    std::array<Action, 65> actions_{};
    GuestPosixServices::SignalRunner runner_;
    unsigned depth_ = 0;
    bool terminated_ = false;
    a64::Fault fail(a64::ServiceState &, unsigned, std::uint64_t);
    a64::Fault validate(const Action &) const;
};
} // namespace aether::bionic
