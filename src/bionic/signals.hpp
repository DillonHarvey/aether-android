#pragma once
#include "aether/bionic/guest_posix.hpp"
#include <array>
#include <chrono>
#include <optional>

namespace aether::bionic {
inline constexpr std::uint32_t native_sigrtmin=42,native_sigrtmax=64;
class NativeThreads;
class NativeSignals {
  public:
    NativeSignals(a64::GuestMemory &memory, NativeThreads &threads,const a64::AppContext &app) : memory_(memory), threads_(threads), app_(app) {}
    void runner(GuestPosixServices::SignalRunner value);
    bool terminated() const noexcept { return terminated_; }
    using AlarmClock = std::chrono::steady_clock;
    std::uint32_t alarm(std::uint32_t seconds);
    void poll_alarm() noexcept;
    std::optional<AlarmClock::time_point> alarm_deadline() const noexcept { return alarm_deadline_; }
    bool ready();
    std::uint64_t delivery_serial() const noexcept { return delivery_serial_; }
    // signal, sigaction, raise, sigpending, sigwait. Only standard-signal generation is supported.
    a64::Fault invoke(unsigned operation, a64::ServiceState &state, bool full_frame);
    a64::Fault deliver_pending(a64::ServiceState &state, bool full_frame, std::uint64_t allowed=~std::uint64_t{0});
    a64::Fault tgkill(std::uint64_t group,std::uint64_t target,std::uint64_t signal,a64::ServiceState &,bool full_frame);
    a64::Fault abort(a64::ServiceState &state, bool full_frame, ProcessState &process);
    a64::Fault abort_failure() const noexcept {return abort_failure_;}
    a64::Fault alternate_stack(a64::ServiceState &state, bool full_frame);

  private:
    struct Action { std::uint32_t flags = 0; a64::Address handler = 0; std::uint64_t mask = 0; };
    a64::GuestMemory &memory_;
    NativeThreads &threads_;
    const a64::AppContext &app_;
    std::array<Action, 65> actions_{};
    GuestPosixServices::SignalRunner runner_;
    unsigned depth_ = 0;
    struct StackFrame {std::uint32_t owner=0;a64::Address base=0,end=0;};
    std::array<StackFrame,8> stack_frames_{};
    bool terminated_ = false, aborting_ = false;
    a64::Fault abort_failure_=a64::Fault::none;
    std::optional<AlarmClock::time_point> alarm_deadline_;
    std::uint64_t process_pending_ = 0, delivery_serial_ = 0;
    void consume_pending(std::uint64_t bit);
    a64::Fault fail(a64::ServiceState &, unsigned, std::uint64_t);
    a64::Fault validate(const Action &) const;
};
} // namespace aether::bionic
