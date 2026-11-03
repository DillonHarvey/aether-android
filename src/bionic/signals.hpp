#pragma once
#include "aether/bionic/guest_posix.hpp"
#include "threads.hpp"
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
    void fault_runner(GuestPosixServices::FaultSignalRunner value);
    a64::CpuFaultAction synchronous_fault(const a64::CpuException &,a64::ArchitecturalState &,
                                         const a64::CpuFaultBoundary &);
    bool pending_signal_entry(const a64::SignalEntry &,a64::Address,std::uint64_t) const noexcept;
    bool frame_ready(const a64::ServiceState &) const noexcept;
    bool terminated() const noexcept { return terminated_; }
    using AlarmClock = std::chrono::steady_clock;
    std::uint32_t alarm(std::uint32_t seconds);
    void poll_alarm() noexcept;
    std::optional<AlarmClock::time_point> alarm_deadline() const noexcept { return alarm_deadline_; }
    bool ready();
    // Waiting owners are observed without selecting them or consuming/queuing
    // a signal. An expired alarm is committed by the actual resumed owner.
    bool wait_ready(std::uint32_t id,const std::shared_ptr<a64::ThreadRegisterState> &owner) const noexcept;
    std::optional<AlarmClock::time_point> wait_deadline(std::uint32_t id,const std::shared_ptr<a64::ThreadRegisterState> &owner) const noexcept;
    // First non-ignored unblocked signal: whether untouched slow I/O restarts.
    struct IoInterruption {unsigned signal;bool restart;};
    std::optional<IoInterruption> io_interruption();
    bool io_frame_ready(const IoInterruption &,const a64::ServiceState &) const noexcept;
    // Caller commits the actual write result before generating this SI_USER event.
    a64::Fault broken_pipe(a64::ServiceState &,bool full_frame);
    std::uint64_t delivery_serial() const noexcept { return delivery_serial_; }
    // signal, sigaction, raise, sigpending, sigwait. Only standard-signal generation is supported.
    a64::Fault invoke(unsigned operation, a64::ServiceState &state, bool full_frame,bool allow_deferred=false);
    a64::Fault deliver_pending(a64::ServiceState &state, bool full_frame, std::uint64_t allowed=~std::uint64_t{0});
    a64::Fault tgkill(std::uint64_t group,std::uint64_t target,std::uint64_t signal,a64::ServiceState &,bool full_frame);
    a64::Fault abort(a64::ServiceState &state, bool full_frame, ProcessState &process);
    a64::Fault abort_failure() const noexcept {return abort_failure_;}
    a64::Fault alternate_stack(a64::ServiceState &state, bool full_frame);

    bool switch_safe() const noexcept { return depth_==0 && !aborting_; }
  private:
    struct DeferredSigwait;
    struct Action { std::uint32_t flags = 0; a64::Address handler = 0; std::uint64_t mask = 0; };
    a64::GuestMemory &memory_;
    NativeThreads &threads_;
    const a64::AppContext &app_;
    std::array<Action, 65> actions_{};
    GuestPosixServices::SignalRunner runner_;
    GuestPosixServices::FaultSignalRunner fault_runner_;
    unsigned depth_ = 0;
    struct StackFrame {std::uint32_t owner=0;a64::Address base=0,end=0,frame=0,handler=0,tls=0;std::uint64_t invocation=0;std::shared_ptr<a64::ThreadRegisterState> registers;};
    std::array<StackFrame,8> stack_frames_{};
    bool terminated_ = false, aborting_ = false;
    a64::Fault abort_failure_=a64::Fault::none;
    std::optional<AlarmClock::time_point> alarm_deadline_;
    std::uint64_t process_pending_ = 0, delivery_serial_ = 0;
    NativeSignalInfos process_information_;
    void consume_pending(std::uint64_t bit);
    void discard_process_pending(std::uint64_t bits) noexcept;
    void discard_pending(std::uint64_t bits) noexcept;
    std::optional<NativeSignalInfo> pending_information(unsigned signal) const noexcept;
    bool context_ready(const a64::ServiceState &) const noexcept;
    a64::Fault deliver_frame(unsigned,const NativeSignalInfo &,std::optional<a64::Address>,
                             const a64::ArchitecturalState &,a64::ArchitecturalState &,const a64::CpuFaultBoundary &,bool pending);
    a64::Fault fail(a64::ServiceState &, unsigned, std::uint64_t);
    a64::Fault validate(const Action &) const;
};
} // namespace aether::bionic
