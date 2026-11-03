#pragma once
#include "aether/a64/guest_cpu.hpp"
#include "aether/host/time_service.hpp"
#include <array>
#include <string_view>

namespace aether::bionic {
class NativeThreads;
class NativeSignals;
// App-local original futex registry; no Windows handle, shared-memory import or
// guest executable pointer is used as synchronization authority.
class NativeFutexes final {
  public:
    NativeFutexes(a64::GuestMemory &memory,NativeThreads &threads,NativeSignals &signals,
                  const host::TimeService &time,const a64::AppContext &app)
        :memory_(memory),threads_(threads),signals_(signals),time_(time),app_(app){}
    struct ResumeRestart {
        std::array<std::uint64_t,31> registers;
        a64::Address instruction=0;
    };
    // x0..x5 are the normalized six futex syscall arguments. Restart, if
    // supplied, is the authenticated original registered SVC before marshalling.
    a64::Fault invoke(a64::ServiceState &,bool full_frame,bool allow_deferred,const ResumeRestart *restart=nullptr);
    std::string_view rejection() const noexcept {return rejection_;}
    std::uint64_t errors() const noexcept {return errors_;}
  private:
    struct DeferredWait;
    a64::GuestMemory &memory_;
    NativeThreads &threads_;
    NativeSignals &signals_;
    const host::TimeService &time_;
    const a64::AppContext &app_;
    // Operations remove their exact live registration on wake or destruction.
    std::array<DeferredWait*,64> waiters_{};
    std::uint64_t next_ticket_=1;
    std::uint64_t errors_=0;
    std::string_view rejection_;
    a64::Fault fail(a64::ServiceState &,a64::Address,unsigned) noexcept;
};
}
