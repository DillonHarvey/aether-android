#pragma once
#include "aether/a64/guest_cpu.hpp"
namespace aether::bionic {
class NativeThreads;
class NativeSignals;
struct NativeSleepDuration {
    std::uint64_t seconds=0;std::uint32_t nanos=0;
    // Both nanosecond components are normalized below one billion.
    void consume(std::uint64_t elapsed_seconds,std::uint32_t elapsed_nanos) noexcept;
};
class NativeSleeping {
  public:
    NativeSleeping(a64::GuestMemory &memory,NativeThreads &threads,NativeSignals &signals,const a64::AppContext &app):memory_(memory),threads_(threads),signals_(signals),app_(app){}
    // sleep, usleep, nanosleep. Only an admitted factory child may retain an
    // owned continuation; no scheduler switch occurs inside this invocation.
    a64::Fault invoke(unsigned operation,a64::Address error,std::array<std::uint64_t,31> &,bool full_frame,a64::ServiceState *frame=nullptr,bool allow_deferred=false);
  private:
    struct DeferredSleep;
    a64::GuestMemory &memory_;NativeThreads &threads_;NativeSignals &signals_;const a64::AppContext &app_;
};
}
