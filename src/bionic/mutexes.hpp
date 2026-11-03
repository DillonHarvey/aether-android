#pragma once
#include "aether/a64/guest_cpu.hpp"
#include <map>
namespace aether::bionic {
class NativeThreads;
class NativeMutexes {
  public:
    explicit NativeMutexes(a64::GuestMemory &memory):memory_(memory){}
    a64::Fault invoke(unsigned operation,std::uint32_t tid,std::array<std::uint64_t,31> &) noexcept;
    // Admitted factory children retain a blocking lock operation; acquisition
    // still uses a fresh trylock. Other callers keep the synchronous op0 path.
    a64::Fault invoke_lock(a64::ServiceState &,NativeThreads &,bool allow_deferred,
                           std::shared_ptr<ProcessState> process) noexcept;
    a64::Fault validate_wait(a64::Address address, std::uint32_t tid) const;
    // Pure op1 readiness: false only for EBUSY; immediate errors also wake the
    // caller to perform its authoritative fresh trylock. The caller authenticates
    // this trusted tid's register-owner incarnation before observing another task.
    bool lock_ready(a64::Address address,std::uint32_t tid) const noexcept;
    std::string_view rejection()const noexcept{return rejection_;}
  private:
    struct DeferredLock;
    struct Held {std::uint32_t owner,depth,type;};
    a64::GuestMemory &memory_;std::map<a64::Address,Held> held_;std::string_view rejection_;
    a64::Fault call(unsigned,std::uint32_t,std::array<std::uint64_t,31> &);
};
}
