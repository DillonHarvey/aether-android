#pragma once
#include "aether/a64/guest_cpu.hpp"
#include <map>
namespace aether::bionic {
class NativeThreads;
class NativeRwLocks {
  public:
    explicit NativeRwLocks(a64::GuestMemory &memory):memory_(memory){}
    a64::Fault invoke(unsigned,std::uint32_t,std::array<std::uint64_t,31> &) noexcept;
    // mode0 reads, mode1 writes. Only admitted factory children retain a wait;
    // the real try-acquire remains authoritative at every selected-owner step.
    a64::Fault invoke_lock(unsigned mode,a64::ServiceState &,NativeThreads &,bool allow_deferred,
                           std::shared_ptr<ProcessState> process) noexcept;
    std::string_view rejection()const noexcept{return rejection_;}
  private:
    struct DeferredLock;
    static constexpr std::size_t waiter_limit=16;
    struct WaitingLock {
        a64::Address address=0;std::uint32_t tid=0;const void *operation=nullptr;
        const a64::ThreadRegisterState *owner=nullptr;bool preference=false,read=false;
    };
    struct Held {std::uint32_t writer=0,total=0;bool preference=false;std::map<std::uint32_t,std::uint32_t> readers;};
    a64::GuestMemory &memory_;std::map<a64::Address,Held> held_;std::string_view rejection_;
    std::array<WaitingLock,waiter_limit> waiters_{}; // Nonowning; each exact continuation retires its own claim.
    bool waiting_writer(a64::Address) const noexcept;
    bool waiting_any(a64::Address) const noexcept;
    bool waiter_state_matches(a64::Address,bool preference) const noexcept;
    bool lock_ready(a64::Address,std::uint32_t tid,bool read) const noexcept;
    a64::Fault call(unsigned,std::uint32_t,std::array<std::uint64_t,31> &);
};
}
