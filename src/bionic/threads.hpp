#pragma once
#include "aether/bionic/guest_posix.hpp"
#include <array>
#include <optional>
#include <thread>
namespace aether::bionic {
class NativeThreads {
  public:
    NativeThreads(a64::GuestMemory &,std::uint32_t,a64::Address);
    ~NativeThreads();
    void initialize();
    void managed_priority(int baseline,host::PriorityService service);
    host::PriorityResult priority(std::int32_t which,std::uint32_t who,std::optional<std::int32_t> nice);
    void runner(GuestPosixServices::ThreadRunner value);
    std::uint64_t &signal_mask();
    std::uint64_t &signal_pending();
    void discard_signal_pending(std::uint64_t)noexcept;
    std::uint64_t &binding_signal_mask(const GuestPosixServices::ThreadBinding&);
    unsigned change_signal_mask(std::array<std::uint64_t,31>&);
    a64::Fault create(std::array<std::uint64_t,31> &);
    void request_exit(std::uint64_t) noexcept;
    std::optional<std::uint64_t> exit_value(a64::Address) const noexcept;
    a64::Fault join(std::array<std::uint64_t,31> &);
    a64::Fault pump(std::uint64_t budget);
    bool has_runnable() const noexcept;
    a64::Fault run_next(std::uint64_t budget, std::uint64_t &spent);
    a64::Address tls()const noexcept;
    a64::Address error_address()const noexcept;
    std::optional<GuestPosixServices::ThreadBinding> exchange_binding(std::optional<GuestPosixServices::ThreadBinding> value);
    std::uint32_t tid()const noexcept{return external_?external_->id:active_;}
    std::string_view rejection()const noexcept{return rejection_;}
    std::uint64_t created=0,started=0,joined=0;
  private:
    enum class State {runnable,running,completed,failed};
    struct Thread {std::uint32_t id; a64::Address entry,arg,stack,tls;State state=State::runnable;GuestPosixServices::ThreadExecution execution;bool stack_owned=false,tls_owned=false;std::uint64_t signal_mask=0,pending_signals=0;std::int32_t nice=0;std::optional<std::uint64_t> exited;};
    a64::GuestMemory &memory_;std::uint32_t main_,active_,next_;a64::Address main_errno_;bool main_tls_owned_=false;std::uint64_t guard_=0;
    std::uint64_t main_mask_=0,main_pending_=0;
    std::optional<std::uint64_t> main_exit_;
    struct ManagedMask {std::uint32_t id=0;a64::Address tls=0;std::uint64_t mask=0,pending=0;std::int32_t nice=0;std::optional<std::uint64_t> exited;};
    std::array<ManagedMask,16> managed_masks_{};
    std::optional<GuestPosixServices::ThreadBinding> external_;
    std::array<std::optional<Thread>,16> threads_;GuestPosixServices::ThreadRunner runner_;std::string_view rejection_;
    std::thread::id owner_=std::this_thread::get_id();
    int priority_baseline_=0;std::int32_t main_nice_=0;bool priority_dirty_=false,priority_restore_failed_=false;
    host::PriorityService managed_priority_;
    std::int32_t &local_priority();
    a64::Fault run(Thread &,std::uint64_t);
    void release(Thread &)noexcept;
    void initialize_tls(a64::Address,std::uint32_t);
};
}
