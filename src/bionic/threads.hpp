#pragma once
#include "aether/bionic/guest_posix.hpp"
#include <array>
#include <memory>
#include <optional>
#include <thread>
namespace aether::bionic {
struct NativeThreadOptions;
class NativeThreadSpecific;
struct NativeSignalStack {
    std::uint64_t base=0,size=0;
    std::uint32_t flags=2;
};
class NativeThreads {
  public:
    NativeThreads(a64::GuestMemory &,std::uint32_t,a64::Address,NativeThreadSpecific *specific=nullptr);
    ~NativeThreads();
    void initialize();
    void managed_priority(int baseline,host::PriorityService service);
    host::PriorityResult priority(std::int32_t which,std::uint32_t who,std::optional<std::int32_t> nice);
    void runner(GuestPosixServices::ThreadRunner value);
    std::uint64_t &signal_mask();
    std::uint64_t &current_locale();
    std::uint64_t &signal_pending();
    struct SignalTarget {std::uint64_t *mask,*pending;};
    std::optional<SignalTarget> signal_target(std::uint32_t id) noexcept;
    NativeSignalStack &current_signal_stack();
    void discard_signal_pending(std::uint64_t)noexcept;
    std::uint64_t &binding_signal_mask(const GuestPosixServices::ThreadBinding&);
    unsigned change_signal_mask(std::array<std::uint64_t,31>&);
    a64::Fault create(std::array<std::uint64_t,31> &,const NativeThreadOptions &);
    void begin_finalization();
    void end_finalization() noexcept;
    void retire(std::uint32_t id,a64::Address tls) noexcept;
    void request_exit(std::uint64_t) noexcept;
    std::optional<std::uint64_t> exit_value(a64::Address) const noexcept;
    a64::Fault join(std::array<std::uint64_t,31> &);
    a64::Fault detach(std::array<std::uint64_t,31> &);
    a64::Fault thread_name(std::array<std::uint64_t,31> &,bool set,bool kernel=false) noexcept;
    unsigned query(std::uint64_t,NativeThreadOptions &,a64::Address &stack_base) const noexcept;
    a64::Fault pump(std::uint64_t budget);
    bool has_runnable() const noexcept;
    a64::Fault run_next(std::uint64_t budget, std::uint64_t &spent);
    // Offer the host owner, then run at most one queued native peer. This is
    // run-to-completion cooperative progress, not resumable thread time slicing.
    a64::Fault yield(bool full_frame);
    a64::Address tls()const noexcept;
    // Architectural values belong to the current trusted owner, not their bits.
    std::shared_ptr<a64::ThreadRegisterState> thread_register_state(a64::Address trusted_tls) const noexcept;
    a64::Address error_address()const noexcept;
    std::optional<GuestPosixServices::ThreadBinding> exchange_binding(std::optional<GuestPosixServices::ThreadBinding> value);
    std::uint32_t tid()const noexcept{return external_?external_->id:active_;}
    std::string_view rejection()const noexcept{return rejection_;}
    std::uint64_t created=0,started=0,joined=0;
  private:
    static constexpr std::array<char,16> initial_name{'a','e','t','h','e','r'};
    enum class State {runnable,running,completed,failed};
    struct Thread {std::uint32_t id; a64::Address entry,arg,stack,tls;State state=State::runnable;GuestPosixServices::ThreadExecution execution;bool stack_owned=false,tls_owned=false,guard_owned=false,detached=false;std::uint64_t stack_size=0,mapped_size=0,guard_size=0;std::uint64_t signal_mask=0,pending_signals=0;std::int32_t nice=0;std::optional<std::uint64_t> exited;NativeSignalStack signal_stack;std::array<char,16> name=initial_name;std::uint64_t locale=UINT64_MAX;std::shared_ptr<a64::ThreadRegisterState> registers;};
    NativeThreadSpecific *specific_;
    struct Finalizing {std::uint32_t id; a64::Address tls;bool exited=false;};
    std::array<Finalizing,33> finalizing_{};
    std::size_t finalizing_depth_=0;
    a64::GuestMemory &memory_;std::uint32_t main_,active_,next_;a64::Address main_errno_;bool main_tls_owned_=false;std::uint64_t guard_=0;
    std::uint64_t main_mask_=0,main_pending_=0,main_locale_=UINT64_MAX;
    NativeSignalStack main_signal_stack_;
    std::array<char,16> main_name_=initial_name;
    std::optional<std::uint64_t> main_exit_;
    std::shared_ptr<a64::ThreadRegisterState> main_registers_;
    struct ManagedMask {std::uint32_t id=0;a64::Address tls=0;std::uint64_t mask=0,pending=0;std::int32_t nice=0;std::optional<std::uint64_t> exited;NativeSignalStack signal_stack;std::array<char,16> name=initial_name;std::uint64_t locale=UINT64_MAX;std::shared_ptr<a64::ThreadRegisterState> registers;};
    std::array<ManagedMask,16> managed_masks_{};
    std::optional<GuestPosixServices::ThreadBinding> external_;
    std::array<std::optional<Thread>,16> threads_;GuestPosixServices::ThreadRunner runner_;std::string_view rejection_;
    std::thread::id owner_=std::this_thread::get_id();
    int priority_baseline_=0;std::int32_t main_nice_=0;bool priority_dirty_=false,priority_restore_failed_=false;
    host::PriorityService managed_priority_;
    std::array<char,16> *find_name(std::uint64_t) noexcept;
    std::int32_t &local_priority();
    a64::Fault run(Thread &,std::uint64_t);
    void release(Thread &)noexcept;
    void initialize_tls(a64::Address,std::uint32_t);
};
}
