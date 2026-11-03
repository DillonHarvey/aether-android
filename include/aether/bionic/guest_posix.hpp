#pragma once
#include "aether/elf/guest_loader.hpp"
#include "aether/bionic/dynamic_linker.hpp"
#include "aether/host/file_service.hpp"
#include "aether/host/time_service.hpp"
#include "aether/host/native_log.hpp"
#include "aether/host/thread_priority.hpp"
#include "aether/android/native_activity.hpp"
#include <functional>

namespace aether::android { struct NativeActivityPointerInput; }
namespace aether::bionic {
struct ServiceMetrics {
    std::uint64_t calls = 0, clock_reads = 0, allocations = 0, frees = 0;
    std::uint64_t errors = 0, rejected_operations = 0, file_operations = 0, log_messages = 0, threads_created = 0, threads_started = 0, threads_joined = 0;
    std::size_t allocated_bytes = 0;
};
class GuestPosixServices final : public a64::GuestServices, public elf::ImportResolver {
  public:
    static constexpr a64::Address trampoline_base = 0x20000, errno_address = 0x24000;
    GuestPosixServices(a64::GuestMemory &memory, const a64::AppContext &app, const host::TimeService &time,
                       std::uint32_t logical_thread = 1, host::FileService *files = nullptr, host::NativeLogSink *logs = nullptr, std::string_view package = {});
    ~GuestPosixServices();
    // Trusted owner-thread transfer from an exact live malloc-family base.
    // The caller owns destination storage; failures retain guest ownership.
    // Empty output still releases a nonnull owned allocation (including malloc(0)).
    a64::Fault copy_release_owned_heap(a64::Address, std::span<std::uint8_t>) noexcept;
    bool has_library(std::string_view library) const noexcept override;
    std::optional<elf::GuestSymbol> resolve(std::string_view library, std::string_view name,
                                            std::string_view version) const override;
    a64::Fault invoke(std::uint32_t service, a64::Address instruction,
                      std::array<std::uint64_t, 31> &registers) noexcept override;
    a64::Fault invoke_frame(std::uint32_t service, a64::Address instruction, a64::ServiceState &state) noexcept override;
    std::optional<std::uint64_t> thread_exit_value(a64::Address tls) const noexcept override;
    std::shared_ptr<a64::ThreadRegisterState> thread_register_state(a64::Address trusted_tls) const override;
    bool event_pending() noexcept override;
    a64::Fault checkpoint(a64::ServiceState &) noexcept override;
    a64::CpuFaultAction synchronous_fault(const a64::CpuException &,a64::ArchitecturalState &,
                                         const a64::CpuFaultBoundary &) noexcept override;
    bool pending_signal_entry(const a64::SignalEntry &,a64::Address,std::uint64_t) const noexcept override;
    void request_thread_exit(std::uint64_t value) noexcept;
    struct ThreadExecution {a64::ExecutionResult result;std::uint64_t ticks=0;bool finalization_failed=false;};
    // The trusted runner finalizes orderly return/exit with finish_current_thread
    // before leaving its original TLS/JNI scope, and reports finalization failure.
    using ThreadRunner=std::function<ThreadExecution(a64::Address,a64::Address,a64::Address,a64::Address,std::uint64_t)>;
    enum class ThreadTaskState { prepared,runnable,running,waiting,completed,cancelled,failed };
    struct ThreadSpec {
        std::uint32_t id=0;
        a64::Address entry=0,argument=0,stack_top=0,tls=0;
        std::shared_ptr<a64::ThreadRegisterState> owner;
        std::uint64_t signal_mask=0,allowance=1000000;
        std::int32_t nice=0;
    };
    struct ThreadSlice {
        ThreadTaskState state=ThreadTaskState::failed;
        std::uint64_t ticks=0;
        std::optional<ThreadExecution> terminal;
        a64::Fault progress_fault=a64::Fault::none; // Caller grant/admission refusal is not child completion.
    };
    class PreparedThread {
      public:
        virtual ~PreparedThread() noexcept=default;
        virtual bool publish() noexcept=0;
        virtual ThreadTaskState state() const noexcept=0;
        virtual bool started() const noexcept=0;
        // The allowance caps this slice; it never refills retained CPU state.
        virtual ThreadSlice resume_slice(std::uint64_t allowance,std::int32_t nice)=0;
        virtual void cancel() noexcept=0;
        // Discard prepared work, release terminal work, or cancel/unwind live
        // work on the external owner. Return only after its stack is retired.
        // Must be idempotent; destruction must never delete a parked stack.
        virtual void close() noexcept=0;
    };
    using ThreadFactory=std::function<std::unique_ptr<PreparedThread>(const ThreadSpec &)>;
    using DestructorRunner=std::function<ThreadExecution(a64::Address,a64::Address,std::uint64_t)>;
    // Trusted terminal-thread phase, while its original TLS/JNI context is alive.
    ThreadExecution finish_current_thread(const DestructorRunner &,std::uint64_t budget);
    void discard_thread(std::uint32_t id,a64::Address tls) noexcept;
    using SignalRunner=std::function<a64::ExecutionResult(a64::Address,std::uint32_t,a64::Address,a64::Address)>;
    void set_signal_runner(SignalRunner runner);
    using FaultSignalRunner=std::function<a64::ExecutionResult(const a64::SignalEntry&,a64::Address,std::uint64_t)>;
    void set_fault_signal_runner(FaultSignalRunner runner);
    // Same logical thread callback: normal return must not finalize the thread.
    using OnceRunner=std::function<a64::ExecutionResult(a64::Address,a64::Address,a64::Address,std::uint64_t)>;
    void set_once_runner(OnceRunner runner);
    // Same-app committed metadata is copied by value across guest callback reentry.
    using ProgramHeaderLookup=std::function<std::optional<elf::ProgramHeaderInfo>(std::size_t)>;
    // Inclusive guest ticks charge nested callbacks to the enumeration budget.
    struct PhdrExecution {a64::ExecutionResult result;std::uint64_t ticks=0;};
    using PhdrRunner=std::function<PhdrExecution(a64::Address,std::array<std::uint64_t,3>,a64::Address,a64::Address,std::uint64_t)>;
    void set_program_header_lookup(ProgramHeaderLookup lookup);
    void set_phdr_runner(PhdrRunner runner);
    void set_comparator_runner(PhdrRunner runner);
    // Native Android Looper shares the owned three-argument callback ABI, not
    // the phdr enumeration state or its dispatch identity.
    using LooperRunner = PhdrRunner;
    void set_looper_runner(LooperRunner runner);
    a64::Fault invoke_looper(std::string_view name, a64::ServiceState &, bool full_frame) noexcept;
    // Trusted Activity lifecycle and captured pointer handoff. Queue admission
    // is distinct from the application's later finishEvent handled result.
    std::uint64_t create_input_queue();
    std::uint64_t current_input_queue() const noexcept;
    void retire_input_queue(std::uint64_t);
    bool enqueue_input_queue(std::uint64_t, const android::NativeActivityPointerInput &);
    bool enqueue_key_input_queue(std::uint64_t, const android::NativeActivityKeyInput &);
    std::optional<android::NativeActivityInputCompletion> peek_input_completion() const;
    bool commit_input_completion(std::uint64_t queue, std::uint64_t event) noexcept;
    a64::Fault invoke_input_queue(std::string_view, a64::ServiceState &, bool full_frame) noexcept;
    // App-owned C++ destructors run on the finalizing caller's live TLS/JNI scope.
    struct CxaExecution {a64::ExecutionResult result;std::uint64_t ticks=0;};
    using CxaRunner=std::function<CxaExecution(a64::Address,a64::Address,a64::Address,a64::Address,std::uint64_t)>;
    void set_cxa_runner(CxaRunner runner);
    // Trusted host shutdown boundary; registers[0] selects opaque DSO or zero/all.
    a64::Fault finalize_cxa(a64::ServiceState &) noexcept;
    using AddressLookup = std::function<std::optional<elf::AddressInfo>(a64::Address)>;
    // The owner keeps the lookup target alive for all calls; results contain guest metadata only.
    void set_address_lookup(AddressLookup lookup);
    void set_dynamic_linker(DynamicLinkCallbacks callbacks);
    struct ThreadBinding {std::uint32_t id; a64::Address tls,error;std::uint64_t initial_signal_mask=0;std::shared_ptr<a64::ThreadRegisterState> prepared_registers={};};
    class ExecutionBinding {
        friend class NativeThreads;
        std::uint32_t active=0;
        std::optional<ThreadBinding> external;
        std::shared_ptr<a64::ThreadRegisterState> owner;
    };
    // Trusted scheduler hooks prevalidate, then commit this reversible raw
    // owner selection without allocation or provider/priority calls.
    std::optional<ExecutionBinding> prepare_thread_execution(std::uint32_t id,const std::shared_ptr<a64::ThreadRegisterState> &owner) const noexcept;
    bool execution_binding_valid(const ExecutionBinding &) const noexcept;
    void exchange_execution_binding(ExecutionBinding &) noexcept;
    std::optional<ThreadBinding> exchange_thread_binding(std::optional<ThreadBinding> binding);
    void set_thread_runner(ThreadRunner runner);
    void set_thread_factory(ThreadFactory factory);
    void close_thread_tasks() noexcept;
    bool native_switch_safe() const noexcept;
    bool has_pending_threads() const noexcept;
    // Callback only requests a later audited CPU-loop yield, never switches in
    // noexcept service dispatch. False retains the existing synchronous path.
    void set_deferred_yield(std::function<bool()> request);
    void set_deferred_wait_admission(std::function<bool()> admit);
    void set_managed_priority_service(int baseline,host::PriorityService service);
    host::PriorityResult current_thread_priority(std::optional<std::int32_t> nice={});
    std::uint64_t signal_mask();
    std::uint64_t binding_signal_mask(const ThreadBinding&);
    a64::Address thread_pointer()const noexcept;
    bool is_main_native_thread()const noexcept;
    a64::Fault run_pending_threads(std::uint64_t instruction_budget=1000000) noexcept;
    const ServiceMetrics &metrics() const noexcept;
    std::string_view last_rejection() const noexcept;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::bionic
