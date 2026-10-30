#pragma once
#include "aether/elf/guest_loader.hpp"
#include "aether/bionic/dynamic_linker.hpp"
#include "aether/host/file_service.hpp"
#include "aether/host/time_service.hpp"
#include "aether/host/native_log.hpp"
#include "aether/host/thread_priority.hpp"
#include <functional>

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
    void request_thread_exit(std::uint64_t value) noexcept;
    struct ThreadExecution {a64::ExecutionResult result;std::uint64_t ticks=0;bool finalization_failed=false;};
    // The trusted runner finalizes orderly return/exit with finish_current_thread
    // before leaving its original TLS/JNI scope, and reports finalization failure.
    using ThreadRunner=std::function<ThreadExecution(a64::Address,a64::Address,a64::Address,a64::Address,std::uint64_t)>;
    using DestructorRunner=std::function<ThreadExecution(a64::Address,a64::Address,std::uint64_t)>;
    // Trusted terminal-thread phase, while its original TLS/JNI context is alive.
    ThreadExecution finish_current_thread(const DestructorRunner &,std::uint64_t budget);
    void discard_thread(std::uint32_t id,a64::Address tls) noexcept;
    using SignalRunner=std::function<a64::ExecutionResult(a64::Address,std::uint32_t,a64::Address,a64::Address)>;
    void set_signal_runner(SignalRunner runner);
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
    std::optional<ThreadBinding> exchange_thread_binding(std::optional<ThreadBinding> binding);
    void set_thread_runner(ThreadRunner runner);
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
