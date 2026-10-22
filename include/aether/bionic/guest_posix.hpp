#pragma once
#include "aether/elf/guest_loader.hpp"
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
    void request_thread_exit(std::uint64_t value) noexcept;
    struct ThreadExecution {a64::ExecutionResult result;std::uint64_t ticks=0;};
    using ThreadRunner=std::function<ThreadExecution(a64::Address,a64::Address,a64::Address,a64::Address,std::uint64_t)>;
    using SignalRunner=std::function<a64::ExecutionResult(a64::Address,std::uint32_t,a64::Address,a64::Address)>;
    void set_signal_runner(SignalRunner runner);
    struct ThreadBinding {std::uint32_t id; a64::Address tls,error;std::uint64_t initial_signal_mask=0;};
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
