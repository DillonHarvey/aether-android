#pragma once
#include "aether/a64/guest_memory.hpp"
#include "aether/common/process_exit.hpp"
#include <array>
#include <memory>
#include <optional>
#include <span>
#include <string_view>

namespace aether::a64 {
struct AppContext {
    std::uint64_t instance_id = 0;
    bool monotonic_time_allowed = false;
    bool graphics_allowed = false;
    bool audio_playback_allowed = false;
    std::shared_ptr<ProcessState> process_state=std::make_shared<ProcessState>();
};
enum class Fault {
    none,
    read,
    write,
    execute,
    unsupported_instruction,
    unsupported_service,
    capability_denied,
    windows_service,
    budget,
    invalid_call,
    jit_protection,
    nesting_limit,
    process_exit,
    thread_exit
};
std::string_view fault_name(Fault fault) noexcept;
using Vector = std::array<std::uint64_t, 2>;
struct ExecutionResult {
    bool returned = false;
    Fault fault = Fault::none;
    Address fault_address = 0;
    Address pc = 0;
    std::uint32_t detail = 0;
    std::array<std::uint64_t, 31> registers{};
    std::array<Vector, 32> vectors{};
    std::uint64_t sp = 0;
    std::uint32_t pstate = 0;
    std::uint32_t fpsr = 0;
    std::uint32_t fpcr = 0;
};
struct Metrics {
    std::uint64_t compiled_blocks = 0, emitted_bytes = 0, compile_nanoseconds = 0;
    std::uint64_t block_lookups = 0, cache_hits = 0, cache_invalidations = 0;
    std::uint64_t execution_nanoseconds = 0, guest_ticks = 0, host_calls = 0;
    std::uint64_t memory_reads = 0, memory_writes = 0, interpreter_fallbacks = 0, faults = 0;
    std::uint64_t rx_checks = 0, rx_failures = 0, last_code_fingerprint = 0;
    Address last_compiled_pc = 0;
    std::uint64_t deferred_services = 0, nested_calls = 0, maximum_call_depth = 0;
};
struct ServiceState {
    std::array<std::uint64_t, 31> registers{};
    std::array<Vector, 32> vectors{};
    Address stack_pointer = 0;
    // Trusted live-call identity and initial stack ceiling, never guest-supplied.
    std::uint64_t invocation = 0;
    Address stack_top = 0;
};
// Traps carry guest values only. Implementations must not throw through generated frames.
class GuestServices {
  public:
    virtual ~GuestServices() = default;
    // Sticky terminal value for this logical TLS owner, including nested callbacks.
    virtual std::optional<std::uint64_t> thread_exit_value(Address) const noexcept {return {};}
    virtual Fault invoke(std::uint32_t service, Address instruction,
                         std::array<std::uint64_t, 31> &registers) noexcept = 0;
    virtual Fault invoke_frame(std::uint32_t service, Address instruction, ServiceState &state) noexcept {
        return invoke(service, instruction, state.registers);
    }
};
// Single owner thread; memory and app context must outlive this CPU. No host pointers in guest registers.
class GuestCpu {
  public:
    static constexpr Address return_trampoline = 0x10000;
    GuestCpu(GuestMemory &memory, const AppContext &app, GuestServices *services = nullptr);
    ~GuestCpu();
    GuestCpu(const GuestCpu &) = delete;
    GuestCpu &operator=(const GuestCpu &) = delete;
    ExecutionResult call(Address entry, std::span<const std::uint64_t> arguments, Address stack_top,
                         std::uint64_t instruction_budget = 1'000'000,
                         std::span<const Vector> floating_arguments = {}, std::optional<Address> thread_pointer = {});
    // Bind an owned logical TLS block before any native call.
    void set_thread_pointer(Address address);
    const Metrics &metrics() const noexcept;
    std::uint64_t counter_frequency() const noexcept;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::a64
