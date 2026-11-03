#pragma once
#include "aether/a64/guest_memory.hpp"
#include "aether/common/process_exit.hpp"
#include <array>
#include <chrono>
#include <functional>
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
    thread_exit,
    alignment
};
std::string_view fault_name(Fault fault) noexcept;
using Vector = std::array<std::uint64_t, 2>;
enum class CpuExceptionKind {
    read_abort, write_abort, instruction_abort, undefined_encoding,
    breakpoint, data_alignment, stack_alignment, data_cache_abort, instruction_cache_abort
};
struct ArchitecturalState {
    std::array<std::uint64_t, 31> registers{};
    std::array<Vector, 32> vectors{};
    Address pc = 0, sp = 0;
    std::uint32_t pstate = 0, fpsr = 0, fpcr = 0;
};
struct CpuException {
    CpuExceptionKind kind = CpuExceptionKind::undefined_encoding;
    Address address = 0;
    std::uint32_t access_bytes = 0; // Zero means not an access or width unavailable.
    std::uint32_t subtype = 0; // Raw source metadata, not a fabricated signal/ESR.
    ArchitecturalState state;
    std::optional<MemoryFailure> memory_failure;
};
struct CpuFaultBoundary {
    Address tls = 0;
    std::uint64_t invocation = 0;
    Address stack_top = 0;
    std::uint64_t remaining_budget = 0;
    bool resource_metered=false;
    std::optional<std::uint64_t> instruction_limit;
    std::uint64_t operation_allowance(std::uint64_t profile_limit) const noexcept {
        const auto limit=resource_metered?instruction_limit:std::optional<std::uint64_t>{remaining_budget};
        return limit && *limit<profile_limit?*limit:profile_limit;
    }
};
enum class CpuFaultAction { unhandled, resume };
struct SignalEntry {
    ArchitecturalState state;
    Address frame = 0;
};
struct ExecutionResult {
    bool returned = false;
    Fault fault = Fault::none;
    Address fault_address = 0; // Fault site/data address, according to fault classification.
    Address pc = 0; // Stopped CPU snapshot; may be post-boundary, not architectural ELR (ADR0313).
    std::uint32_t detail = 0;
    std::array<std::uint64_t, 31> registers{};
    std::array<Vector, 32> vectors{};
    std::uint64_t sp = 0;
    std::uint32_t pstate = 0;
    std::uint32_t fpsr = 0;
    std::uint32_t fpcr = 0;
    // Genuine first CPU exception only. No signal delivery or resume is implied.
    std::optional<CpuException> cpu_exception;
    bool signal_return = false;
};
struct Metrics {
    std::uint64_t compiled_blocks = 0, emitted_bytes = 0, compile_nanoseconds = 0;
    std::uint64_t block_lookups = 0, cache_hits = 0, cache_invalidations = 0;
    std::uint64_t execution_nanoseconds = 0, guest_ticks = 0, host_calls = 0;
    std::uint64_t memory_reads = 0, memory_writes = 0, interpreter_fallbacks = 0, faults = 0;
    std::uint64_t rx_checks = 0, rx_failures = 0, last_code_fingerprint = 0;
    Address last_compiled_pc = 0;
    std::uint64_t deferred_services = 0, nested_calls = 0, maximum_call_depth = 0;
    std::uint64_t scheduling_yields = 0, data_cache_cleans = 0, instruction_cache_invalidations = 0;
    std::uint64_t interpreted_lse_instructions = 0;
};
struct ServiceState;
struct DeferredServiceResult { Fault fault = Fault::none; bool completed = false; };
// Host-owned operation state. Readiness is only a hint; resume validates current
// resources and performs the next step without replaying the original service.
class DeferredService {
  public:
    virtual ~DeferredService() = default;
    virtual bool ready() const noexcept = 0;
    virtual std::optional<std::chrono::steady_clock::time_point> deadline() const noexcept = 0;
    virtual DeferredServiceResult resume(ServiceState &) noexcept = 0;
};
struct ServiceState {
    std::array<std::uint64_t, 31> registers{};
    std::array<Vector, 32> vectors{};
    Address stack_pointer = 0;
    // Trusted live-call identity and initial stack ceiling, never guest-supplied.
    std::uint64_t invocation = 0;
    Address stack_top = 0;
    Address pc = 0;
    std::uint32_t pstate = 0, fpsr = 0, fpcr = 0;
    Address trusted_tls = 0;
    std::uint64_t remaining_budget = 0;
    // Explicit output-only signal/context transfer, authoritative over legacy fields.
    std::optional<ArchitecturalState> resume;
    std::shared_ptr<DeferredService> deferred;
    bool resource_metered=false;
    std::optional<std::uint64_t> instruction_limit;
    std::uint64_t operation_allowance(std::uint64_t profile_limit) const noexcept {
        const auto limit=resource_metered?instruction_limit:std::optional<std::uint64_t>{remaining_budget};
        return limit && *limit<profile_limit?*limit:profile_limit;
    }
};
// Host-owned architectural data, separate from trusted service/thread identity.
// Actual owner records retain this state; each active CPU frame pins it.
struct ThreadRegisterState {
    std::uint64_t tpidr_el0 = 0, tpidrro_el0 = 0;
};
// Traps carry guest values only. Implementations must not throw through generated frames.
class GuestServices {
  public:
    virtual ~GuestServices() = default;
    // Called only at validated call entry outside generated frames. Owning
    // providers reject an invalid trusted binding rather than return a fallback.
    virtual std::shared_ptr<ThreadRegisterState> thread_register_state(Address) const { return {}; }
    virtual CpuFaultAction synchronous_fault(const CpuException &, ArchitecturalState &,
                                            const CpuFaultBoundary &) noexcept { return CpuFaultAction::unhandled; }
    virtual bool pending_signal_entry(const SignalEntry &, Address, std::uint64_t) const noexcept { return false; }
    // Sticky terminal value for this logical TLS owner, including nested callbacks.
    virtual std::optional<std::uint64_t> thread_exit_value(Address) const noexcept {return {};}
    // Event polling may halt generated code; delivery runs only after Run returns.
    virtual bool event_pending() noexcept {return false;}
    virtual Fault checkpoint(ServiceState &) noexcept {return Fault::none;}
    virtual Fault invoke(std::uint32_t service, Address instruction,
                         std::array<std::uint64_t, 31> &registers) noexcept = 0;
    virtual Fault invoke_frame(std::uint32_t service, Address instruction, ServiceState &state) noexcept {
        return invoke(service, instruction, state.registers);
    }
};
// Single owner thread; memory and app context must outlive this CPU. No host pointers in guest registers.
class GuestCpu {
  public:
    struct ExecutionBoundary {
        enum class Reason { entry, checkpoint, service, quantum, before_service, before_checkpoint, before_fault, after_fault, deferred_service };
        Reason reason;
        std::uint64_t ticks,remaining,slice_remaining;
        bool yield_requested,can_yield;
        bool resource_metered=false;
        std::optional<std::uint64_t> retained;
        std::optional<std::uint64_t> operation_remaining;
    };
    // Trusted host callback outside generated execution. It caps allowance at
    // every normal call depth, including handlers. Only can_yield authorizes a
    // scheduler/cancellation checkpoint outside ancestral noexcept dispatch.
    using ExecutionBoundaryCallback=std::function<std::uint64_t(const ExecutionBoundary &)>;
    struct ResourceBudget {
        std::optional<std::uint64_t> retained;
        std::uint64_t quantum_remaining=0;
    };
    // The trusted caller checks its original host resource admission and meters
    // actual inclusive work. An absent instruction ceiling is not a fresh
    // numeric allowance. The soft quantum may resume the same retained stack.
    using ResourceBoundaryCallback=std::function<ResourceBudget(const ExecutionBoundary &)>;
    // Called outside noexcept service dispatch with the actual frame retained.
    // May park/cancel; readiness and deadline never authorize guest replay.
    using ExecutionWaitCallback=std::function<void(const std::shared_ptr<DeferredService> &)>;
    // Host-owned inactive execution storage. It grants no guest entry or thread
    // identity; only its creating CPU may exchange it on the owning OS thread.
    class ExecutionContext final {
      public:
        ~ExecutionContext();
        ExecutionContext(const ExecutionContext &) = delete;
        ExecutionContext &operator=(const ExecutionContext &) = delete;
      private:
        struct State;
        explicit ExecutionContext(std::unique_ptr<State>) noexcept;
        std::unique_ptr<State> state_;
        friend class GuestCpu;
    };
    static constexpr Address return_trampoline = 0x10000;
    static constexpr Address signal_restorer = 0x10010;
    GuestCpu(GuestMemory &memory, const AppContext &app, GuestServices *services = nullptr);
    ~GuestCpu();
    GuestCpu(const GuestCpu &) = delete;
    GuestCpu &operator=(const GuestCpu &) = delete;
    ExecutionResult call(Address entry, std::span<const std::uint64_t> arguments, Address stack_top,
                         std::uint64_t instruction_budget = 1'000'000,
                         std::span<const Vector> floating_arguments = {}, std::optional<Address> thread_pointer = {},
                         const SignalEntry *signal_entry = nullptr);
    ExecutionResult call_resource_metered(Address entry,std::span<const std::uint64_t> arguments,Address stack_top,
                         std::span<const Vector> floating_arguments={},std::optional<Address> thread_pointer={},
                         const SignalEntry *signal_entry=nullptr,std::optional<std::uint64_t> operation_limit={});
    // operation_limit is an independent finite service/campaign cap, inclusive
    // of nested native calls; it never replaces or renews resource admission.
    // Select the trusted default TLS identity while idle. This does not rewrite
    // an owning provider's saved architectural register values.
    void set_thread_pointer(Address address);
    // Preparation may allocate on the owner outside generated execution,
    // including a deferred service; it never captures or changes its live state.
    // The legacy bool exchange admits only two idle execution states. Live
    // coordinated commit has a separate, explicitly guarded interface below.
    std::unique_ptr<ExecutionContext> prepare_execution_context();
    std::unique_ptr<ExecutionContext> prepare_execution_context(ExecutionBoundaryCallback,std::uint64_t quantum);
    std::unique_ptr<ExecutionContext> prepare_execution_context(ExecutionBoundaryCallback,std::uint64_t quantum,ExecutionWaitCallback);
    std::unique_ptr<ExecutionContext> prepare_resource_execution_context(ResourceBoundaryCallback,
                         std::uint64_t quantum=10000,std::optional<std::uint64_t> hard_instruction_ceiling={});
    bool exchange_execution_context(ExecutionContext &) noexcept;
    // Preflight both execution states before coordinated provider/JNI hooks.
    // Live admission is limited to a normal root boundary callback or a deferred
    // service root; providers must independently exclude signal/poll ancestors.
    bool can_exchange_execution_context(const ExecutionContext &) const noexcept;
    void commit_execution_context(ExecutionContext &) noexcept;
    // Install the next hard CPU-tick grant on an inactive configured execution.
    // It changes neither the fatal allowance nor the cooperative quantum.
    bool set_execution_slice_allowance(ExecutionContext &,std::uint64_t) noexcept;
    // A trusted active boundary may reduce the current transient work grant.
    // Fatal allowance and cooperative quantum remain independent of this cap.
    bool limit_execution_slice(std::uint64_t cap) noexcept;
    bool execution_idle() const noexcept;
    // Trusted physical-owner maintenance only after all active CPU frames have
    // unwound. Refuses service, fault, deferred-wait and parked boundaries.
    // Architectural state and execution/accounting capsules remain unchanged.
    bool trim_translation_cache();
    // Trusted independent-child progress during an ordinary root service only.
    // The caller also authenticates provider ancestors and restores this exact
    // execution before debiting actual child ticks. Idle is not a live grant.
    std::optional<std::uint64_t> execution_progress_allowance() const noexcept;
    // No mutation on refusal. External ticks consume this caller's fatal/hard
    // allowance without becoming its own CPU ticks or aggregate metrics.
    bool debit_external_progress(std::uint64_t ticks) noexcept;
    // Recap restored parent work after independent runtime settlement. This
    // only decreases allowances at the same registered root-service boundary;
    // runtime work is never recorded as fabricated native/external CPU ticks.
    // The authenticated live service frame receives the same reduced headroom
    // before it can construct a nested signal/callback boundary.
    // Recapped legacy calls also enforce the hard translated-block tail bound;
    // nested calls inherit it, and a fresh unrelated root starts without it.
    bool limit_external_progress(std::uint64_t retained,std::uint64_t work) noexcept;
    // A registered normal root service may defer a yield until its result and
    // context have committed. This never switches or throws through a service.
    bool request_execution_yield() noexcept;
    // Cumulative ticks of the selected execution, including its nested calls.
    // Aggregate metrics().guest_ticks continues to include every execution.
    std::uint64_t active_ticks() const noexcept;
    // Trusted host boundary: preserve the canonical process terminal cause.
    void process_checkpoint() const;
    // Trusted diagnostic annotation; cannot create or change a terminal cause.
    void retain_initializer_context(const GuestInitializerContext &context) noexcept;
    const Metrics &metrics() const noexcept;
    std::uint64_t counter_frequency() const noexcept;

  private:
    ExecutionResult call_impl(Address,std::span<const std::uint64_t>,Address,std::uint64_t,
                             std::span<const Vector>,std::optional<Address>,const SignalEntry *,bool,std::optional<std::uint64_t>);
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::a64
