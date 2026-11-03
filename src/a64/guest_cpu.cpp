#include "aether/a64/guest_cpu.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <exception>
#include <dynarmic/interface/A64/a64.h>
#include <dynarmic/interface/A64/config.h>
#include <dynarmic/interface/exclusive_monitor.h>
#include <dynarmic/interface/halt_reason.h>
#include <limits>
#include <type_traits>
#include <utility>
#include <windows.h>

namespace aether::a64 {
namespace {
// Match CTR_EL0's 16-word minimum cache lines. Guest bytes are ordinary,
// coherent host data; translated x86 code has its own checked W^X cache.
constexpr std::size_t guest_cache_line_size = 64;
// Pinned frontend/A64/translate/a64_translate.cpp bounds each translated block
// to 256 one-tick instructions. Bulk runs reserve the worst final-block tail.
constexpr std::uint64_t maximum_translated_block_ticks=256;
enum class ScalarAtomic { compare, add, clear, exclusive_or, set, swap };
struct ScalarLse {
    ScalarAtomic operation;
    unsigned bytes, source, base, destination;
};
std::optional<ScalarLse> decode_scalar_lse(std::uint32_t instruction) noexcept {
    // Encoding reference: disabled ARMv8.1 patterns in the pinned Dynarmic
    // frontend/A64/decoder/a64.inc. This is an Aether-owned scalar fallback,
    // not a claim that the vendor JIT translates the optional LSE extension.
    const auto bytes = 1u << (instruction >> 30);
    const auto source = (instruction >> 16) & 31u;
    const auto base = (instruction >> 5) & 31u;
    const auto destination = instruction & 31u;
    if ((instruction & 0x3fa07c00u) == 0x08a07c00u)
        return ScalarLse{ScalarAtomic::compare, bytes, source, base, destination};
    if ((instruction & 0x3f200c00u) != 0x38200000u)
        return {};
    ScalarAtomic operation;
    switch ((instruction >> 12) & 15u) {
    case 0: operation = ScalarAtomic::add; break;
    case 1: operation = ScalarAtomic::clear; break;
    case 2: operation = ScalarAtomic::exclusive_or; break;
    case 3: operation = ScalarAtomic::set; break;
    case 8: operation = ScalarAtomic::swap; break;
    default: return {}; // No min/max, LDAPR, CASP, or reserved encodings.
    }
    return ScalarLse{operation, bytes, source, base, destination};
}
struct ScalarLseFallback { Address pc; std::uint32_t instruction; ScalarLse decoded; };
std::atomic<std::uint64_t> invocation_sequence{1};
std::atomic<std::uint64_t> execution_sequence{1};
std::uint64_t next_execution() noexcept {
    auto value=execution_sequence.load(std::memory_order_relaxed);
    while(value!=UINT64_MAX){if(execution_sequence.compare_exchange_weak(value,value+1,std::memory_order_relaxed))return value;}
    return 0;
}
std::uint64_t next_invocation() noexcept {
    auto value=invocation_sequence.load(std::memory_order_relaxed);
    while(value!=UINT64_MAX){if(invocation_sequence.compare_exchange_weak(value,value+1,std::memory_order_relaxed))return value;}
    return 0;
}
bool representable_user_state(const ArchitecturalState &state) noexcept {
    // Reserved FP bits follow the existing MSR/SetFpcr/SetFpsr normalization.
    // Only NZCV is represented in this baseline PSTATE, never EL/privilege bits.
    return state.pc < GuestMemory::address_limit && state.sp <= GuestMemory::address_limit &&
        !(state.pstate & ~std::uint32_t{0xf0000000});
}
struct CpuOwnerIdentity { std::atomic<std::size_t> prepared_contexts{0}; };
// Stable-address value storage: Dynarmic's configured TLS pointers continue to
// point at the active Impl fields when these values are exchanged with a capsule.
struct CpuExecutionState {
    ArchitecturalState architectural;
    ExecutionResult result;
    bool cpu_exception_pc_pending = false;
    std::uint64_t remaining = 0, execution_ticks = 0, execution_id = 0;
    bool strict_budget = false; // A recapped legacy call inherits the same hard block-tail bound as configured tasks.
    // Inclusive child cost is distinct from this execution's native CPU ticks.
    // Keep it monotonic across calls and exchange it with its owning capsule.
    std::uint64_t external_tick_debits = 0;
    std::uint64_t tpidr = 0, tpidr_read_only = 0, default_tpidr = 0;
    std::shared_ptr<ThreadRegisterState> default_registers = std::make_shared<ThreadRegisterState>();
    std::shared_ptr<ThreadRegisterState> active_registers;
    Address active_tls = 0;
    bool service_pending = false, dispatching_service = false, dispatching_fault = false;
    std::optional<SignalEntry> active_signal_entry;
    bool yield_pending = false;
    std::optional<Address> instruction_cache_pending;
    std::optional<ScalarLseFallback> scalar_lse_pending;
    std::uint32_t pending_service = 0, call_depth = 0;
    Address service_instruction = 0;
    std::uint64_t active_invocation = 0;
    const void *saved_frame_chain = nullptr; // Actual C++ SavedFrame addresses, never copied frames.
    std::shared_ptr<const GuestCpu::ExecutionBoundaryCallback> boundary_callback;
    std::shared_ptr<const GuestCpu::ResourceBoundaryCallback> resource_callback;
    bool resource_metered=false;
    std::optional<std::uint64_t> resource_remaining;
    std::optional<std::uint64_t> operation_remaining;
    std::shared_ptr<const GuestCpu::ExecutionWaitCallback> wait_callback;
    ServiceState *registered_service_frame = nullptr; // Actual ordinary invoke_frame stack object.
    const void *deferred_service_frame = nullptr; // Actual fiber-local ServiceState, never copied into another stack.
    bool deferred_wait_active = false;
    std::uint64_t quantum_ticks = 0,quantum_remaining = 0,slice_remaining = UINT64_MAX;
    bool boundary_active = false,boundary_can_yield = false,registered_service_dispatch = false,execution_yield_requested = false;
    bool idle() const noexcept {
        return !call_depth && !saved_frame_chain && !service_pending && !dispatching_service && !dispatching_fault &&
            !active_signal_entry && !yield_pending && !instruction_cache_pending && !scalar_lse_pending &&
            !cpu_exception_pc_pending && !boundary_active && !boundary_can_yield && !registered_service_dispatch && !execution_yield_requested &&
            !registered_service_frame && !deferred_service_frame && !deferred_wait_active && !strict_budget;
    }
    bool exchangeable() const noexcept {
        if(idle())return true;
        if(deferred_wait_active && (!deferred_service_frame || !boundary_active || !boundary_can_yield))return false;
        if(call_depth!=1 || !saved_frame_chain || !active_registers || !active_invocation || active_signal_entry ||
           dispatching_fault || service_pending || yield_pending || instruction_cache_pending || scalar_lse_pending ||
           cpu_exception_pc_pending || result.cpu_exception || result.fault!=Fault::none || result.returned)return false;
        return (boundary_active && boundary_can_yield && !dispatching_service && !registered_service_dispatch && !registered_service_frame) ||
            (!boundary_active && !boundary_can_yield && dispatching_service && registered_service_dispatch && registered_service_frame);
    }
};
static_assert(std::is_nothrow_swappable_v<CpuExecutionState>);
}
struct GuestCpu::ExecutionContext::State {
    std::shared_ptr<CpuOwnerIdentity> owner;
    CpuExecutionState execution;
    bool charged=false;
    ~State() {
        if(!execution.idle())std::terminate(); // A live parked C++ stack must unwind before its capsule is retired.
        if(charged)owner->prepared_contexts.fetch_sub(1,std::memory_order_relaxed);
    }
};
GuestCpu::ExecutionContext::ExecutionContext(std::unique_ptr<State> state) noexcept : state_(std::move(state)) {}
GuestCpu::ExecutionContext::~ExecutionContext() = default;
std::string_view fault_name(Fault fault) noexcept {
    switch (fault) {
    case Fault::none:
        return "none";
    case Fault::read:
        return "AETHER_GUEST_READ_FAULT";
    case Fault::write:
        return "AETHER_GUEST_WRITE_FAULT";
    case Fault::execute:
        return "AETHER_GUEST_EXECUTE_FAULT";
    case Fault::unsupported_instruction:
        return "AETHER_A64_UNSUPPORTED_INSTRUCTION";
    case Fault::unsupported_service:
        return "AETHER_GUEST_UNSUPPORTED_SERVICE";
    case Fault::capability_denied:
        return "AETHER_GUEST_CAPABILITY_DENIED";
    case Fault::windows_service:
        return "AETHER_HOST_TIME_FAILED";
    case Fault::budget:
        return "AETHER_GUEST_BUDGET_EXHAUSTED";
    case Fault::invalid_call:
        return "AETHER_GUEST_INVALID_CALL";
    case Fault::jit_protection:
        return "AETHER_JIT_PROTECTION_FAILED";
    case Fault::nesting_limit:
        return "AETHER_GUEST_CALL_DEPTH";
    case Fault::process_exit:
        return "AETHER_GUEST_PROCESS_EXIT";
    case Fault::thread_exit:
        return "AETHER_GUEST_THREAD_EXIT";
    case Fault::alignment:
        return "AETHER_GUEST_ALIGNMENT_FAULT";
    }
    return "AETHER_GUEST_UNKNOWN_FAULT";
}
struct GuestCpu::Impl final : Dynarmic::A64::UserCallbacks, CpuExecutionState {
    GuestMemory &memory;
    const AppContext &app;
    GuestServices *services;
    Metrics stats;
    // Physical CPU custody, not execution-capsule state: inactive fibers can
    // still own real SavedFrames while another selected execution is idle.
    std::uint64_t live_saved_frames = 0;
    Dynarmic::ExclusiveMonitor monitor{1};
    std::unique_ptr<Dynarmic::A64::Jit> jit;
    std::uint64_t code_generation = 0, frequency = 0;
    const DWORD owner_thread = GetCurrentThreadId();
    const std::shared_ptr<CpuOwnerIdentity> execution_owner = std::make_shared<CpuOwnerIdentity>();

    Impl(GuestMemory &memory_, const AppContext &app_, GuestServices *services_)
        : memory(memory_), app(app_), services(services_) {
        if(!app.process_state)throw GuestError("AETHER_GUEST_CONTEXT","Guest process state is required");
        execution_id=next_execution();
        if(!execution_id)throw GuestError("AETHER_GUEST_CONTEXT","Execution identity range exhausted");
        LARGE_INTEGER f{};
        if (!QueryPerformanceFrequency(&f) || f.QuadPart <= 0 ||
            f.QuadPart > std::numeric_limits<std::uint32_t>::max())
            throw GuestError("AETHER_HOST_TIME_FAILED", "Windows counter frequency is unavailable");
        frequency = static_cast<std::uint64_t>(f.QuadPart);
        // This reserved page contains SVC #65535; it is never host executable.
        memory.map(return_trampoline, GuestMemory::page_size, read_write);
        constexpr std::array<std::uint8_t, 4> trap{0xe1, 0xff, 0x1f, 0xd4};
        if (!memory.write(return_trampoline, trap))
            throw GuestError("AETHER_GUEST_MAPPING", "Cannot initialize return trampoline");
        constexpr std::array<std::uint8_t, 8> restorer{0x68, 0x11, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4};
        if (!memory.write(signal_restorer, restorer))
            throw GuestError("AETHER_GUEST_MAPPING", "Cannot initialize signal restorer");
        memory.protect(return_trampoline, read_execute);
        Dynarmic::A64::UserConfig config{};
        config.callbacks = this;
        config.global_monitor = &monitor;
        config.tpidr_el0 = &tpidr;
        config.tpidrro_el0 = &tpidr_read_only;
        config.code_cache_size = 32 * 1024 * 1024;
        config.check_halt_on_memory_access = true;
        config.hook_data_cache_operations = true;
        config.hook_hint_instructions = true;
        config.ctr_el0 = 0x8444c004;
        // DC ZVA has no implementation here. Report it prohibited instead of
        // advertising a usable instruction which the hook would reject.
        config.dczid_el0 = 0x14;
        config.cntfrq_el0 = static_cast<std::uint32_t>(frequency);
        // Keep safe IR optimizations, but observe every dispatched block in this
        // correctness baseline. No linking, return predictor, or fast dispatcher.
        config.optimizations = Dynarmic::OptimizationFlag::ConstProp | Dynarmic::OptimizationFlag::MiscIROpt;
        jit = std::make_unique<Dynarmic::A64::Jit>(config);
        code_generation = memory.code_generation();
    }
    void stop(Fault fault, Address address = 0, std::uint32_t detail = 0) noexcept {
        if (result.fault == Fault::none) {
            result.fault = fault;
            result.fault_address = address;
            result.detail = detail;
            if(fault!=Fault::process_exit && fault!=Fault::thread_exit)++stats.faults;
        }
        auto reason = Dynarmic::HaltReason::UserDefined1;
        if (result.fault == Fault::read || result.fault == Fault::write || result.fault == Fault::alignment)
            reason |= Dynarmic::HaltReason::MemoryAbort;
        // check_halt_on_memory_access checks this specific bit immediately
        // after each callback. It restores that access's instruction PC and
        // returns before a failed load/result or base writeback can commit.
        // A generic user halt alone is only observed at a later block boundary.
        jit->HaltExecution(reason);
    }
    void stop_cpu(CpuExceptionKind kind, Fault fault, Address address, std::uint32_t bytes,
                  std::uint32_t subtype = 0, std::optional<Address> pc = {},
                  std::optional<MemoryFailure> failure = {}) noexcept {
        if (result.fault == Fault::none) {
            CpuException exception;
            exception.kind = kind;
            exception.address = address;
            exception.access_bytes = bytes;
            exception.subtype = subtype;
            exception.state.pc = pc.value_or(0);
            exception.memory_failure = failure;
            result.cpu_exception = exception;
            // Translated memory callbacks do not yet have a materialized PC.
            // Their MemoryAbort guard supplies it before Run returns.
            cpu_exception_pc_pending = !pc.has_value();
        }
        stop(fault, address, subtype);
    }
    bool configured_boundary() const noexcept {
        return resource_metered?bool(resource_callback):bool(boundary_callback);
    }
    std::optional<std::uint64_t> instruction_limit() const noexcept {
        if(!resource_metered)return remaining;
        auto limit=resource_remaining;
        if(operation_remaining)limit=limit?std::min(*limit,*operation_remaining):*operation_remaining;
        return limit;
    }
    std::uint64_t service_allowance() const noexcept {
        if(!resource_metered)return remaining;
        const auto quantum=quantum_remaining;
        auto available=resource_remaining?(std::min)(*resource_remaining,quantum):quantum;
        if(operation_remaining)available=std::min(available,*operation_remaining);
        return available;
    }
    bool resource_exhausted() const noexcept {
        return (resource_remaining && !*resource_remaining) || (operation_remaining && !*operation_remaining);
    }
    ServiceState service_frame(Address stack_top) const {
        ServiceState state{jit->GetRegisters(), jit->GetVectors(), jit->GetSP(), active_invocation, stack_top};
        state.pc = jit->GetPC();
        state.pstate = jit->GetPstate();
        state.fpsr = jit->GetFpsr();
        state.fpcr = jit->GetFpcr();
        state.trusted_tls = active_tls;
        state.remaining_budget = service_allowance();
        state.resource_metered=resource_metered;
        state.instruction_limit=instruction_limit();
        return state;
    }
    bool current_owner(const std::shared_ptr<ThreadRegisterState> &expected, Address tls,
                       std::uint64_t invocation) const noexcept {
        if (active_registers != expected || active_tls != tls || active_invocation != invocation) return false;
        try {
            const auto owned = services ? services->thread_register_state(tls) : nullptr;
            return !owned || owned == expected;
        } catch (...) {
            return false;
        }
    }
    bool commit_context(const ArchitecturalState &state) {
        if (!representable_user_state(state)) return false;
        jit->SetRegisters(state.registers);
        jit->SetVectors(state.vectors);
        jit->SetSP(state.sp);
        jit->SetPC(state.pc);
        jit->SetPstate(state.pstate);
        jit->SetFpcr(state.fpcr);
        jit->SetFpsr(state.fpsr);
        jit->ClearExclusiveState();
        monitor.Clear();
        return true;
    }
    bool execution_boundary(GuestCpu::ExecutionBoundary::Reason reason,bool permit_yield=true) {
        const bool fault_accounting=reason==GuestCpu::ExecutionBoundary::Reason::before_fault && !permit_yield;
        // A final SVC instruction may consume the last strict tick before its
        // host effect is dispatched. No callback is required to enforce this
        // exhausted allowance; retain an original synchronous fault instead.
        if(!resource_metered && strict_budget && !remaining){
            if(!fault_accounting)stop(Fault::budget,jit->GetPC());
            return false;
        }
        if(!configured_boundary() || !call_depth || !saved_frame_chain || dispatching_service || dispatching_fault ||
           service_pending || yield_pending || instruction_cache_pending || scalar_lse_pending ||
           cpu_exception_pc_pending || (!fault_accounting && (result.cpu_exception || result.fault!=Fault::none)) || result.returned)return true;
        if(boundary_active || boundary_can_yield)std::terminate();
        // A simultaneous quantum expiry is not permission to yield/refill an
        // exhausted fatal allowance. Its final tail is billed by the caller.
        if(resource_metered?resource_exhausted():!remaining){if(!fault_accounting)stop(Fault::budget,jit->GetPC());return false;}
        const auto callback=boundary_callback; // Prepared ownership survives a value exchange while this call is parked.
        const auto resource=resource_callback;
        const auto expected_owner=active_registers;
        const auto expected_tls=active_tls,expected_invocation=active_invocation;
        const bool can_yield=permit_yield && call_depth==1 && !active_signal_entry;
        const bool requested=can_yield && (execution_yield_requested ||
            (!resource_metered && !slice_remaining) || (quantum_ticks && !quantum_remaining));
        if(can_yield){
            execution_yield_requested=false;
            if(requested && !resource_metered)quantum_remaining=quantum_ticks; // Never renew aggregate admission.
        }
        boundary_active=true;
        boundary_can_yield=can_yield;
        struct BoundaryEnd {
            Impl &p;std::uint64_t execution;const void *chain;bool can_yield;
            ~BoundaryEnd(){
                if(p.execution_id!=execution || p.saved_frame_chain!=chain || !p.boundary_active ||
                   p.boundary_can_yield!=can_yield)std::terminate();
                p.boundary_active=p.boundary_can_yield=false;
            }
        } end{*this,execution_id,saved_frame_chain,can_yield};
        const GuestCpu::ExecutionBoundary boundary{reason,execution_ticks,
            resource_metered?resource_remaining.value_or(0):remaining,
            resource_metered?quantum_remaining:slice_remaining,requested,can_yield,resource_metered,
            resource_metered?resource_remaining:std::optional<std::uint64_t>{remaining},operation_remaining};
        std::uint64_t cap=0;
        if(resource_metered){
            const auto budget=(*resource)(boundary);
            if(budget.retained)resource_remaining=resource_remaining?
                std::min(*resource_remaining,*budget.retained):*budget.retained;
            // A nested/provider boundary may defer a soft scheduling yield.
            // Poll the same admitted execution again; never mint a hard grant.
            quantum_remaining=budget.quantum_remaining?std::min(budget.quantum_remaining,quantum_ticks):quantum_ticks;
        }else cap=(*callback)(boundary); // Nested finite callbacks account only.
        if(execution_id!=end.execution || saved_frame_chain!=end.chain || !boundary_active || boundary_can_yield!=can_yield)std::terminate();
        if(!current_owner(expected_owner,expected_tls,expected_invocation)){
            if(!fault_accounting)stop(Fault::invalid_call,jit->GetPC());
            return false;
        }
        if(resource_metered){
            if(resource_exhausted()){if(!fault_accounting)stop(Fault::budget,jit->GetPC());return false;}
            return true;
        }
        remaining=(std::min)(remaining,cap);
        if(!remaining || (permit_yield && !slice_remaining)){
            if(!fault_accounting)stop(Fault::budget,jit->GetPC());
            return false;
        }
        if(fault_accounting && !slice_remaining)return false; // Keep the original fault; no grant exists for its handler.
        return true;
    }
    Fault complete_deferred_service(ServiceState &state,const std::shared_ptr<ThreadRegisterState> &owner,
                                    Address tls,std::uint64_t invocation,Address stack_top,
                                    std::uint64_t execution,const void *chain) {
        if(!boundary_callback || !wait_callback || call_depth!=1 || active_signal_entry || dispatching_service ||
           dispatching_fault || deferred_service_frame || deferred_wait_active)return Fault::unsupported_service;
        if(!state.deferred || state.resume)return Fault::invalid_call;
        const auto operation=state.deferred;
        const auto resource_policy=state.resource_metered;
        const auto instruction_policy=state.instruction_limit;
        deferred_service_frame=&state;
        struct DeferredEnd {
            Impl &p;const ServiceState *frame;std::uint64_t execution;const void *chain;
            ~DeferredEnd(){
                if(p.execution_id!=execution || p.saved_frame_chain!=chain || p.deferred_service_frame!=frame ||
                   p.deferred_wait_active)std::terminate();
                p.deferred_service_frame=nullptr;
            }
        } end{*this,&state,execution,chain};
        const auto authentic=[&]{
            if(execution_id!=execution || saved_frame_chain!=chain || deferred_service_frame!=&state)std::terminate();
            return state.trusted_tls==tls && state.invocation==invocation && state.stack_top==stack_top &&
                state.resource_metered==resource_policy && state.instruction_limit==instruction_policy &&
                current_owner(owner,tls,invocation);
        };
        const auto terminal=[&]{return app.process_state->exit_status() || (services && services->thread_exit_value(tls));};
        for(;;){
            if(!authentic())return Fault::invalid_call;
            if(terminal())return Fault::none;
            if(!execution_boundary(GuestCpu::ExecutionBoundary::Reason::deferred_service))return result.fault;
            if(!authentic())return Fault::invalid_call;
            if(terminal())return Fault::none;
            state.remaining_budget=remaining; // Fresh retained allowance after every restored work grant.
            DeferredServiceResult step;
            {
                struct ResumeEnd {
                    Impl &p;
                    ~ResumeEnd(){if(!p.dispatching_service || p.registered_service_dispatch)std::terminate();p.dispatching_service=false;}
                } resume_end{*this};
                dispatching_service=true;
                // Nested signal delivery is permitted; peer pumping/scheduling is not.
                step=operation->resume(state);
            }
            if(!authentic())return Fault::invalid_call;
            if(terminal())return Fault::none;
            if(step.fault!=Fault::none)return step.fault;
            if(step.completed){state.deferred.reset();return Fault::none;}
            if(state.resume || state.deferred!=operation)return Fault::invalid_call;
            // Bill any nested native/managed tail before an outside-noexcept park.
            if(!execution_boundary(GuestCpu::ExecutionBoundary::Reason::deferred_service))return result.fault;
            if(!authentic())return Fault::invalid_call;
            if(terminal())return Fault::none;
            const auto wait=wait_callback;
            if(boundary_active || boundary_can_yield || deferred_wait_active)std::terminate();
            boundary_active=boundary_can_yield=deferred_wait_active=true;
            {
                struct WaitEnd {
                    Impl &p;std::uint64_t execution;const void *chain;const ServiceState *frame;
                    ~WaitEnd(){
                        if(p.execution_id!=execution || p.saved_frame_chain!=chain || p.deferred_service_frame!=frame ||
                           !p.boundary_active || !p.boundary_can_yield || !p.deferred_wait_active)std::terminate();
                        p.boundary_active=p.boundary_can_yield=p.deferred_wait_active=false;
                    }
                } wait_end{*this,execution,chain,&state};
                (*wait)(operation); // May throw cancellation only on this regular C++ stack.
            }
            if(!authentic())return Fault::invalid_call;
        }
    }
    template <class T> T read(Address address, CpuExceptionKind origin = CpuExceptionKind::read_abort) noexcept {
        T value{};
        ++stats.memory_reads;
        if (!memory.read(address, {reinterpret_cast<std::uint8_t *>(&value), sizeof(value)}))
            stop_cpu(origin, Fault::read, address, static_cast<std::uint32_t>(sizeof(T)), 0, {},
                     memory.access_failure(address, sizeof(T), Permission::read));
        return value;
    }
    template <class T> void write(Address address, T value) noexcept {
        ++stats.memory_writes;
        if (!memory.write(address, {reinterpret_cast<const std::uint8_t *>(&value), sizeof(value)}))
            stop_cpu(CpuExceptionKind::write_abort, Fault::write, address, static_cast<std::uint32_t>(sizeof(T)), 0, {},
                     memory.access_failure(address, sizeof(T), Permission::write));
    }
    template <class T> bool exclusive(Address address, T value, T expected) noexcept {
        if (address % sizeof(T)) {
            stop(Fault::write, address);
            return false;
        }
        // The comparison read implements a guest exclusive STORE, not a load.
        // Preserve its historical diagnostic Fault while recording CPU intent.
        if (read<T>(address, CpuExceptionKind::write_abort) != expected || result.fault != Fault::none)
            return false;
        write(address, value);
        return result.fault == Fault::none;
    }
    std::optional<std::uint32_t> MemoryReadCode(Address address) override {
        std::uint32_t value{};
        if (address % 4 || !memory.read(address, {reinterpret_cast<std::uint8_t *>(&value), sizeof(value)},
                                        Permission::execute))
            return std::nullopt;
        return value;
    }
    std::uint8_t MemoryRead8(Address a) override { return read<std::uint8_t>(a); }
    std::uint16_t MemoryRead16(Address a) override { return read<std::uint16_t>(a); }
    std::uint32_t MemoryRead32(Address a) override { return read<std::uint32_t>(a); }
    std::uint64_t MemoryRead64(Address a) override { return read<std::uint64_t>(a); }
    Vector MemoryRead128(Address a) override { return read<Vector>(a); }
    void MemoryWrite8(Address a, std::uint8_t v) override { write(a, v); }
    void MemoryWrite16(Address a, std::uint16_t v) override { write(a, v); }
    void MemoryWrite32(Address a, std::uint32_t v) override { write(a, v); }
    void MemoryWrite64(Address a, std::uint64_t v) override { write(a, v); }
    void MemoryWrite128(Address a, Vector v) override { write(a, v); }
    bool MemoryWriteExclusive8(Address a, std::uint8_t v, std::uint8_t e) override {
        return exclusive(a, v, e);
    }
    bool MemoryWriteExclusive16(Address a, std::uint16_t v, std::uint16_t e) override {
        return exclusive(a, v, e);
    }
    bool MemoryWriteExclusive32(Address a, std::uint32_t v, std::uint32_t e) override {
        return exclusive(a, v, e);
    }
    bool MemoryWriteExclusive64(Address a, std::uint64_t v, std::uint64_t e) override {
        return exclusive(a, v, e);
    }
    bool MemoryWriteExclusive128(Address a, Vector v, Vector e) override { return exclusive(a, v, e); }
    void InterpreterFallback(Address pc, std::size_t count) override {
        ++stats.interpreter_fallbacks;
        if (count == 1) {
            const auto instruction = MemoryReadCode(pc);
            if (!instruction) {
                stop_cpu(CpuExceptionKind::instruction_abort, Fault::execute, pc, 4, 0, pc,
                         memory.access_failure(pc, 4, Permission::execute));
                return;
            }
            if (const auto decoded = decode_scalar_lse(*instruction)) {
                scalar_lse_pending = ScalarLseFallback{pc, *instruction, *decoded};
                jit->HaltExecution();
                return;
            }
        }
        stop(Fault::unsupported_instruction, pc, static_cast<std::uint32_t>(count));
    }
    void execute_scalar_lse(const ScalarLseFallback &pending) {
        const auto &decoded = pending.decoded;
        jit->SetPC(pending.pc);
        const auto address = decoded.base == 31 ? jit->GetSP() : jit->GetRegister(decoded.base);
        if (decoded.base == 31 && address % 16) {
            stop_cpu(CpuExceptionKind::stack_alignment, Fault::alignment, address, decoded.bytes,
                     pending.instruction, pending.pc);
            return;
        }
        if (address % decoded.bytes) {
            stop_cpu(CpuExceptionKind::data_alignment, Fault::alignment, address, decoded.bytes,
                     pending.instruction, pending.pc);
            return;
        }
        if (!memory.accessible(address, decoded.bytes, Permission::read)) {
            stop_cpu(CpuExceptionKind::read_abort, Fault::read, address, decoded.bytes, pending.instruction, pending.pc,
                     memory.access_failure(address, decoded.bytes, Permission::read));
            return;
        }
        // An atomic is a read/write access, including a failed CAS comparison.
        // Preflight the entire range before reading or modifying guest state.
        if (!memory.accessible(address, decoded.bytes, Permission::write)) {
            stop_cpu(CpuExceptionKind::write_abort, Fault::write, address, decoded.bytes, pending.instruction, pending.pc,
                     memory.access_failure(address, decoded.bytes, Permission::write));
            return;
        }
        const auto mask = decoded.bytes == 8 ? UINT64_MAX : (std::uint64_t{1} << (decoded.bytes * 8)) - 1;
        const auto source = decoded.source == 31 ? 0 : jit->GetRegister(decoded.source) & mask;
        const auto replacement = decoded.destination == 31 ? 0 : jit->GetRegister(decoded.destination) & mask;
        std::uint64_t observed = 0;
        // GuestMemory and its CPU have one owner. No callback, allocation, or
        // scheduler handoff is allowed inside this checked read/modify/write;
        // this gives indivisibility against every supported logical guest.
        // Stronger host fences implement all relaxed/acquire/release variants.
        std::atomic_thread_fence(std::memory_order_seq_cst);
        ++stats.memory_reads;
        if (!memory.read(address, {reinterpret_cast<std::uint8_t *>(&observed), decoded.bytes})) {
            stop_cpu(CpuExceptionKind::read_abort, Fault::read, address, decoded.bytes, pending.instruction, pending.pc,
                     memory.access_failure(address, decoded.bytes, Permission::read));
            return;
        }
        auto changed = observed;
        bool store = true;
        switch (decoded.operation) {
        case ScalarAtomic::compare: store = observed == source; changed = replacement; break;
        case ScalarAtomic::add: changed = (observed + source) & mask; break;
        case ScalarAtomic::clear: changed = observed & ~source; break;
        case ScalarAtomic::exclusive_or: changed = observed ^ source; break;
        case ScalarAtomic::set: changed = observed | source; break;
        case ScalarAtomic::swap: changed = source; break;
        }
        if (store) {
            ++stats.memory_writes;
            if (!memory.write(address, {reinterpret_cast<const std::uint8_t *>(&changed), decoded.bytes})) {
                stop_cpu(CpuExceptionKind::write_abort, Fault::write, address, decoded.bytes, pending.instruction, pending.pc,
                         memory.access_failure(address, decoded.bytes, Permission::write));
                return;
            }
        }
        std::atomic_thread_fence(std::memory_order_seq_cst);
        // CAS returns the observed value through Rs; other atomics use Rt.
        // Byte/half/word results zero-extend, and register31 discards the result.
        const auto output = decoded.operation == ScalarAtomic::compare ? decoded.source : decoded.destination;
        if (output != 31) jit->SetRegister(output, observed);
        jit->ClearExclusiveState();
        monitor.Clear();
        jit->SetPC(pending.pc + 4);
        ++stats.interpreted_lse_instructions;
    }
    std::uint64_t counter(Address fault_origin = 0, std::uint32_t fault_detail = 0) noexcept {
        if (!app.monotonic_time_allowed) {
            stop(Fault::capability_denied, fault_origin, fault_detail);
            return 0;
        }
        LARGE_INTEGER value{};
        ++stats.host_calls;
        if (!QueryPerformanceCounter(&value)) {
            stop(Fault::windows_service, fault_origin, fault_detail);
            return 0;
        }
        return static_cast<std::uint64_t>(value.QuadPart);
    }
    void CallSVC(std::uint32_t service) override {
        if (service == 0 && active_signal_entry && jit->GetPC() == signal_restorer + 8) {
            if (jit->GetRegister(8) == 139 && jit->GetSP() == active_signal_entry->frame) {
                result.returned = true;
                result.signal_return = true;
                jit->HaltExecution();
            } else {
                stop(Fault::unsupported_service, signal_restorer + 4, service);
            }
            return;
        }
        if (service == 0xffff && jit->GetPC() == return_trampoline + 4) {
            if (active_signal_entry) {
                stop(Fault::unsupported_service, return_trampoline, service);
            } else {
                result.returned = true;
                jit->HaltExecution();
            }
        } else if (service == 1) {
            const auto instruction = jit->GetPC() - 4;
            const auto ticks = counter(instruction, service);
            if (result.fault == Fault::none) {
                jit->SetRegister(0, ticks);
                jit->SetRegister(1, frequency);
            }
        } else if (services) {
            // Run must return before services can invoke another guest call.
            pending_service = service;
            service_instruction = jit->GetPC() - 4;
            service_pending = true;
            jit->HaltExecution();
        } else
            stop(Fault::unsupported_service, jit->GetPC() - 4, service);
    }
    void MemoryAlignmentFault(Address pc, Address address) override {
        // The typed callback preserves SP and identifies the actual effective
        // address. No load, store or exclusive-monitor operation has run yet.
        jit->SetPC(pc);
        stop_cpu(CpuExceptionKind::data_alignment, Fault::alignment, address, 0,
                 static_cast<std::uint32_t>(Dynarmic::A64::Exception::DataAlignment), pc);
    }
    void ExceptionRaised(Address pc, Dynarmic::A64::Exception exception) override {
        if (exception == Dynarmic::A64::Exception::StackPointerAlignment) {
            // The backend has materialized the exact captured live SP and PC,
            // before any effective-address offset, memory access or writeback.
            stop_cpu(CpuExceptionKind::stack_alignment, Fault::alignment, jit->GetSP(), 0,
                     static_cast<std::uint32_t>(exception), pc);
            return;
        }
        if (exception == Dynarmic::A64::Exception::Yield) {
            // The frontend already advanced PC by four. Perform the host
            // scheduling hint only after returning out of generated frames.
            yield_pending = true;
            jit->HaltExecution();
            return;
        }
        switch (exception) {
        case Dynarmic::A64::Exception::NoExecuteFault:
            stop_cpu(CpuExceptionKind::instruction_abort, Fault::execute, pc, 4, static_cast<std::uint32_t>(exception), pc,
                     memory.access_failure(pc, 4, Permission::execute));
            return;
        case Dynarmic::A64::Exception::Breakpoint:
            stop_cpu(CpuExceptionKind::breakpoint, Fault::unsupported_instruction, pc, 0, static_cast<std::uint32_t>(exception), pc);
            return;
        case Dynarmic::A64::Exception::UnallocatedEncoding:
        case Dynarmic::A64::Exception::ReservedValue:
            stop_cpu(CpuExceptionKind::undefined_encoding, Fault::unsupported_instruction, pc, 0,
                     static_cast<std::uint32_t>(exception), pc);
            return;
        default:
            stop(Fault::unsupported_instruction, pc, static_cast<std::uint32_t>(exception));
        }
    }
    void DataCacheOperationRaised(Dynarmic::A64::DataCacheOperation op, Address value) override {
        if (op == Dynarmic::A64::DataCacheOperation::CleanByVAToPoU) {
            if (!memory.accessible(value, 1, Permission::read)) {
                stop_cpu(CpuExceptionKind::data_cache_abort, Fault::read, value, 1,
                         static_cast<std::uint32_t>(op), {}, memory.access_failure(value, 1, Permission::read));
                return;
            }
            // There is no separate dirty guest data cache. A real host fence
            // publishes prior guest stores; IC IVAU separately retires any
            // translations of the corresponding guest instruction line.
            std::atomic_thread_fence(std::memory_order_seq_cst);
            ++stats.data_cache_cleans;
            return;
        }
        stop(Fault::unsupported_instruction, value, static_cast<std::uint32_t>(op));
        // The post-callback IR guard handles every cache fault immediately,
        // including unsupported operations, before later instruction effects.
        jit->HaltExecution(Dynarmic::HaltReason::MemoryAbort);
    }
    void InstructionCacheOperationRaised(Dynarmic::A64::InstructionCacheOperation op,
                                         Address value) override {
        if (op == Dynarmic::A64::InstructionCacheOperation::InvalidateByVAToPoU) {
            if (!memory.accessible(value, 1, Permission::read)) {
                stop_cpu(CpuExceptionKind::instruction_cache_abort, Fault::read, value, 1,
                         static_cast<std::uint32_t>(op), {}, memory.access_failure(value, 1, Permission::read));
                return;
            }
            // IC IVAU terminates this translated block and advances PC. Never
            // release its executable allocation while its generated frame is
            // still on the host stack. One line is pending per Run boundary.
            instruction_cache_pending = value & ~(Address{guest_cache_line_size} - 1);
            jit->HaltExecution();
            return;
        }
        stop(Fault::unsupported_instruction, value, static_cast<std::uint32_t>(op));
        jit->HaltExecution(Dynarmic::HaltReason::MemoryAbort);
    }
    void AddTicks(std::uint64_t ticks) override {
        stats.guest_ticks += ticks;
        execution_ticks += ticks;
        if(resource_metered){
            if(resource_remaining)*resource_remaining=ticks>=*resource_remaining?0:*resource_remaining-ticks;
            if(operation_remaining)*operation_remaining=ticks>=*operation_remaining?0:*operation_remaining-ticks;
        }
        else remaining = ticks >= remaining ? 0 : remaining - ticks;
        if(configured_boundary() && quantum_ticks)
            quantum_remaining=ticks>=quantum_remaining?0:quantum_remaining-ticks;
        if(boundary_callback && !resource_metered)slice_remaining=ticks>=slice_remaining?0:slice_remaining-ticks;
    }
    std::uint64_t GetTicksRemaining() override {
        if(resource_metered){
            // Soft scheduling expiry permits a bounded final-block tail. Only
            // an actual aggregate/operation ceiling requires a strict margin.
            const auto hard=instruction_limit();
            if(!hard)return quantum_remaining;
            const auto bulk=*hard>=maximum_translated_block_ticks?
                *hard-(maximum_translated_block_ticks-1):*hard;
            return std::min(quantum_remaining,bulk);
        }
        if(!boundary_callback && !strict_budget)return remaining;
        const auto hard=boundary_callback?(std::min)(remaining,slice_remaining):remaining;
        // Run may execute its final full block before observing expiry. The
        // short remainder is executed with Step below, never beyond this grant.
        const auto bulk=hard>=maximum_translated_block_ticks?hard-(maximum_translated_block_ticks-1):hard;
        return boundary_callback && quantum_ticks && call_depth==1 && !active_signal_entry
            ?(std::min)(bulk,quantum_remaining):bulk;
    }
    std::uint64_t GetCNTPCT() override { return counter(); }
    void BlockLookup(Address, bool hit) noexcept override {
        ++stats.block_lookups;
        if (hit)
            ++stats.cache_hits;
        if(services && services->event_pending())jit->HaltExecution();
    }
    void BlockCompiled(Address pc, const void *code, std::size_t size,
                       std::uint64_t elapsed) noexcept override {
        ++stats.compiled_blocks;
        stats.emitted_bytes += size;
        stats.compile_nanoseconds += elapsed;
        stats.last_compiled_pc = pc;
        ++stats.rx_checks;
        const auto *bytes = static_cast<const std::uint8_t *>(code);
        std::size_t offset = 0;
        while (offset < size) {
            MEMORY_BASIC_INFORMATION info{};
            if (!VirtualQuery(bytes + offset, &info, sizeof(info)) || info.State != MEM_COMMIT ||
                info.Protect != PAGE_EXECUTE_READ) {
                ++stats.rx_failures;
                stop(Fault::jit_protection, pc);
                return;
            }
            const auto available =
                info.RegionSize - static_cast<std::size_t>(
                                      bytes + offset - static_cast<const std::uint8_t *>(info.BaseAddress));
            if (!available) {
                ++stats.rx_failures;
                stop(Fault::jit_protection, pc);
                return;
            }
            offset += (size - offset < available ? size - offset : available);
        }
        // Evidence fingerprint, not a security hash or cross-process stable value.
        std::uint64_t hash = 14695981039346656037ull;
        for (std::size_t i = 0; i < size; ++i)
            hash = (hash ^ bytes[i]) * 1099511628211ull;
        stats.last_code_fingerprint = hash;
    }
};
GuestCpu::GuestCpu(GuestMemory &memory, const AppContext &app, GuestServices *services)
    : impl_(std::make_unique<Impl>(memory, app, services)) {}
GuestCpu::~GuestCpu() = default;
void GuestCpu::set_thread_pointer(Address address) {
    auto &p=*impl_;
    if(GetCurrentThreadId()!=p.owner_thread || p.call_depth || p.jit->IsExecuting())throw GuestError("AETHER_GUEST_CPU_OWNERSHIP","TLS binding requires idle CPU owner");
    if(address && !p.memory.accessible(address,48,Permission::read))throw GuestError("AETHER_GUEST_TLS","TLS block is not guest readable");
    if (p.default_tpidr != address) {
        // This one bounded fallback incarnation is preallocated. Provider-owned
        // values are selected at call entry and are never changed by this setter.
        *p.default_registers = ThreadRegisterState{address, 0};
        p.default_tpidr = address;
    }
}
std::unique_ptr<GuestCpu::ExecutionContext> GuestCpu::prepare_execution_context() {
    return prepare_execution_context({},0);
}
std::unique_ptr<GuestCpu::ExecutionContext> GuestCpu::prepare_execution_context(ExecutionBoundaryCallback callback,std::uint64_t quantum) {
    return prepare_execution_context(std::move(callback),quantum,{});
}
std::unique_ptr<GuestCpu::ExecutionContext> GuestCpu::prepare_execution_context(ExecutionBoundaryCallback callback,std::uint64_t quantum,ExecutionWaitCallback wait) {
    auto &p=*impl_;
    if(GetCurrentThreadId()!=p.owner_thread || p.jit->IsExecuting())
        throw GuestError("AETHER_GUEST_CPU_OWNERSHIP","Execution preparation requires the CPU owner outside generated execution");
    if(p.execution_owner->prepared_contexts.load(std::memory_order_relaxed)>=16)
        throw GuestError("AETHER_GUEST_CONTEXT_LIMIT","Sixteen prepared CPU executions exhausted");
    if(quantum>10'000'000 || ((quantum || wait) && !callback))
        throw GuestError("AETHER_GUEST_CONTEXT","A cooperative quantum requires a prepared callback and bounded ticks");
    auto state=std::make_unique<ExecutionContext::State>();
    state->owner=p.execution_owner;
    state->execution.execution_id=next_execution();
    if(!state->execution.execution_id)
        throw GuestError("AETHER_GUEST_CONTEXT_LIMIT","Execution identity range exhausted");
    if(callback)state->execution.boundary_callback=std::make_shared<const ExecutionBoundaryCallback>(std::move(callback));
    if(wait)state->execution.wait_callback=std::make_shared<const ExecutionWaitCallback>(std::move(wait));
    state->execution.quantum_ticks=quantum;
    if(state->execution.boundary_callback)state->execution.slice_remaining=0;
    auto context=std::unique_ptr<ExecutionContext>(new ExecutionContext(std::move(state)));
    p.execution_owner->prepared_contexts.fetch_add(1,std::memory_order_relaxed);
    context->state_->charged=true;
    return context;
}
std::unique_ptr<GuestCpu::ExecutionContext> GuestCpu::prepare_resource_execution_context(
    ResourceBoundaryCallback callback,std::uint64_t quantum,std::optional<std::uint64_t> ceiling) {
    if(!callback || !quantum || quantum>10'000'000)
        throw GuestError("AETHER_GUEST_CONTEXT","Resource execution requires a trusted callback and finite scheduling quantum");
    auto context=prepare_execution_context({},0,{});
    context->state_->execution.resource_callback=std::make_shared<const ResourceBoundaryCallback>(std::move(callback));
    context->state_->execution.quantum_ticks=quantum;
    context->state_->execution.resource_remaining=ceiling;
    return context;
}
bool GuestCpu::exchange_execution_context(ExecutionContext &context) noexcept {
    auto &p=*impl_;
    if(GetCurrentThreadId()!=p.owner_thread || p.jit->IsExecuting() || !context.state_ ||
       context.state_->owner!=p.execution_owner || !p.idle() || !context.state_->execution.idle())return false;
    commit_execution_context(context);
    return true;
}
bool GuestCpu::can_exchange_execution_context(const ExecutionContext &context) const noexcept {
    const auto &p=*impl_;
    return GetCurrentThreadId()==p.owner_thread && !p.jit->IsExecuting() && context.state_ &&
        context.state_->owner==p.execution_owner && p.exchangeable() && context.state_->execution.exchangeable();
}
void GuestCpu::commit_execution_context(ExecutionContext &context) noexcept {
    if(!can_exchange_execution_context(context))std::terminate();
    auto &p=*impl_;
    // No fallible lookup/allocation or service callback follows admission.
    // The physical TLS addresses used by UserConfig remain inside this Impl.
    if(p.active_registers)*p.active_registers=ThreadRegisterState{p.tpidr,p.tpidr_read_only};
    p.architectural={p.jit->GetRegisters(),p.jit->GetVectors(),p.jit->GetPC(),p.jit->GetSP(),
                     p.jit->GetPstate(),p.jit->GetFpsr(),p.jit->GetFpcr()};
    using std::swap;
    swap(static_cast<CpuExecutionState &>(p),context.state_->execution);
    // The trusted incarnation is authoritative if same-owner work updated it
    // while this execution was inactive; never roll those values back.
    if(p.active_registers){p.tpidr=p.active_registers->tpidr_el0;p.tpidr_read_only=p.active_registers->tpidrro_el0;}
    p.jit->Reset(); // Retains shared queued cache invalidation; do not ClearHalt here.
    const auto &state=p.architectural;
    p.jit->SetRegisters(state.registers);p.jit->SetVectors(state.vectors);
    p.jit->SetPC(state.pc);p.jit->SetSP(state.sp);p.jit->SetPstate(state.pstate);
    p.jit->SetFpsr(state.fpsr);p.jit->SetFpcr(state.fpcr);
    p.jit->ClearExclusiveState();p.monitor.Clear();
}
bool GuestCpu::request_execution_yield() noexcept {
    auto &p=*impl_;
    if(GetCurrentThreadId()!=p.owner_thread || p.jit->IsExecuting() || !p.configured_boundary() ||
       !p.registered_service_dispatch || !p.dispatching_service || !p.exchangeable())return false;
    p.execution_yield_requested=true;
    return true;
}
bool GuestCpu::set_execution_slice_allowance(ExecutionContext &context,std::uint64_t grant) noexcept {
    auto &p=*impl_;
    if(GetCurrentThreadId()!=p.owner_thread || p.jit->IsExecuting() || !context.state_ ||
       context.state_->owner!=p.execution_owner || !context.state_->execution.boundary_callback ||
       !context.state_->execution.exchangeable() || context.state_->execution.registered_service_dispatch)return false;
    context.state_->execution.slice_remaining=grant;
    return true;
}
bool GuestCpu::limit_execution_slice(std::uint64_t cap) noexcept {
    auto &p=*impl_;
    if(GetCurrentThreadId()!=p.owner_thread || p.jit->IsExecuting() || !p.boundary_callback ||
       !p.boundary_active || !p.call_depth || !p.saved_frame_chain || !p.active_registers || !p.active_invocation)return false;
    p.slice_remaining=(std::min)(p.slice_remaining,cap);
    return true;
}
bool GuestCpu::execution_idle() const noexcept {
    const auto &p=*impl_;
    return GetCurrentThreadId()==p.owner_thread && !p.jit->IsExecuting() && p.idle();
}
bool GuestCpu::trim_translation_cache() {
    if(!execution_idle())return false;
    auto &p=*impl_;
    if(p.live_saved_frames)return false;
    if(!p.jit->TrimCache())return false;
    ++p.stats.cache_invalidations;
    return true;
}
std::optional<std::uint64_t> GuestCpu::execution_progress_allowance() const noexcept {
    const auto &p=*impl_;
    if(GetCurrentThreadId()!=p.owner_thread || p.jit->IsExecuting() ||
       p.resource_metered || !p.dispatching_service || !p.registered_service_dispatch || !p.exchangeable())return {};
    return p.boundary_callback?(std::min)(p.remaining,p.slice_remaining):p.remaining;
}
bool GuestCpu::debit_external_progress(std::uint64_t ticks) noexcept {
    const auto allowance=execution_progress_allowance();
    auto &p=*impl_;
    if(!allowance || ticks>*allowance || ticks>UINT64_MAX-p.external_tick_debits)return false;
    p.remaining-=ticks;
    if(p.boundary_callback){
        p.slice_remaining-=ticks;
        if(p.quantum_ticks)p.quantum_remaining=ticks>=p.quantum_remaining?0:p.quantum_remaining-ticks;
    }
    p.external_tick_debits+=ticks;
    return true;
}
bool GuestCpu::limit_external_progress(std::uint64_t retained,std::uint64_t work) noexcept {
    if(!execution_progress_allowance())return false;
    auto &p=*impl_;
    auto *frame=p.registered_service_frame;
    if(!frame || frame->trusted_tls!=p.active_tls || frame->invocation!=p.active_invocation)return false;
    p.strict_budget=true;
    p.remaining=(std::min)(p.remaining,retained);
    if(p.boundary_callback)p.slice_remaining=(std::min)(p.slice_remaining,work);
    else p.remaining=(std::min)(p.remaining,work);
    const auto available=p.boundary_callback?(std::min)(p.remaining,p.slice_remaining):p.remaining;
    frame->remaining_budget=(std::min)(frame->remaining_budget,available);
    return true;
}
std::uint64_t GuestCpu::active_ticks() const noexcept { return impl_->execution_ticks; }
ExecutionResult GuestCpu::call(Address entry, std::span<const std::uint64_t> arguments, Address stack_top,
                               std::uint64_t instruction_budget, std::span<const Vector> floating_arguments,
                               std::optional<Address> thread_pointer, const SignalEntry *signal_entry) {
    return call_impl(entry,arguments,stack_top,instruction_budget,floating_arguments,thread_pointer,signal_entry,false,{});
}
ExecutionResult GuestCpu::call_resource_metered(Address entry,std::span<const std::uint64_t> arguments,Address stack_top,
                               std::span<const Vector> floating_arguments,std::optional<Address> thread_pointer,
                               const SignalEntry *signal_entry,std::optional<std::uint64_t> operation_limit) {
    return call_impl(entry,arguments,stack_top,0,floating_arguments,thread_pointer,signal_entry,true,operation_limit);
}
ExecutionResult GuestCpu::call_impl(Address entry,std::span<const std::uint64_t> arguments,Address stack_top,
                               std::uint64_t instruction_budget,std::span<const Vector> floating_arguments,
                               std::optional<Address> thread_pointer,const SignalEntry *signal_entry,bool resource_requested,
                               std::optional<std::uint64_t> operation_limit) {
    auto &p = *impl_;
    if (GetCurrentThreadId() != p.owner_thread || p.jit->IsExecuting() ||
        (p.call_depth && !p.dispatching_service))
        throw GuestError("AETHER_GUEST_CPU_OWNERSHIP",
                         "Nested calls require a suspended service on the CPU owner thread");
    if(const auto status=p.app.process_state->exit_status()){ExecutionResult exited;exited.fault=Fault::process_exit;exited.detail=*status;return exited;}
    const auto logical_tls=thread_pointer.value_or(p.default_tpidr);
    if(p.services)if(const auto value=p.services->thread_exit_value(logical_tls)){ExecutionResult exited;exited.fault=Fault::thread_exit;exited.registers[0]=*value;return exited;}
    if (p.call_depth >= 32) {
        ++p.stats.faults;
        ExecutionResult limit;
        limit.fault = Fault::nesting_limit;
        return limit;
    }
    const std::optional<SignalEntry> selected_signal = signal_entry ? std::optional<SignalEntry>{*signal_entry} : std::nullopt;
    const bool resource_mode=resource_requested || (p.call_depth && p.resource_metered);
    const bool valid_resource=resource_mode?(p.resource_callback && (!p.call_depth || p.resource_metered)):
        (!p.resource_callback || p.call_depth!=0);
    const bool valid_stack = selected_signal ?
        stack_top % 16 == 0 && stack_top == selected_signal->frame && stack_top == selected_signal->state.sp &&
            p.memory.accessible(stack_top, 16, Permission::write) :
        stack_top % 16 == 0 && stack_top >= 16 && p.memory.accessible(stack_top - 16, 16, Permission::write);
    const bool valid_signal = !selected_signal ||
        (p.call_depth && p.dispatching_service &&
         logical_tls == p.active_tls && p.active_registers && arguments.empty() && floating_arguments.empty() &&
         entry == selected_signal->state.pc && representable_user_state(selected_signal->state) &&
         p.memory.accessible(entry, 4, Permission::execute) &&
         ((p.dispatching_fault && p.result.cpu_exception && p.result.fault != Fault::none) ||
          (p.services && p.services->pending_signal_entry(*selected_signal, logical_tls, p.active_invocation))));
    if (arguments.size() > 8 || floating_arguments.size() > 8 || entry % 4 || !valid_stack || !valid_signal ||
        !valid_resource || (!resource_mode && (!instruction_budget || instruction_budget > 10'000'000))) {
        ExecutionResult invalid;
        invalid.fault = Fault::invalid_call;
        ++p.stats.faults;
        return invalid;
    }
    const auto invocation=next_invocation();
    if(!invocation){ExecutionResult invalid;invalid.fault=Fault::invalid_call;++p.stats.faults;return invalid;}
    // Save the live software register before consulting any next-owner record.
    // Lookup failure leaves the active frame and its backing unchanged.
    if (p.active_registers)
        *p.active_registers = ThreadRegisterState{p.tpidr, p.tpidr_read_only};
    auto selected_registers = p.services ? p.services->thread_register_state(logical_tls) : nullptr;
    if (p.active_registers && logical_tls == p.active_tls) {
        if (selected_registers && selected_registers != p.active_registers)
            throw GuestError("AETHER_GUEST_TLS", "Nested TLS owner incarnation changed");
        selected_registers = p.active_registers;
    } else if (selected_registers && selected_registers == p.active_registers) {
        throw GuestError("AETHER_GUEST_TLS", "Different TLS owners share architectural register state");
    }
    if (!selected_registers)
        selected_registers = logical_tls == p.default_tpidr ? p.default_registers :
            std::make_shared<ThreadRegisterState>(ThreadRegisterState{logical_tls, 0});
    if(p.live_saved_frames==UINT64_MAX)std::terminate();
    struct SavedFrame {
        Impl &p;
        std::uint64_t execution;
        const void *previous_chain;
        ExecutionResult result;
        std::array<std::uint64_t, 31> registers;
        std::array<Vector, 32> vectors;
        Address pc, sp;
        std::uint32_t pstate, fpsr, fpcr;
        std::uint64_t remaining, ticks, external_debits, tpidr, tpidr_read_only, invocation;
        std::shared_ptr<ThreadRegisterState> parent_registers;
        Address parent_tls;
        std::optional<SignalEntry> parent_signal;
        ServiceState *registered_frame;
        bool dispatching, fault_dispatching, registered_dispatch, deferred_yield, strict_budget, nested, cpu_exception_pc_pending;
        bool resource_metered;
        std::optional<std::uint64_t> resource_remaining;
        std::optional<std::uint64_t> operation_remaining;
        ~SavedFrame() {
            // A future scheduler must restore this execution before unwinding
            // its real fiber stack. Never restore a sibling's CPU state.
            if(!p.live_saved_frames || !p.call_depth || p.execution_id!=execution ||
               p.saved_frame_chain!=this || p.registered_service_frame ||
               registered_dispatch!=(registered_frame!=nullptr) || (registered_frame &&
               (registered_frame->trusted_tls!=parent_tls || registered_frame->invocation!=invocation)))std::terminate();
            p.saved_frame_chain=previous_chain;
            --p.call_depth;
            --p.live_saved_frames;
            p.dispatching_service = dispatching;
            p.dispatching_fault = fault_dispatching;
            p.registered_service_dispatch=registered_dispatch;
            p.registered_service_frame=registered_frame;
            p.execution_yield_requested=deferred_yield;
            p.strict_budget=strict_budget;
            p.resource_metered=resource_metered;
            // Resource work is debited directly from this execution's persistent
            // optional ceiling, including nested calls. Do not subtract twice
            // or restore an earlier aggregate balance on return.
            if(resource_metered && resource_remaining &&
               (!p.resource_remaining || *p.resource_remaining>*resource_remaining))std::terminate();
            if(p.execution_ticks<ticks || p.external_tick_debits<external_debits)std::terminate();
            // The child's local cap may be narrower. Restore the parent's
            // actual balance after inclusive child work, not that narrower cap.
            p.operation_remaining=operation_remaining;
            if(p.operation_remaining){
                const auto spent=p.execution_ticks-ticks;
                *p.operation_remaining=spent>=*p.operation_remaining?0:*p.operation_remaining-spent;
                const auto external=p.external_tick_debits-external_debits;
                *p.operation_remaining=external>=*p.operation_remaining?0:*p.operation_remaining-external;
            }
            p.boundary_active=false;
            p.boundary_can_yield=false;
            p.active_signal_entry = std::move(parent_signal);
            p.service_pending = false;
            p.yield_pending = false;
            p.instruction_cache_pending.reset();
            p.scalar_lse_pending.reset();
            if (p.active_registers)
                *p.active_registers = ThreadRegisterState{p.tpidr, p.tpidr_read_only};
            p.active_registers = std::move(parent_registers);
            p.active_tls = parent_tls;
            // Same-owner callbacks may have changed this shared state. Reload
            // its current value rather than rolling back to the captured bits.
            p.tpidr = p.active_registers ? p.active_registers->tpidr_el0 : tpidr;
            p.tpidr_read_only = p.active_registers ? p.active_registers->tpidrro_el0 : tpidr_read_only;
            p.active_invocation=invocation;
            p.cpu_exception_pc_pending = cpu_exception_pc_pending;
            if (!nested)
                return;
            p.jit->Reset();
            p.jit->SetRegisters(registers);
            p.jit->SetVectors(vectors);
            p.jit->SetPC(pc);
            p.jit->SetSP(sp);
            p.jit->SetPstate(pstate);
            p.jit->SetFpsr(fpsr);
            p.jit->SetFpcr(fpcr);
            p.jit->ClearExclusiveState();
            p.monitor.Clear();
            p.result = result;
            const auto spent = p.execution_ticks - ticks;
            p.remaining = spent >= remaining ? 0 : remaining - spent;
            if(p.external_tick_debits<external_debits)std::terminate();
            const auto external_spent=p.external_tick_debits-external_debits;
            p.remaining=external_spent>=p.remaining?0:p.remaining-external_spent;
        }
    } saved{p,
            p.execution_id,p.saved_frame_chain,
            p.result,
            p.jit->GetRegisters(),
            p.jit->GetVectors(),
            p.jit->GetPC(),
            p.jit->GetSP(),
            p.jit->GetPstate(),
            p.jit->GetFpsr(),
            p.jit->GetFpcr(),
            p.remaining,
            p.execution_ticks,
            p.external_tick_debits,
            p.tpidr,p.tpidr_read_only,p.active_invocation,
            p.active_registers,p.active_tls,
            p.active_signal_entry,
            p.registered_service_frame,
            p.dispatching_service,
            p.dispatching_fault,
            p.registered_service_dispatch,p.execution_yield_requested,p.strict_budget,
            p.call_depth != 0,
            p.cpu_exception_pc_pending,p.resource_metered,p.resource_remaining,p.operation_remaining};
    p.saved_frame_chain=&saved;
    ++p.live_saved_frames;
    p.resource_metered=resource_mode;
    if(resource_mode){
        const auto local=resource_requested?operation_limit:std::optional<std::uint64_t>{instruction_budget};
        if(local)p.operation_remaining=p.operation_remaining?std::min(*p.operation_remaining,*local):*local;
    }
    p.active_invocation=invocation;
    p.active_registers = std::move(selected_registers);
    p.active_tls = logical_tls;
    p.tpidr = p.active_registers->tpidr_el0;
    p.tpidr_read_only = p.active_registers->tpidrro_el0;
    ++p.call_depth;
    p.stats.maximum_call_depth = std::max<std::uint64_t>(p.stats.maximum_call_depth, p.call_depth);
    if (saved.nested)
        ++p.stats.nested_calls;
    p.dispatching_service = false;
    p.dispatching_fault = false;
    p.registered_service_dispatch=false;
    p.registered_service_frame=nullptr;
    p.boundary_active=false;
    p.boundary_can_yield=false;
    if(!saved.nested){p.quantum_remaining=p.quantum_ticks;p.execution_yield_requested=false;p.strict_budget=false;}
    p.active_signal_entry = selected_signal;
    p.service_pending = false;
    p.yield_pending = false;
    p.instruction_cache_pending.reset();
    p.scalar_lse_pending.reset();
    p.result = {};
    p.cpu_exception_pc_pending = false;
    p.jit->Reset();
    p.monitor.Clear();
    p.remaining = resource_mode?0:saved.nested ? std::min(instruction_budget, saved.remaining) : instruction_budget;
    if (selected_signal) {
        const auto &state = selected_signal->state;
        p.jit->SetRegisters(state.registers);
        p.jit->SetVectors(state.vectors);
        p.jit->SetPC(state.pc);
        p.jit->SetSP(state.sp);
        p.jit->SetPstate(state.pstate);
        p.jit->SetFpcr(state.fpcr);
        p.jit->SetFpsr(state.fpsr);
        p.jit->SetRegister(30, signal_restorer);
    } else {
        p.jit->SetPC(entry);
        p.jit->SetSP(stack_top);
        p.jit->SetRegister(30, return_trampoline);
        for (std::size_t i = 0; i < arguments.size(); ++i)
            p.jit->SetRegister(i, arguments[i]);
        for (std::size_t i = 0; i < floating_arguments.size(); ++i)
            p.jit->SetVector(i, floating_arguments[i]);
    }
    bool entry_boundary=true;
    for (;;) {
        if(p.app.process_state->exit_status()){p.stop(Fault::process_exit,p.jit->GetPC());break;}
        if(p.services && p.services->thread_exit_value(logical_tls)){p.stop(Fault::thread_exit,p.jit->GetPC());break;}
        if(entry_boundary){
            entry_boundary=false;
            if(!p.execution_boundary(ExecutionBoundary::Reason::entry))break;
        }
        const bool finite_quantum=p.call_depth==1 && !p.active_signal_entry && (p.execution_yield_requested ||
            (p.boundary_callback && (!p.slice_remaining || (p.quantum_ticks && !p.quantum_remaining))));
        if((p.resource_metered && (!p.quantum_remaining || p.execution_yield_requested)) || finite_quantum)
            if(!p.execution_boundary(ExecutionBoundary::Reason::quantum))break;
        if(p.resource_metered?p.resource_exhausted():
           ((p.boundary_callback || p.strict_budget) && (!p.remaining || (p.boundary_callback && !p.slice_remaining)))){
            p.stop(Fault::budget,p.jit->GetPC());break;
        }
        if(p.services && p.services->event_pending()){
            if(!p.execution_boundary(ExecutionBoundary::Reason::before_checkpoint))break;
            auto state = p.service_frame(stack_top);
            const auto resource_policy=state.resource_metered;
            const auto instruction_policy=state.instruction_limit;
            const auto expected_owner = p.active_registers;
            const auto expected_invocation = p.active_invocation;
            p.dispatching_service=true;
            const auto fault=p.services->checkpoint(state);
            p.dispatching_service=false;
            if(p.app.process_state->exit_status()){p.stop(Fault::process_exit,p.jit->GetPC());break;}
            if(p.services->thread_exit_value(logical_tls)){p.stop(Fault::thread_exit,p.jit->GetPC());break;}
            if(state.resource_metered!=resource_policy || state.instruction_limit!=instruction_policy){p.stop(Fault::invalid_call,p.jit->GetPC());break;}
            if(fault!=Fault::none){p.stop(fault,p.jit->GetPC());break;}
            if (state.resume) {
                if (!p.current_owner(expected_owner, logical_tls, expected_invocation) || !p.commit_context(*state.resume)) {
                    p.stop(Fault::invalid_call, p.jit->GetPC());break;
                }
                if(!p.execution_boundary(ExecutionBoundary::Reason::checkpoint))break;
                continue;
            } else {
                if (state.stack_pointer != p.jit->GetSP() && (state.stack_pointer < 16 || state.stack_pointer % 16 ||
                    state.stack_pointer > stack_top || !p.memory.accessible(state.stack_pointer - 16, 16, Permission::write))) {
                    p.stop(Fault::write, p.jit->GetPC());break;
                }
                p.jit->SetRegisters(state.registers);
                p.jit->SetVectors(state.vectors);
                p.jit->SetSP(state.stack_pointer);
                p.jit->ClearExclusiveState();p.monitor.Clear();
            }
            if(!p.execution_boundary(ExecutionBoundary::Reason::checkpoint))break;
        }
        if (p.resource_metered?p.resource_exhausted():!p.remaining) {
            p.stop(Fault::budget, p.jit->GetPC());
            break;
        }
        // Data accesses always use live checked callbacks. Heap allocation/free
        // cannot change executable bytes, so it need not discard translated code.
        if (p.code_generation != p.memory.code_generation()) {
            p.jit->ClearCache();
            p.code_generation = p.memory.code_generation();
            ++p.stats.cache_invalidations;
        }
        // Run/Step must see queued shared cache invalidation before entering
        // code. Clear only execution-stop reasons, not the cache request bit.
        p.jit->ClearHalt(~Dynarmic::HaltReason::CacheInvalidation);
        const auto start = std::chrono::steady_clock::now();
        const auto hard=p.resource_metered?p.instruction_limit():
            std::optional<std::uint64_t>{p.boundary_callback?(std::min)(p.remaining,p.slice_remaining):p.remaining};
        const bool single_step=hard && (p.resource_metered || p.boundary_callback || p.strict_budget) &&
            *hard<maximum_translated_block_ticks;
        const auto halt=single_step?p.jit->Step():p.jit->Run();
        p.stats.execution_nanoseconds += static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() - start)
                .count());
        if (p.cpu_exception_pc_pending && p.result.cpu_exception) {
            p.result.cpu_exception->state.pc = p.jit->GetPC();
            p.cpu_exception_pc_pending = false;
        }
        if (p.result.fault == Fault::none && !p.result.returned) {
            if (p.scalar_lse_pending) {
                const auto pending = *p.scalar_lse_pending;
                p.scalar_lse_pending.reset();
                // The frontend counts this one instruction in block.CycleCount;
                // EmitAddCycles and ReturnFromRunCode already charged AddTicks.
                // Do not charge it again or reset the enclosing call's budget.
                p.execute_scalar_lse(pending);
                if (p.result.fault == Fault::none) continue;
            }
            if (p.instruction_cache_pending) {
                const auto line = *p.instruction_cache_pending;
                p.instruction_cache_pending.reset();
                std::atomic_thread_fence(std::memory_order_seq_cst);
                p.jit->InvalidateCacheRange(line, guest_cache_line_size);
                ++p.stats.cache_invalidations;
                ++p.stats.instruction_cache_invalidations;
                continue;
            }
            if (p.yield_pending) {
                p.yield_pending = false;
                ++p.stats.host_calls;
                ++p.stats.scheduling_yields;
                // SwitchToThread is an advisory yield: a false result simply
                // means no eligible thread was ready on this processor.
                SwitchToThread();
                continue;
            }
        }
        if (p.result.cpu_exception && p.services && !p.result.returned) {
            if (p.app.process_state->exit_status() || p.services->thread_exit_value(logical_tls)) break;
            // Keep a value copy: a nested CPU call replaces the result optional.
            auto exception = *p.result.cpu_exception;
            exception.state.registers = p.jit->GetRegisters();
            exception.state.vectors = p.jit->GetVectors();
            exception.state.sp = p.jit->GetSP();
            exception.state.pstate = p.jit->GetPstate();
            exception.state.fpsr = p.jit->GetFpsr();
            exception.state.fpcr = p.jit->GetFpcr();
            p.result.cpu_exception = exception;
            if(!p.execution_boundary(ExecutionBoundary::Reason::before_fault,false))break;
            auto candidate = exception.state;
            const auto expected_owner = p.active_registers;
            const auto expected_tls = p.active_tls, expected_invocation = p.active_invocation;
            const CpuFaultBoundary boundary{logical_tls, expected_invocation, stack_top, p.service_allowance(),
                p.resource_metered,p.instruction_limit()};
            CpuFaultAction action;
            {
                struct FaultDispatch {
                    Impl &p;
                    bool service, fault;
                    ~FaultDispatch() { p.dispatching_service = service; p.dispatching_fault = fault; }
                } dispatch{p, p.dispatching_service, p.dispatching_fault};
                p.dispatching_service = true;
                p.dispatching_fault = true;
                action = p.services->synchronous_fault(exception, candidate, boundary);
            }
            if (p.app.process_state->exit_status() || p.services->thread_exit_value(logical_tls)) break;
            if (action == CpuFaultAction::resume && p.current_owner(expected_owner, expected_tls, expected_invocation) &&
                p.commit_context(candidate)) {
                // All callback/ownership/context validation precedes the commit.
                // No call-entry stack ceiling or blanket alignment rule applies.
                p.result = {};
                p.cpu_exception_pc_pending = false;
                p.service_pending = false;
                p.scalar_lse_pending.reset();
                p.instruction_cache_pending.reset();
                p.yield_pending = false;
                p.jit->ClearHalt(Dynarmic::HaltReason::UserDefined1 | Dynarmic::HaltReason::MemoryAbort);
                if(!p.execution_boundary(ExecutionBoundary::Reason::after_fault))break;
                continue;
            }
        }
        if(!p.service_pending && p.result.fault==Fault::none && !p.result.returned && p.services && p.services->event_pending())continue;
        if(!p.service_pending && p.result.fault==Fault::none && !p.result.returned && p.boundary_callback &&
           (!p.slice_remaining || (p.quantum_ticks && !p.quantum_remaining)) && p.call_depth==1 && !p.active_signal_entry)continue;
        if(!p.service_pending && p.result.fault==Fault::none && !p.result.returned && p.resource_metered && !p.quantum_remaining)continue;
        if(single_step && Dynarmic::Has(halt,Dynarmic::HaltReason::Step) && !p.service_pending &&
           p.result.fault==Fault::none && !p.result.returned)continue;
        // A bulk dispatcher deliberately reserves its final255 ticks. Consume
        // the actual remaining tail with Step rather than inventing exhaustion.
        if((p.strict_budget || p.resource_metered) && !halt &&
           (p.resource_metered?p.service_allowance():p.remaining) && !p.service_pending &&
           p.result.fault==Fault::none && !p.result.returned)continue;
        if (!p.service_pending || p.result.fault != Fault::none || p.result.returned)
            break;
        const auto service = p.pending_service;
        const auto instruction = p.service_instruction;
        p.service_pending = false;
        // The pending host effect is retained on this exact C++ stack while a
        // root boundary parks; no service has been invoked and none is replayed.
        if(!p.execution_boundary(ExecutionBoundary::Reason::before_service))break;
        auto state = p.service_frame(stack_top);
        const auto resource_policy=state.resource_metered;
        const auto instruction_policy=state.instruction_limit;
        const auto expected_owner = p.active_registers;
        const auto expected_invocation = p.active_invocation;
        const auto expected_execution=p.execution_id;
        const auto expected_chain=p.saved_frame_chain;
        p.dispatching_service = true;
        p.registered_service_dispatch=true;
        p.registered_service_frame=&state;
        ++p.stats.host_calls;
        ++p.stats.deferred_services;
        auto fault = p.services->invoke_frame(service, instruction, state);
        if(p.execution_id!=expected_execution || p.saved_frame_chain!=expected_chain ||
           p.registered_service_frame!=&state || !p.registered_service_dispatch || !p.dispatching_service)std::terminate();
        p.registered_service_frame=nullptr;
        p.registered_service_dispatch=false;
        p.dispatching_service = false;
        if(state.resource_metered!=resource_policy || state.instruction_limit!=instruction_policy){p.stop(Fault::invalid_call,instruction);break;}
        if(fault==Fault::none && state.deferred)
            fault=p.complete_deferred_service(state,expected_owner,logical_tls,expected_invocation,stack_top,expected_execution,expected_chain);
        if(p.app.process_state->exit_status()){p.stop(Fault::process_exit,instruction);break;}
        if(p.services && p.services->thread_exit_value(logical_tls)){p.stop(Fault::thread_exit,instruction);break;}
        if (fault != Fault::none) {
            p.stop(fault, instruction, service);
            break;
        }
        if (state.resume) {
            if (!p.current_owner(expected_owner, logical_tls, expected_invocation) || !p.commit_context(*state.resume)) {
                p.stop(Fault::invalid_call, instruction, service);break;
            }
            if(!p.execution_boundary(ExecutionBoundary::Reason::service))break;
            continue;
        }
        if(state.stack_pointer!=p.jit->GetSP() && (state.stack_pointer<16 || state.stack_pointer%16 ||
           state.stack_pointer>stack_top || !p.memory.accessible(state.stack_pointer-16,16,Permission::write))){
            p.stop(Fault::write,instruction,service);break;
        }
        p.jit->SetRegisters(state.registers);
        p.jit->SetVectors(state.vectors);
        p.jit->SetSP(state.stack_pointer);
        // Host transitions may break an exclusive reservation; a spurious failure is allowed.
        p.jit->ClearExclusiveState();
        p.monitor.Clear();
        if(!p.execution_boundary(ExecutionBoundary::Reason::service))break;
    }
    if (!p.result.returned && p.result.fault == Fault::none)
        p.stop(Fault::budget, p.jit->GetPC());
    p.result.registers = p.jit->GetRegisters();
    p.result.vectors = p.jit->GetVectors();
    p.result.sp = p.jit->GetSP();
    p.result.pc = p.jit->GetPC();
    p.result.pstate = p.jit->GetPstate();
    p.result.fpsr = p.jit->GetFpsr();
    p.result.fpcr = p.jit->GetFpcr();
    if(p.services)if(const auto value=p.services->thread_exit_value(logical_tls)){p.result.fault=Fault::thread_exit;p.result.registers[0]=*value;p.result.returned=false;}
    if(const auto status=p.app.process_state->exit_status()){p.result.fault=Fault::process_exit;p.result.detail=*status;p.result.returned=false;}
    if (p.result.fault == Fault::process_exit || p.result.fault == Fault::thread_exit) {
        p.result.cpu_exception.reset();
    } else if (p.result.cpu_exception) {
        auto &state = p.result.cpu_exception->state;
        state.registers = p.result.registers;
        state.vectors = p.result.vectors;
        state.sp = p.result.sp;
        state.pstate = p.result.pstate;
        state.fpsr = p.result.fpsr;
        state.fpcr = p.result.fpcr;
    }
    p.result.returned = p.result.returned && p.result.fault == Fault::none;
    return p.result;
}
void GuestCpu::process_checkpoint() const {impl_->app.process_state->checkpoint();}
void GuestCpu::retain_initializer_context(const GuestInitializerContext &context) noexcept {
    impl_->app.process_state->retain_initializer_context(context);
}
const Metrics &GuestCpu::metrics() const noexcept { return impl_->stats; }
std::uint64_t GuestCpu::counter_frequency() const noexcept { return impl_->frequency; }
} // namespace aether::a64
