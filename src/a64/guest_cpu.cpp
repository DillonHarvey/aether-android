#include "aether/a64/guest_cpu.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <dynarmic/interface/A64/a64.h>
#include <dynarmic/interface/A64/config.h>
#include <dynarmic/interface/exclusive_monitor.h>
#include <dynarmic/interface/halt_reason.h>
#include <limits>
#include <windows.h>

namespace aether::a64 {
namespace {
// Match CTR_EL0's 16-word minimum cache lines. Guest bytes are ordinary,
// coherent host data; translated x86 code has its own checked W^X cache.
constexpr std::size_t guest_cache_line_size = 64;
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
std::uint64_t next_invocation() noexcept {
    auto value=invocation_sequence.load(std::memory_order_relaxed);
    while(value!=UINT64_MAX){if(invocation_sequence.compare_exchange_weak(value,value+1,std::memory_order_relaxed))return value;}
    return 0;
}
}
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
struct GuestCpu::Impl final : Dynarmic::A64::UserCallbacks {
    GuestMemory &memory;
    const AppContext &app;
    GuestServices *services;
    Metrics stats;
    ExecutionResult result;
    Dynarmic::ExclusiveMonitor monitor{1};
    std::unique_ptr<Dynarmic::A64::Jit> jit;
    std::uint64_t remaining = 0, memory_generation = 0, frequency = 0;
    std::uint64_t tpidr = 0, tpidr_read_only = 0, default_tpidr = 0;
    const DWORD owner_thread = GetCurrentThreadId();
    bool service_pending = false, dispatching_service = false;
    bool yield_pending = false;
    std::optional<Address> instruction_cache_pending;
    std::optional<ScalarLseFallback> scalar_lse_pending;
    std::uint32_t pending_service = 0, call_depth = 0;
    Address service_instruction = 0;
    std::uint64_t active_invocation = 0;

    Impl(GuestMemory &memory_, const AppContext &app_, GuestServices *services_)
        : memory(memory_), app(app_), services(services_) {
        if(!app.process_state)throw GuestError("AETHER_GUEST_CONTEXT","Guest process state is required");
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
        memory_generation = memory.generation();
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
    template <class T> T read(Address address) noexcept {
        T value{};
        ++stats.memory_reads;
        if (!memory.read(address, {reinterpret_cast<std::uint8_t *>(&value), sizeof(value)}))
            stop(Fault::read, address);
        return value;
    }
    template <class T> void write(Address address, T value) noexcept {
        ++stats.memory_writes;
        if (!memory.write(address, {reinterpret_cast<const std::uint8_t *>(&value), sizeof(value)}))
            stop(Fault::write, address);
    }
    template <class T> bool exclusive(Address address, T value, T expected) noexcept {
        if (address % sizeof(T)) {
            stop(Fault::write, address);
            return false;
        }
        if (read<T>(address) != expected || result.fault != Fault::none)
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
                stop(Fault::execute, pc);
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
        if ((decoded.base == 31 && address % 16) || address % decoded.bytes) {
            stop(Fault::alignment, address, pending.instruction);
            return;
        }
        if (!memory.accessible(address, decoded.bytes, Permission::read)) {
            stop(Fault::read, address, pending.instruction);
            return;
        }
        // An atomic is a read/write access, including a failed CAS comparison.
        // Preflight the entire range before reading or modifying guest state.
        if (!memory.accessible(address, decoded.bytes, Permission::write)) {
            stop(Fault::write, address, pending.instruction);
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
            stop(Fault::read, address, pending.instruction);
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
                stop(Fault::write, address, pending.instruction);
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
    std::uint64_t counter() noexcept {
        if (!app.monotonic_time_allowed) {
            stop(Fault::capability_denied);
            return 0;
        }
        LARGE_INTEGER value{};
        ++stats.host_calls;
        if (!QueryPerformanceCounter(&value)) {
            stop(Fault::windows_service);
            return 0;
        }
        return static_cast<std::uint64_t>(value.QuadPart);
    }
    void CallSVC(std::uint32_t service) override {
        if (service == 0xffff && jit->GetPC() == return_trampoline + 4) {
            result.returned = true;
            jit->HaltExecution();
        } else if (service == 1) {
            const auto ticks = counter();
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
        stop(Fault::alignment, address, static_cast<std::uint32_t>(Dynarmic::A64::Exception::DataAlignment));
    }
    void ExceptionRaised(Address pc, Dynarmic::A64::Exception exception) override {
        if (exception == Dynarmic::A64::Exception::StackPointerAlignment) {
            // The backend has materialized the exact captured live SP and PC,
            // before any effective-address offset, memory access or writeback.
            stop(Fault::alignment, jit->GetSP(), static_cast<std::uint32_t>(exception));
            return;
        }
        if (exception == Dynarmic::A64::Exception::Yield) {
            // The frontend already advanced PC by four. Perform the host
            // scheduling hint only after returning out of generated frames.
            yield_pending = true;
            jit->HaltExecution();
            return;
        }
        stop(exception == Dynarmic::A64::Exception::NoExecuteFault ? Fault::execute
                                                                   : Fault::unsupported_instruction,
             pc, static_cast<std::uint32_t>(exception));
    }
    void DataCacheOperationRaised(Dynarmic::A64::DataCacheOperation op, Address value) override {
        if (op == Dynarmic::A64::DataCacheOperation::CleanByVAToPoU) {
            if (!memory.accessible(value, 1, Permission::read)) {
                stop(Fault::read, value);
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
                stop(Fault::read, value);
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
        remaining = ticks >= remaining ? 0 : remaining - ticks;
    }
    std::uint64_t GetTicksRemaining() override { return remaining; }
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
    p.default_tpidr=p.tpidr=address;
}
ExecutionResult GuestCpu::call(Address entry, std::span<const std::uint64_t> arguments, Address stack_top,
                               std::uint64_t instruction_budget, std::span<const Vector> floating_arguments, std::optional<Address> thread_pointer) {
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
    if (arguments.size() > 8 || floating_arguments.size() > 8 || entry % 4 || stack_top % 16 ||
        stack_top < 16 || !p.memory.accessible(stack_top - 16, 16, Permission::write) ||
        !instruction_budget || instruction_budget > 10'000'000) {
        ExecutionResult invalid;
        invalid.fault = Fault::invalid_call;
        ++p.stats.faults;
        return invalid;
    }
    const auto invocation=next_invocation();
    if(!invocation){ExecutionResult invalid;invalid.fault=Fault::invalid_call;++p.stats.faults;return invalid;}
    struct SavedFrame {
        Impl &p;
        ExecutionResult result;
        std::array<std::uint64_t, 31> registers;
        std::array<Vector, 32> vectors;
        Address pc, sp;
        std::uint32_t pstate, fpsr, fpcr;
        std::uint64_t remaining, ticks, tpidr, tpidr_read_only, invocation;
        bool dispatching, nested;
        ~SavedFrame() {
            --p.call_depth;
            p.dispatching_service = dispatching;
            p.service_pending = false;
            p.yield_pending = false;
            p.instruction_cache_pending.reset();
            p.scalar_lse_pending.reset();
            p.tpidr=tpidr;p.tpidr_read_only=tpidr_read_only;p.active_invocation=invocation;
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
            const auto spent = p.stats.guest_ticks - ticks;
            p.remaining = spent >= remaining ? 0 : remaining - spent;
        }
    } saved{p,
            p.result,
            p.jit->GetRegisters(),
            p.jit->GetVectors(),
            p.jit->GetPC(),
            p.jit->GetSP(),
            p.jit->GetPstate(),
            p.jit->GetFpsr(),
            p.jit->GetFpcr(),
            p.remaining,
            p.stats.guest_ticks,
            p.tpidr,p.tpidr_read_only,p.active_invocation,
            p.dispatching_service,
            p.call_depth != 0};
    p.active_invocation=invocation;
    ++p.call_depth;
    p.stats.maximum_call_depth = std::max<std::uint64_t>(p.stats.maximum_call_depth, p.call_depth);
    if (saved.nested)
        ++p.stats.nested_calls;
    p.dispatching_service = false;
    p.service_pending = false;
    p.yield_pending = false;
    p.instruction_cache_pending.reset();
    p.scalar_lse_pending.reset();
    p.result = {};
    p.jit->Reset();
    p.monitor.Clear();
    p.remaining = saved.nested ? std::min(instruction_budget, saved.remaining) : instruction_budget;
    p.tpidr=thread_pointer.value_or(p.default_tpidr);
    p.jit->SetPC(entry);
    p.jit->SetSP(stack_top);
    p.jit->SetRegister(30, return_trampoline);
    for (std::size_t i = 0; i < arguments.size(); ++i)
        p.jit->SetRegister(i, arguments[i]);
    for (std::size_t i = 0; i < floating_arguments.size(); ++i)
        p.jit->SetVector(i, floating_arguments[i]);
    for (;;) {
        if(p.app.process_state->exit_status()){p.stop(Fault::process_exit,p.jit->GetPC());break;}
        if(p.services && p.services->thread_exit_value(logical_tls)){p.stop(Fault::thread_exit,p.jit->GetPC());break;}
        if(p.services && p.services->event_pending()){
            ServiceState state{p.jit->GetRegisters(),p.jit->GetVectors(),p.jit->GetSP(),p.active_invocation,stack_top};
            p.dispatching_service=true;
            const auto fault=p.services->checkpoint(state);
            p.dispatching_service=false;
            if(p.app.process_state->exit_status()){p.stop(Fault::process_exit,p.jit->GetPC());break;}
            if(p.services->thread_exit_value(logical_tls)){p.stop(Fault::thread_exit,p.jit->GetPC());break;}
            if(fault!=Fault::none){p.stop(fault,p.jit->GetPC());break;}
            p.jit->ClearExclusiveState();p.monitor.Clear();
        }
        if (!p.remaining) {
            p.stop(Fault::budget, p.jit->GetPC());
            break;
        }
        if (p.memory_generation != p.memory.generation()) {
            p.jit->ClearCache();
            p.memory_generation = p.memory.generation();
            ++p.stats.cache_invalidations;
        }
        p.jit->ClearHalt();
        const auto start = std::chrono::steady_clock::now();
        p.jit->Run();
        p.stats.execution_nanoseconds += static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() - start)
                .count());
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
        if(!p.service_pending && p.result.fault==Fault::none && !p.result.returned && p.services && p.services->event_pending())continue;
        if (!p.service_pending || p.result.fault != Fault::none || p.result.returned)
            break;
        const auto service = p.pending_service;
        const auto instruction = p.service_instruction;
        p.service_pending = false;
        ServiceState state{p.jit->GetRegisters(), p.jit->GetVectors(), p.jit->GetSP(),p.active_invocation,stack_top};
        p.dispatching_service = true;
        ++p.stats.host_calls;
        ++p.stats.deferred_services;
        const auto fault = p.services->invoke_frame(service, instruction, state);
        p.dispatching_service = false;
        if(p.app.process_state->exit_status()){p.stop(Fault::process_exit,instruction);break;}
        if(p.services && p.services->thread_exit_value(logical_tls)){p.stop(Fault::thread_exit,instruction);break;}
        if (fault != Fault::none) {
            p.stop(fault, instruction, service);
            break;
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
    p.result.returned = p.result.returned && p.result.fault == Fault::none;
    return p.result;
}
void GuestCpu::process_checkpoint() const {impl_->app.process_state->checkpoint();}
const Metrics &GuestCpu::metrics() const noexcept { return impl_->stats; }
std::uint64_t GuestCpu::counter_frequency() const noexcept { return impl_->frequency; }
} // namespace aether::a64
