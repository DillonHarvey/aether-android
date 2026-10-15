#include "aether/a64/guest_cpu.hpp"
#include <algorithm>
#include <chrono>
#include <cstring>
#include <dynarmic/interface/A64/a64.h>
#include <dynarmic/interface/A64/config.h>
#include <dynarmic/interface/exclusive_monitor.h>
#include <limits>
#include <windows.h>

namespace aether::a64 {
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
    std::uint64_t tpidr = 0, tpidr_read_only = 0;
    const DWORD owner_thread = GetCurrentThreadId();
    bool service_pending = false, dispatching_service = false;
    std::uint32_t pending_service = 0, call_depth = 0;
    Address service_instruction = 0;

    Impl(GuestMemory &memory_, const AppContext &app_, GuestServices *services_)
        : memory(memory_), app(app_), services(services_) {
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
            ++stats.faults;
        }
        jit->HaltExecution();
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
        stop(Fault::unsupported_instruction, pc, static_cast<std::uint32_t>(count));
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
    void ExceptionRaised(Address pc, Dynarmic::A64::Exception exception) override {
        stop(exception == Dynarmic::A64::Exception::NoExecuteFault ? Fault::execute
                                                                   : Fault::unsupported_instruction,
             pc, static_cast<std::uint32_t>(exception));
    }
    void DataCacheOperationRaised(Dynarmic::A64::DataCacheOperation op, Address value) override {
        stop(Fault::unsupported_instruction, value, static_cast<std::uint32_t>(op));
    }
    void InstructionCacheOperationRaised(Dynarmic::A64::InstructionCacheOperation op,
                                         Address value) override {
        stop(Fault::unsupported_instruction, value, static_cast<std::uint32_t>(op));
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
ExecutionResult GuestCpu::call(Address entry, std::span<const std::uint64_t> arguments, Address stack_top,
                               std::uint64_t instruction_budget, std::span<const Vector> floating_arguments) {
    auto &p = *impl_;
    if (GetCurrentThreadId() != p.owner_thread || p.jit->IsExecuting() ||
        (p.call_depth && !p.dispatching_service))
        throw GuestError("AETHER_GUEST_CPU_OWNERSHIP",
                         "Nested calls require a suspended service on the CPU owner thread");
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
    struct SavedFrame {
        Impl &p;
        ExecutionResult result;
        std::array<std::uint64_t, 31> registers;
        std::array<Vector, 32> vectors;
        Address pc, sp;
        std::uint32_t pstate, fpsr, fpcr;
        std::uint64_t remaining, ticks;
        bool dispatching, nested;
        ~SavedFrame() {
            --p.call_depth;
            p.dispatching_service = dispatching;
            p.service_pending = false;
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
            p.dispatching_service,
            p.call_depth != 0};
    ++p.call_depth;
    p.stats.maximum_call_depth = std::max<std::uint64_t>(p.stats.maximum_call_depth, p.call_depth);
    if (saved.nested)
        ++p.stats.nested_calls;
    p.dispatching_service = false;
    p.service_pending = false;
    p.result = {};
    p.jit->Reset();
    p.monitor.Clear();
    p.remaining = saved.nested ? std::min(instruction_budget, saved.remaining) : instruction_budget;
    p.jit->SetPC(entry);
    p.jit->SetSP(stack_top);
    p.jit->SetRegister(30, return_trampoline);
    for (std::size_t i = 0; i < arguments.size(); ++i)
        p.jit->SetRegister(i, arguments[i]);
    for (std::size_t i = 0; i < floating_arguments.size(); ++i)
        p.jit->SetVector(i, floating_arguments[i]);
    for (;;) {
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
        if (!p.service_pending || p.result.fault != Fault::none || p.result.returned)
            break;
        const auto service = p.pending_service;
        const auto instruction = p.service_instruction;
        p.service_pending = false;
        ServiceState state{p.jit->GetRegisters(), p.jit->GetVectors(), p.jit->GetSP()};
        p.dispatching_service = true;
        ++p.stats.host_calls;
        ++p.stats.deferred_services;
        const auto fault = p.services->invoke_frame(service, instruction, state);
        p.dispatching_service = false;
        if (fault != Fault::none) {
            p.stop(fault, instruction, service);
            break;
        }
        p.jit->SetRegisters(state.registers);
        p.jit->SetVectors(state.vectors);
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
    p.result.returned = p.result.returned && p.result.fault == Fault::none;
    return p.result;
}
const Metrics &GuestCpu::metrics() const noexcept { return impl_->stats; }
std::uint64_t GuestCpu::counter_frequency() const noexcept { return impl_->frequency; }
} // namespace aether::a64
