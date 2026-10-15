#include "aether/a64/selftest.hpp"
#include "aether/a64/selftest_code.hpp"
#include "aether/common/text.hpp"
#include <algorithm>
#include <bit>
#include <chrono>
#include <cmath>
#include <cstring>
#include <limits>
#include <numeric>
#include <sstream>
#include <windows.h>

namespace aether::a64 {
namespace {
constexpr Address data_address = 0x30000, stack_base = 0x80000, stack_top = stack_base + 0x10000;
template <class T> void store(GuestMemory &memory, Address address, const T &value) {
    if (!memory.write(address, {reinterpret_cast<const std::uint8_t *>(&value), sizeof(value)}))
        throw GuestError("AETHER_SELFTEST_SETUP", "Fixture data does not fit its mapping");
}
template <class T> T load(GuestMemory &memory, Address address) {
    T value{};
    if (!memory.read(address, {reinterpret_cast<std::uint8_t *>(&value), sizeof(value)}))
        throw GuestError("AETHER_SELFTEST_SETUP", "Fixture read does not fit its mapping");
    return value;
}
std::uint64_t integer_oracle(std::uint64_t a, std::uint64_t b) {
    return ((a * b) ^ std::rotr(a, 13)) + (b << 3);
}
} // namespace
SelftestReport translate_selftest() {
    SelftestReport report;
    GuestMemory memory;
    AppContext app{1, true};
    memory.map(fixture::base, GuestMemory::page_size, read_write);
    if (!memory.write(fixture::base, fixture::code))
        throw GuestError("AETHER_SELFTEST_SETUP", "Cannot populate ARM64 code");
    memory.protect(fixture::base, read_execute);
    memory.map(data_address, GuestMemory::page_size, read_write);
    memory.map(stack_base, 0x10000, read_write);
    GuestCpu cpu(memory, app);
    auto check = [&](std::string name, bool passed, std::string detail = {}) {
        report.checks.push_back({std::move(name), passed, std::move(detail)});
    };
    auto call = [&](Address entry, std::initializer_list<std::uint64_t> args = {},
                    std::uint64_t budget = 1'000'000) {
        return cpu.call(entry, {args.begin(), args.size()}, stack_top, budget);
    };
    auto success = [](const ExecutionResult &r, std::uint64_t expected) {
        return r.returned && r.fault == Fault::none && r.registers[0] == expected;
    };
    const auto initial = call(fixture::aether_add, {20, 22});
    check("arm64-add", success(initial, 42),
          "x0=" + std::to_string(initial.registers[0]) + "; " + std::string(fault_name(initial.fault)));
    bool arithmetic = true;
    std::uint64_t seed = 0x123456789abcdef0ull;
    for (unsigned i = 0; i < 128; ++i) {
        seed = seed * 6364136223846793005ull + 1442695040888963407ull;
        const auto a = seed;
        seed = seed * 6364136223846793005ull + 1442695040888963407ull;
        arithmetic &= success(call(fixture::aether_add, {a, seed}), a + seed);
        arithmetic &= success(call(fixture::aether_integer, {a, seed}), integer_oracle(a, seed));
    }
    check("integer-wrap-multiply-rotate", arithmetic,
          "256 calls compared with independent unsigned C++ arithmetic");
    bool loops = true;
    for (std::uint64_t i = 0; i < 32; ++i)
        loops &= success(call(fixture::aether_sum, {i}), i * (i + 1) / 2);
    check("branches-and-loops", loops, "32 triangular sums, including zero iterations");
    const auto stack = call(fixture::aether_call_stack, {37, 19});
    check("call-return-and-stack", success(stack, 93) && stack.sp == stack_top && stack.registers[19] == 0 &&
                                       stack.registers[29] == 0 &&
                                       stack.registers[30] == GuestCpu::return_trampoline);
    check("eight-argument-registers",
          success(call(fixture::aether_eight_args, {1, 3, 5, 7, 11, 13, 17, 19}), 76));
    constexpr std::uint64_t word = 0x123456789abcdef0ull;
    check("unaligned-load-store-widths",
          success(call(fixture::aether_memory, {data_address + 1, word}),
                  word + (word & 0xff) + (word & 0xffff) + (word & 0xffffffff)) &&
              load<std::uint64_t>(memory, data_address + 1) == word);
    const auto carry = call(fixture::aether_flags, {std::numeric_limits<std::uint64_t>::max(), 1});
    const auto overflow = call(fixture::aether_flags, {0x7fffffffffffffffull, 1});
    check("condition-flags", success(carry, 1) && carry.registers[1] == 0 &&
                                 (carry.pstate & 0xf0000000) == 0x60000000 && success(overflow, 0) &&
                                 overflow.registers[1] == 1 && (overflow.pstate & 0xf0000000) == 0x90000000);
    bool fp = true;
    for (double a : {-3.5, 0.0, 0.25, 1.5, 1024.0}) {
        const auto r =
            call(fixture::aether_fp, {std::bit_cast<std::uint64_t>(a), std::bit_cast<std::uint64_t>(2.0)});
        fp &= r.returned && std::bit_cast<double>(r.registers[0]) == a * 2.0 + a;
    }
    const auto nan =
        call(fixture::aether_fp, {std::bit_cast<std::uint64_t>(std::numeric_limits<double>::quiet_NaN()),
                                  std::bit_cast<std::uint64_t>(1.0)});
    check("scalar-fp-and-nan", fp && nan.returned && std::isnan(std::bit_cast<double>(nan.registers[0])));
    const std::array<std::uint32_t, 4> left{1, 2, 3, 0xffffffff}, right{11, 13, 17, 1},
        expected{12, 15, 20, 0};
    store(memory, data_address + 32, left);
    store(memory, data_address + 48, right);
    check(
        "simd-four-lanes",
        success(call(fixture::aether_simd, {data_address + 32, data_address + 48, data_address + 64}), 47) &&
            load<std::array<std::uint32_t, 4>>(memory, data_address + 64) == expected);
    store(memory, data_address, std::uint64_t{100});
    check("exclusive-atomic-increment", success(call(fixture::aether_atomic, {data_address}), 101) &&
                                            load<std::uint64_t>(memory, data_address) == 101);
    check("clrex-prevents-store", success(call(fixture::aether_exclusive_clear, {data_address}), 1) &&
                                      load<std::uint64_t>(memory, data_address) == 101);
    LARGE_INTEGER before{}, after{};
    const bool before_ok = QueryPerformanceCounter(&before) != FALSE;
    const auto time = call(fixture::aether_time);
    const bool after_ok = QueryPerformanceCounter(&after) != FALSE;
    report.counter_frequency = cpu.counter_frequency();
    check("windows-time-bridge",
          before_ok && after_ok && time.returned &&
              time.registers[0] >= static_cast<std::uint64_t>(before.QuadPart) &&
              time.registers[0] <= static_cast<std::uint64_t>(after.QuadPart) &&
              time.registers[1] == report.counter_frequency,
          "QueryPerformanceCounter ticks=" + std::to_string(time.registers[0]));
    check("supported-functions-use-jit-only", cpu.metrics().interpreter_fallbacks == 0);
    app.monotonic_time_allowed = false;
    check("time-capability-denial", call(fixture::aether_time).fault == Fault::capability_denied);
    app.monotonic_time_allowed = true;
    check("unknown-service-rejected", call(fixture::aether_bad_service).fault == Fault::unsupported_service);
    const auto unsupported = call(fixture::aether_bad_instruction);
    check("undefined-instruction-rejected",
          unsupported.fault == Fault::unsupported_instruction &&
              unsupported.fault_address == fixture::aether_bad_instruction &&
              cpu.metrics().interpreter_fallbacks == 1);
    check("unmapped-read-fault", call(fixture::aether_load, {0xdead0000}).fault == Fault::read);
    check("cross-boundary-read-fault",
          call(fixture::aether_load, {data_address + 4092}).fault == Fault::read);
    check("code-write-rejected", call(fixture::aether_store, {fixture::base, 0}).fault == Fault::write);
    check("data-execution-rejected", call(fixture::aether_jump, {data_address}).fault == Fault::execute);
    check("unmapped-execution-rejected", call(0xdead0000).fault == Fault::execute);
    check("loop-budget", call(fixture::aether_spin, {}, 1000).fault == Fault::budget);
    check("fault-recovery", success(call(fixture::aether_add, {9, 3}), 12));
    const auto cache_before = cpu.metrics();
    memory.protect(fixture::base, read_write);
    constexpr std::uint32_t sub_x0_x0_x1 = 0xcb010000;
    store(memory, fixture::base, sub_x0_x0_x1);
    memory.protect(fixture::base, read_execute);
    const auto patched = call(fixture::aether_add, {9, 3});
    check("code-cache-invalidation",
          success(patched, 6) && cpu.metrics().compiled_blocks > cache_before.compiled_blocks &&
              cpu.metrics().cache_invalidations == cache_before.cache_invalidations + 1);
    memory.protect(fixture::base, read_write);
    if (!memory.write(fixture::base, fixture::code))
        throw GuestError("AETHER_SELFTEST_SETUP", "Cannot restore fixture");
    memory.protect(fixture::base, read_execute);
    check("restored-code-result", success(call(fixture::aether_add, {9, 3}), 12));
    call(fixture::aether_integer, {1, 2}); // Explicit warm-up, measured separately from hot benchmark.
    const auto benchmark_before = cpu.metrics();
    const auto start = std::chrono::steady_clock::now();
    report.benchmark_iterations = 1000;
    std::uint64_t expected_checksum = 0;
    bool benchmark_returns = true;
    for (std::uint64_t i = 0; i < report.benchmark_iterations; ++i) {
        const auto a = i * 0x9e3779b97f4a7c15ull, b = i + 17;
        const auto r = call(fixture::aether_integer, {a, b});
        benchmark_returns &= r.returned;
        report.benchmark_checksum ^= r.registers[0];
        expected_checksum ^= integer_oracle(a, b);
    }
    report.benchmark_nanoseconds = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() - start)
            .count());
    check("deterministic-hot-benchmark",
          benchmark_returns && report.benchmark_checksum == expected_checksum &&
              cpu.metrics().compiled_blocks == benchmark_before.compiled_blocks &&
              cpu.metrics().cache_hits - benchmark_before.cache_hits == 2 * report.benchmark_iterations,
          "1000 calls; checksum=" + std::to_string(report.benchmark_checksum));
    check("guest-pages-never-host-executable", memory.host_pages_are_non_executable());
    SYSTEM_INFO system{};
    GetSystemInfo(&system);
    std::uintptr_t address = 0;
    bool protection_scan_ok = true;
    while (address < reinterpret_cast<std::uintptr_t>(system.lpMaximumApplicationAddress)) {
        MEMORY_BASIC_INFORMATION info{};
        if (!VirtualQuery(reinterpret_cast<const void *>(address), &info, sizeof(info)) || !info.RegionSize) {
            protection_scan_ok = false;
            break;
        }
        if (info.State == MEM_COMMIT && info.Type == MEM_PRIVATE &&
            (info.Protect & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
            ++report.private_writable_executable_regions;
        if (info.RegionSize > std::numeric_limits<std::uintptr_t>::max() - address)
            break;
        address += info.RegionSize;
    }
    check("no-private-writable-executable-regions",
          protection_scan_ok && report.private_writable_executable_regions == 0);
    report.metrics = cpu.metrics();
    check("jit-emission-and-rx-evidence",
          report.metrics.compiled_blocks > 20 && report.metrics.emitted_bytes > 0 &&
              report.metrics.compile_nanoseconds > 0 &&
              report.metrics.rx_checks == report.metrics.compiled_blocks && report.metrics.rx_failures == 0 &&
              report.metrics.last_code_fingerprint != 0);
    return report;
}
bool SelftestReport::passed() const {
    return !checks.empty() &&
           std::all_of(checks.begin(), checks.end(), [](const Check &c) { return c.passed; });
}
std::string SelftestReport::json() const {
    std::ostringstream out;
    out << "{\"schemaVersion\":1,\"command\":\"translate-selftest\",\"passed\":"
        << (passed() ? "true" : "false")
        << ",\"engine\":\"Dynarmic A64-to-x86_64 "
           "JIT\",\"mode\":\"self-authored-fixtures-only\",\"androidOsStarted\":false,\"checks\":[";
    for (std::size_t i = 0; i < checks.size(); ++i) {
        if (i)
            out << ',';
        out << "{\"name\":" << json_quote(checks[i].name)
            << ",\"passed\":" << (checks[i].passed ? "true" : "false")
            << ",\"detail\":" << json_quote(checks[i].detail) << '}';
    }
    out << "],\"metrics\":{\"compiledBlocks\":" << metrics.compiled_blocks
        << ",\"emittedBytes\":" << metrics.emitted_bytes
        << ",\"compileNanoseconds\":" << metrics.compile_nanoseconds
        << ",\"blockLookups\":" << metrics.block_lookups << ",\"cacheHits\":" << metrics.cache_hits
        << ",\"cacheInvalidations\":" << metrics.cache_invalidations
        << ",\"executionNanosecondsIncludingCompilation\":" << metrics.execution_nanoseconds
        << ",\"guestTicks\":" << metrics.guest_ticks << ",\"hostCalls\":" << metrics.host_calls
        << ",\"memoryReads\":" << metrics.memory_reads << ",\"memoryWrites\":" << metrics.memory_writes
        << ",\"rejectedInterpreterFallbackRequests\":" << metrics.interpreter_fallbacks
        << ",\"interpretedInstructions\":0,\"expectedFaults\":" << metrics.faults
        << ",\"rxChecks\":" << metrics.rx_checks << ",\"rxFailures\":" << metrics.rx_failures
        << ",\"lastCodeFingerprint\":" << metrics.last_code_fingerprint
        << "},\"privateWritableExecutableRegions\":" << private_writable_executable_regions
        << ",\"counterFrequency\":" << counter_frequency
        << ",\"benchmark\":{\"iterations\":" << benchmark_iterations << ",\"checksum\":" << benchmark_checksum
        << ",\"nanoseconds\":" << benchmark_nanoseconds << "}}";
    return out.str();
}
std::string SelftestReport::text(bool verbose) const {
    std::ostringstream out;
    out << "ARM64 translation self-test: " << (passed() ? "PASS" : "FAIL") << " (" << checks.size()
        << " checks)\n"
        << "Engine: Dynarmic A64 -> x86-64 JIT; self-authored fixtures only; no Android OS\n"
        << "JIT: " << metrics.compiled_blocks << " compiled blocks, " << metrics.emitted_bytes
        << " emitted bytes, " << metrics.cache_hits << " cache hits, " << metrics.interpreter_fallbacks
        << " rejected fallback requests\n"
        << "RX checks: " << metrics.rx_checks << "; failures: " << metrics.rx_failures
        << "; Windows calls: " << metrics.host_calls << '\n'
        << "Hot benchmark: " << benchmark_iterations << " calls in " << benchmark_nanoseconds
        << " ns; checksum " << benchmark_checksum << '\n';
    if (verbose || !passed())
        for (const auto &c : checks)
            out << (c.passed ? "  PASS " : "  FAIL ") << c.name << (c.detail.empty() ? "" : ": " + c.detail)
                << '\n';
    return out.str();
}
} // namespace aether::a64
