#include "aether/elf/selftest.hpp"
#include "aether/apk/inspect.hpp"
#include "aether/common/text.hpp"
#include "aether/elf/fixture_hashes.hpp"
#include <algorithm>
#include <array>
#include <set>
#include <sstream>
#include <windows.h>

namespace aether::elf {
namespace {
std::uint64_t read_value(const a64::GuestMemory &memory, Address address, std::size_t size) {
    std::array<std::uint8_t, 8> bytes{};
    if (size > bytes.size() || !memory.read(address, std::span{bytes}.first(size)))
        throw ElfError("AETHER_NATIVE_SELFTEST_MEMORY", "Cannot read a fixture result from guest memory");
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < size; ++i)
        value |= std::uint64_t{bytes[i]} << (8 * i);
    return value;
}
std::uint64_t clock_ns(const host::HostTimeService &time) {
    host::MonotonicTime value;
    if (!time.monotonic(value))
        throw ElfError("AETHER_HOST_TIME_FAILED", "Cannot bracket native guest time");
    return value.seconds * 1'000'000'000 + value.nanoseconds;
}
} // namespace
NativeSelftestReport native_selftest(const std::filesystem::path &fixture_path) {
    NativeSelftestReport report;
    apk::InspectLimits limits;
    limits.archive_bytes = 64 * 1024 * 1024;
    const auto bytes = apk::read_package(fixture_path, limits);
    report.fixture_sha256 = apk::sha256(bytes);
    if (report.fixture_sha256 != fixture::aether_fixture_sha256)
        throw ElfError("AETHER_NATIVE_FIXTURE_NOT_TRUSTED",
                       "Only the exact built-in first-party NDK fixture may execute before Phase 7");
    const auto dependency = apk::read_package(fixture_path.parent_path() / "libaether_support.so", limits);
    report.dependency_sha256 = apk::sha256(dependency);
    if (report.dependency_sha256 != fixture::aether_support_sha256)
        throw ElfError("AETHER_NATIVE_FIXTURE_NOT_TRUSTED",
                       "Native dependency does not match the first-party fixture hash");
    const auto check = [&](std::string name, bool passed, std::string detail = {}) {
        report.checks.push_back({std::move(name), passed, std::move(detail)});
    };
    a64::GuestMemory memory;
    a64::AppContext app{3, true};
    host::HostTimeService time;
    std::wstring executable_path(32768, L'\0');
    const auto path_length =
        GetModuleFileNameW(nullptr, executable_path.data(), static_cast<DWORD>(executable_path.size()));
    if (!path_length || path_length >= executable_path.size())
        throw ElfError("AETHER_NATIVE_SELFTEST_STORAGE", "Cannot locate the development evidence directory");
    executable_path.resize(path_length);
    const auto data_root = std::filesystem::path(executable_path).parent_path() / "native-selftest-data";
    std::filesystem::create_directories(data_root);
    host::HostFileService files(data_root);
    bionic::GuestPosixServices services(memory, app, time, 1, &files);
    GuestLoader loader(memory, services);
    const std::array inputs{ModuleInput{"libaether_fixture.so", bytes},
                            ModuleInput{"libaether_support.so", dependency}};
    loader.load(inputs, "libaether_fixture.so");
    constexpr Address data = 0x30000000, stack = 0x31000000, stack_top = stack + 65536;
    memory.map(data, 8192, a64::read_write);
    memory.map(stack, 65536, a64::read_write);
    a64::GuestCpu cpu(memory, app, &services);
    const auto symbol = [&](std::string_view name) {
        return loader.symbol("libaether_fixture.so", name).address;
    };
    const auto call = [&](std::string_view name, std::initializer_list<std::uint64_t> args) {
        const auto result = cpu.call(symbol(name), {args.begin(), args.size()}, stack_top);
        if (!result.returned)
            throw ElfError("AETHER_NATIVE_SELFTEST_EXECUTION",
                           std::string(name) + " failed: " + std::string(a64::fault_name(result.fault)) +
                               "; " + std::string(services.last_rejection()));
        return result.registers[0];
    };
    const auto state = symbol("aether_state");
    const auto support_state = loader.symbol("libaether_support.so", "aether_support_state").address;
    check("bss-starts-zero", read_value(memory, state, 4) == 0 && read_value(memory, support_state, 4) == 0,
          "root=" + std::to_string(read_value(memory, state, 4)) +
              "; dependency=" + std::to_string(read_value(memory, support_state, 4)));
    loader.initialize(cpu, stack_top);
    check("dependency-constructors-first",
          read_value(memory, state, 4) == 117 && read_value(memory, support_state, 4) == 17);
    check("guest-dependency-symbol-version",
          loader.symbol("libaether_support.so", "aether_support_value").version == "AETHER_1.0");
    report.addition = call("aether_add", {20, 22});
    check("ndk-export-through-jit", report.addition == 42);
    bool arithmetic = true;
    for (std::uint32_t i = 0; i < 128; ++i)
        arithmetic &= call("aether_add", {i * 7, i * 3}) == i * 10;
    check("repeated-native-arithmetic", arithmetic);
    check("abs64-data-pointer", read_value(memory, symbol("aether_data_pointer"), 8) == state);
    check("abs64-function-pointer",
          read_value(memory, symbol("aether_function_pointer"), 8) == symbol("aether_add"));
    report.indirect_addition = call("aether_indirect_add", {20, 22});
    check("glob-dat-and-indirect-call", report.indirect_addition == 159);
    const auto greeting = call("aether_greeting", {});
    const auto length = call("aether_string_length", {greeting});
    std::array<std::uint8_t, 16> text{};
    const auto text_read = memory.read(greeting, text);
    report.greeting = {text.begin(), text.end()};
    check("guest-string-and-libc-strlen",
          length == text.size() && text_read && report.greeting == "Aether ARM64 ELF");
    constexpr std::array<std::uint8_t, 8> source{3, 1, 4, 1, 5, 9, 2, 6};
    if (!memory.write(data, source))
        throw ElfError("AETHER_NATIVE_SELFTEST_MEMORY", "Cannot prepare memory fixture");
    report.copy_sum = call("aether_copy_and_sum", {data + 4096, data, source.size()});
    std::array<std::uint8_t, 8> copied{};
    check("libc-copy-and-guest-loads",
          report.copy_sum == 31 && memory.read(data + 4096, copied) && copied == source);
    check("malloc-memset-memmove-free",
          call("aether_memory_services", {}) == 17 && services.metrics().allocated_bytes == 0);
    check("logical-thread-id", call("aether_thread_id", {}) == 1);
    const auto error = call("aether_errno_address", {});
    check("guest-errno-pointer", error == bionic::GuestPosixServices::errno_address);
    report.clock_before = clock_ns(time);
    report.clock_guest = call("aether_clock_ns", {});
    report.clock_after = clock_ns(time);
    check("bionic-clock-reaches-windows",
          report.clock_before <= report.clock_guest && report.clock_guest <= report.clock_after);
    check("invalid-clock-errno",
          call("aether_clock_errno", {999, data}) == 22 && read_value(memory, error, 4) == 22);
    check("bad-timespec-pointer-errno",
          call("aether_clock_errno", {1, 0}) == 14 && read_value(memory, error, 4) == 14);
    app.monotonic_time_allowed = false;
    check("clock-capability-denied",
          call("aether_clock_errno", {1, data}) == 13 && read_value(memory, error, 4) == 13);
    app.monotonic_time_allowed = true;
    check("success-preserves-errno",
          call("aether_clock_errno", {1, data}) == 0 && read_value(memory, error, 4) == 13);
    check("timespec-arm64-layout",
          read_value(memory, data, 8) > 0 && read_value(memory, data + 8, 8) < 1'000'000'000);
    constexpr std::string_view file_name = "proof.txt",
                               file_content = "Aether guest ELF -> scoped Windows file\n";
    const auto write_string = [&](Address at, std::string_view value) {
        std::vector<std::uint8_t> buffer(value.begin(), value.end());
        buffer.push_back(0);
        if (!memory.write(at, buffer))
            throw ElfError("AETHER_NATIVE_SELFTEST_MEMORY", "Cannot prepare guest file arguments");
    };
    write_string(data + 128, file_name);
    write_string(data + 256, file_content);
    std::vector<std::uint8_t> file_result(file_content.size());
    check("scoped-windows-file-roundtrip",
          call("aether_file_roundtrip", {data + 128, data + 256, data + 512, file_content.size()}) ==
                  file_content.size() &&
              memory.read(data + 512, file_result) &&
              std::string(file_result.begin(), file_result.end()) == file_content);
    write_string(data + 128, "../outside.txt");
    check("guest-file-traversal-denied", call("aether_file_errno", {data + 128}) == 13);
    write_string(data + 128, "missing-first-party-fixture.txt");
    check("missing-file-errno", call("aether_file_errno", {data + 128}) == 2);
    bool relro = true, code = true;
    std::set<std::uint32_t> types;
    for (const auto &module : loader.modules()) {
        if (module.image.relro_end)
            relro &= memory.accessible(module.base + module.image.relro_begin, 1, a64::Permission::read) &&
                     !memory.accessible(module.base + module.image.relro_begin, 1, a64::Permission::write);
        for (const auto &segment : module.image.segments)
            if (a64::has(segment.permissions, a64::Permission::execute))
                code &= memory.accessible(module.base + segment.address, 4, a64::Permission::execute) &&
                        !memory.accessible(module.base + segment.address, 4, a64::Permission::write);
        for (const auto &relocation : module.image.relocations)
            types.insert(relocation.type);
    }
    check("gnu-relro-read-only", relro);
    check("guest-code-read-execute", code);
    check("all-four-relocation-types", types == std::set<std::uint32_t>{257, 1025, 1026, 1027});
    const auto unsupported = services.resolve("libc.so", "__cxa_atexit", "LIBC");
    const auto rejected = cpu.call(unsupported->address, {}, stack_top);
    check("unsupported-callback-registration-fails",
          !rejected.returned && rejected.fault == a64::Fault::unsupported_service);
    loader.finalize(cpu, stack_top);
    check("reverse-dependency-finalizers",
          read_value(memory, state, 4) == 217 && read_value(memory, support_state, 4) == 31);
    const auto blocks = cpu.metrics().block_lookups;
    loader.finalize(cpu, stack_top);
    check("finalizers-run-once", cpu.metrics().block_lookups == blocks);
    check("guest-pages-never-host-executable", memory.host_pages_are_non_executable());
    report.metrics = cpu.metrics();
    report.services = services.metrics();
    report.modules = loader.modules().size();
    report.relocations = loader.relocation_count();
    report.relocation_types.assign(types.begin(), types.end());
    check("actual-jit-emission", report.metrics.compiled_blocks > 10 && report.metrics.emitted_bytes > 0 &&
                                     report.metrics.rx_checks == report.metrics.compiled_blocks &&
                                     report.metrics.rx_failures == 0 &&
                                     report.metrics.interpreter_fallbacks == 0);
    return report;
}
bool NativeSelftestReport::passed() const {
    return !checks.empty() &&
           std::all_of(checks.begin(), checks.end(), [](const auto &c) { return c.passed; });
}
std::string NativeSelftestReport::json() const {
    std::ostringstream out;
    out << "{\"schemaVersion\":1,\"command\":\"native-selftest\",\"passed\":" << (passed() ? "true" : "false")
        << ",\"mode\":\"self-authored-fixtures-only\",\"androidOsStarted\":false,\"windowsLoadLibraryUsed\":"
           "false"
        << ",\"fixtureSha256\":" << json_quote(fixture_sha256)
        << ",\"dependencySha256\":" << json_quote(dependency_sha256) << ",\"modules\":" << modules
        << ",\"relocations\":" << relocations << ",\"relocationTypes\":[";
    for (std::size_t i = 0; i < relocation_types.size(); ++i) {
        if (i)
            out << ',';
        out << relocation_types[i];
    }
    out << "],\"addition\":" << addition << ",\"indirectAddition\":" << indirect_addition
        << ",\"copySum\":" << copy_sum << ",\"greeting\":" << json_quote(greeting)
        << ",\"clock\":{\"before\":" << clock_before << ",\"guest\":" << clock_guest
        << ",\"after\":" << clock_after << "},\"checks\":[";
    for (std::size_t i = 0; i < checks.size(); ++i) {
        if (i)
            out << ',';
        out << "{\"name\":" << json_quote(checks[i].name)
            << ",\"passed\":" << (checks[i].passed ? "true" : "false")
            << ",\"detail\":" << json_quote(checks[i].detail) << '}';
    }
    out << "],\"metrics\":{\"compiledBlocks\":" << metrics.compiled_blocks
        << ",\"emittedBytes\":" << metrics.emitted_bytes << ",\"cacheHits\":" << metrics.cache_hits
        << ",\"cacheInvalidations\":" << metrics.cache_invalidations
        << ",\"hostCalls\":" << metrics.host_calls << ",\"guestTicks\":" << metrics.guest_ticks
        << ",\"rxChecks\":" << metrics.rx_checks << ",\"rxFailures\":" << metrics.rx_failures
        << ",\"rejectedInterpreterFallbackRequests\":" << metrics.interpreter_fallbacks
        << ",\"expectedFaults\":" << metrics.faults << "},\"services\":{\"calls\":" << services.calls
        << ",\"clockReads\":" << services.clock_reads << ",\"allocations\":" << services.allocations
        << ",\"frees\":" << services.frees << ",\"allocatedBytes\":" << services.allocated_bytes
        << ",\"errors\":" << services.errors << ",\"rejectedOperations\":" << services.rejected_operations
        << ",\"fileOperations\":" << services.file_operations
        << "},\"fileArtifact\":\"native-selftest-data/proof.txt\"}";
    return out.str();
}
std::string NativeSelftestReport::text(bool verbose) const {
    std::ostringstream out;
    out << "Android ARM64 ELF self-test: " << (passed() ? "PASS" : "FAIL") << " (" << checks.size()
        << " checks)\n"
        << "Developer-only first-party NDK fixtures; Dynarmic JIT; no Android OS or Windows LoadLibrary\n"
        << modules << " guest modules, " << relocations << " relocations; addition " << addition << "; "
        << greeting << '\n'
        << "JIT: " << metrics.compiled_blocks << " blocks, " << metrics.emitted_bytes << " emitted bytes; "
        << services.clock_reads << " Windows clock reads\n";
    if (verbose || !passed())
        for (const auto &c : checks)
            out << (c.passed ? "  PASS " : "  FAIL ") << c.name << '\n';
    return out.str();
}
} // namespace aether::elf
