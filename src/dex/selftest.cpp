#include "aether/dex/selftest.hpp"
#include "aether/apk/archive.hpp"
#include "aether/common/text.hpp"
#include "aether/dex/bytecode.hpp"
#include "aether/dex/fixture_hash.hpp"
#include "aether/elf/fixture_hashes.hpp"
#include <algorithm>
#include <bit>
#include <sstream>

namespace aether::dex {
ManagedSelftestReport managed_selftest(const std::filesystem::path &path) {
    ManagedSelftestReport report;
    apk::InspectLimits limits;
    limits.archive_bytes = 64 * 1024 * 1024;
    const auto bytes = apk::read_package(path, limits);
    report.apk_sha256 = apk::sha256(bytes);
    if (report.apk_sha256 != fixture::apk_sha256)
        throw DexError("AETHER_DEX_FIXTURE_NOT_TRUSTED",
                       "Only the exact built-in first-party APK may execute before Phase 7");
    apk::Archive archive(bytes, limits);
    const auto entry = [&](std::string_view name) {
        for (std::size_t i = 0; i < archive.entries().size(); ++i)
            if (archive.entries()[i].path == name)
                return archive.read(i);
        throw DexError("AETHER_DEX_FIXTURE_ENTRY", "Required first-party APK entry is absent");
    };
    const auto dex = entry("classes.dex"), root = entry("lib/arm64-v8a/libaether_fixture.so"),
               support = entry("lib/arm64-v8a/libaether_support.so");
    report.dex_sha256 = apk::sha256(dex);
    report.native_sha256 = apk::sha256(root);
    if (report.native_sha256 != elf::fixture::aether_fixture_sha256 ||
        apk::sha256(support) != elf::fixture::aether_support_sha256)
        throw DexError("AETHER_DEX_FIXTURE_NOT_TRUSTED",
                       "APK native entries differ from the reviewed native fixture registry");
    ManagedRuntime runtime(parse(dex));
    a64::GuestMemory memory;
    a64::AppContext app{4, true};
    host::HostTimeService time;
    const std::array inputs{elf::ModuleInput{"libaether_fixture.so", root},
                            elf::ModuleInput{"libaether_support.so", support}};
    jni::Bridge bridge(runtime, memory, app, time, inputs, "libaether_fixture.so");
    const auto check = [&](std::string name, bool passed) {
        report.checks.push_back({std::move(name), passed, {}});
    };
    const auto managed = [&](std::string_view name, std::string_view signature,
                             std::initializer_list<Value> args = {}) {
        return runtime.invoke_static("Lcom/aether/hello/ManagedCases;", name, signature,
                                     {args.begin(), args.size()});
    };
    const auto native = [&](std::string_view name, std::string_view signature,
                            std::initializer_list<Value> args = {}) {
        return runtime.invoke_static("Lcom/aether/hello/RuntimeFixture;", name, signature,
                                     {args.begin(), args.size()});
    };
    report.arithmetic =
        static_cast<std::uint32_t>(managed("arithmetic", "(II)I", {Value::word(123), Value::word(31)}).bits);
    std::uint32_t expected = 17;
    for (std::uint32_t i = 0; i < 31; ++i)
        expected += 123 ^ i;
    check("actual-dex-loop-and-static-initializer", report.arithmetic == expected);
    check("actual-dex-array-loop", managed("arrays", "(I)I", {Value::word(34)}) == Value::word(42));
    check("actual-dex-instance-field-and-virtual-call",
          managed("objects", "(I)I", {Value::word(38)}) == Value::word(42));
    check("actual-dex-utf16-string", managed("strings", "()I") == Value::word(942));
    check("actual-dex-catch-region", managed("bounds", "()I") == Value::word(91));
    report.round_trip =
        static_cast<std::uint32_t>(native("roundTrip", "(II)I", {Value::word(20), Value::word(22)}).bits);
    check("dex-jni-a64-jni-dex-nested-a64", report.round_trip == 85);
    check("jni-onload-and-registered-native",
          bridge.metrics().on_load_calls == 1 && bridge.metrics().native_calls == 2);
    report.reference_flags = static_cast<std::uint32_t>(native("referenceChecks", "()I").bits);
    check("jni-local-global-utf16-mutf8-array-and-signature", report.reference_flags == 255);
    check("jni-local-return-cleanup", bridge.metrics().local_references == 0 &&
                                          bridge.metrics().global_references == 0 &&
                                          bridge.metrics().string_buffers == 0);
    report.wide_result = native("primitiveLong", "(J)J", {Value::wide(0xfedcba9876543210ull)}).bits;
    check("jni-long-registers", report.wide_result == (0xfedcba9876543210ull ^ 0x9123456789abcdefull));
    report.floating = std::bit_cast<double>(
        native("primitiveDouble", "(D)D", {Value::wide(std::bit_cast<std::uint64_t>(-7.5))}).bits);
    check("jni-double-vector-registers", report.floating == -9.0);
    report.caught = static_cast<std::uint32_t>(native("catchNative", "()I").bits);
    check("jni-throw-caught-in-dex", report.caught == static_cast<std::uint32_t>(-99));
    bool propagated = false;
    try {
        (void)native("callbackThrows", "(I)I", {Value::word(0)});
    } catch (const JavaException &e) {
        propagated = runtime.object_type(e.object) == "Ljava/lang/ArithmeticException;";
    }
    check("dex-throw-through-jni-and-a64", propagated);
    for (std::uint32_t mode = 0; mode < 8; ++mode) {
        bool rejected = false;
        try {
            (void)native("invalidReference", "(I)I", {Value::word(mode)});
        } catch (const DexError &e) {
            rejected = e.code == "AETHER_JNI_NATIVE_EXECUTION" && bridge.metrics().local_references == 0;
        }
        check("jni-reject-invalid-operation-" + std::to_string(mode), rejected);
    }
    bool signature = false;
    try {
        (void)runtime.lookup("Lcom/aether/hello/RuntimeFixture;", "add", "(J)I", true);
    } catch (const DexError &e) {
        signature = e.code == "AETHER_DEX_METHOD_NOT_FOUND";
    }
    check("wrong-managed-signature-diagnostic", signature);
    check("native-fault-unwinds-and-allows-next-call",
          native("roundTrip", "(II)I", {Value::word(1), Value::word(2)}) == Value::word(7));
    check("jit-confirmed-with-suspended-nested-calls", bridge.cpu_metrics().compiled_blocks > 0 &&
                                                           bridge.cpu_metrics().emitted_bytes > 0 &&
                                                           bridge.cpu_metrics().maximum_call_depth == 2);
    bridge.shutdown();
    runtime.collect();
    check("jni-shutdown-releases-all-roots-and-buffers",
          runtime.metrics().pinned_references == 0 && bridge.metrics().string_buffers == 0);
    report.managed = runtime.metrics();
    report.jni = bridge.metrics();
    report.cpu = bridge.cpu_metrics();
    return report;
}
bool ManagedSelftestReport::passed() const {
    return !checks.empty() &&
           std::all_of(checks.begin(), checks.end(), [](const auto &check) { return check.passed; });
}
std::string ManagedSelftestReport::json() const {
    std::ostringstream out;
    out << "{\"schemaVersion\":1,\"passed\":" << (passed() ? "true" : "false")
        << ",\"mode\":\"self-authored-fixtures-only\",\"androidOsStarted\":false,\"managedEngine\":\"aether-"
           "dex-interpreter\","
        << "\"apkSha256\":" << json_quote(apk_sha256) << ",\"dexSha256\":" << json_quote(dex_sha256)
        << ",\"nativeSha256\":" << json_quote(native_sha256) << ",\"arithmetic\":" << arithmetic
        << ",\"roundTrip\":" << round_trip << ",\"referenceFlags\":" << reference_flags
        << ",\"longResult\":" << wide_result << ",\"doubleResult\":" << floating << ",\"caught\":" << caught
        << ",\"managed\":{\"instructions\":" << managed.instructions << ",\"calls\":" << managed.managed_calls
        << ",\"nativeCalls\":" << managed.native_calls << ",\"allocations\":" << managed.allocations
        << ",\"collections\":" << managed.collections << ",\"reclaimed\":" << managed.reclaimed
        << ",\"liveObjects\":" << managed.live_objects
        << ",\"pinnedReferences\":" << managed.pinned_references
        << ",\"maximumFrames\":" << managed.maximum_frames << "},\"jni\":{\"calls\":" << jni.calls
        << ",\"onLoadCalls\":" << jni.on_load_calls << ",\"managedCallbacks\":" << jni.managed_callbacks
        << ",\"automaticLocalDeletions\":" << jni.automatic_local_deletions
        << ",\"rejectedCalls\":" << jni.rejected_calls << ",\"localReferences\":" << jni.local_references
        << ",\"globalReferences\":" << jni.global_references << ",\"stringBuffers\":" << jni.string_buffers
        << "},\"cpu\":{\"compiledBlocks\":" << cpu.compiled_blocks
        << ",\"emittedBytes\":" << cpu.emitted_bytes << ",\"nestedCalls\":" << cpu.nested_calls
        << ",\"maximumCallDepth\":" << cpu.maximum_call_depth << ",\"rxFailures\":" << cpu.rx_failures
        << ",\"interpreterFallbacks\":" << cpu.interpreter_fallbacks << "},\"checks\":[";
    bool first = true;
    for (const auto &check : checks) {
        if (!first)
            out << ',';
        first = false;
        out << "{\"name\":" << json_quote(check.name) << ",\"passed\":" << (check.passed ? "true" : "false")
            << '}';
    }
    out << "]}";
    return out.str();
}
std::string ManagedSelftestReport::text(bool verbose) const {
    std::ostringstream out;
    out << "DEX/JNI self-test: " << (passed() ? "PASS" : "FAIL") << " (" << checks.size() << " checks)\n"
        << "Actual first-party APK classes.dex -> JNI -> translated ARM64 -> DEX -> nested ARM64\n"
        << "Round trip: " << round_trip << "; managed instructions: " << managed.instructions
        << "; JIT blocks: " << cpu.compiled_blocks << "; maximum native depth: " << cpu.maximum_call_depth
        << '\n'
        << "No Android OS; arbitrary APK execution remains disabled.\n";
    if (verbose || !passed())
        for (const auto &check : checks)
            out << (check.passed ? "  PASS " : "  FAIL ") << check.name << '\n';
    return out.str();
}
} // namespace aether::dex
