#include "aether/graphics/selftest.hpp"
#include "aether/common/text.hpp"
#include "fixture_runtime.hpp"
#include <algorithm>
#include <sstream>

namespace aether::graphics {
namespace {
[[noreturn]] void fail(const std::string &message) {
    throw a64::GuestError("AETHER_GRAPHICS_SELFTEST", message);
}
} // namespace
SelftestReport execute_graphics_fixture(std::vector<std::uint8_t> bytes, std::uint64_t app_id,
                                        host::TimeService &time, GraphicsChannel &channel,
                                        std::vector<std::uint8_t> &capture) {
    SelftestReport report;
    detail::FixtureRuntime fixture(std::move(bytes), app_id, time, channel);
    report.fixture_sha256 = fixture.hash();
    report.relocations = fixture.relocations();
    auto &memory = fixture.memory;
    constexpr auto output = detail::FixtureRuntime::output;
    const auto check = [&](std::string name, bool passed) {
        report.checks.push_back({std::move(name), passed, {}});
    };
    const auto call = [&](std::string_view name, std::initializer_list<std::uint64_t> arguments) {
        fixture.call(name, arguments);
    };
    call("aether_gles_open", {128, 96});
    check("translated-egl-setup-and-shaders", fixture.graphics.metrics().shader_compiles == 3 &&
                                                  fixture.graphics.metrics().contexts == 1 &&
                                                  fixture.graphics.metrics().surfaces == 1);
    capture.clear();
    const auto draw = [&](bool green, std::size_t size) {
        std::vector<std::uint8_t> guard(65536, 0xa5);
        if (!memory.write(output, guard))
            fail("Cannot initialize pixel canaries");
        call("aether_gles_draw", {output + 16, green ? 1ULL : 0ULL});
        if (!memory.read(output, guard))
            fail("Cannot read pixel results");
        check(
            green ? (size == 128 * 96 * 4 ? "green-readback-canaries" : "resized-readback-canaries")
                  : "red-readback-canaries",
            std::all_of(guard.begin(), guard.begin() + 16, [](auto byte) { return byte == 0xa5; }) &&
                std::all_of(guard.begin() + 16 + size, guard.end(), [](auto byte) { return byte == 0xa5; }));
        capture.insert(capture.end(), guard.begin() + 16, guard.begin() + 16 + size);
    };
    draw(false, 128 * 96 * 4);
    draw(true, 128 * 96 * 4);
    call("aether_gles_resize", {80, 60});
    check("translated-pbuffer-resize",
          fixture.graphics.metrics().contexts == 1 && fixture.graphics.metrics().surfaces == 1);
    draw(true, 80 * 60 * 4);
    report.host = fixture.graphics.host_info();
    check("hardware-d3d11-device", report.host.hardware && !report.host.adapter.empty() &&
                                       report.host.renderer.find("Direct3D11") != std::string::npos);
    call("aether_gles_close", {});
    check("guest-explicit-cleanup",
          fixture.graphics.metrics().contexts == 0 && fixture.graphics.metrics().surfaces == 0 &&
              fixture.graphics.metrics().shaders == 0 && fixture.graphics.metrics().programs == 0 &&
              fixture.graphics.metrics().buffers == 0 && fixture.graphics.metrics().buffer_bytes == 0);
    fixture.finalize();
    const auto mapped = memory.mapped_bytes();
    fixture.graphics.shutdown();
    report.graphics = fixture.graphics.metrics();
    report.cpu = fixture.cpu_metrics();
    check("bridge-resource-release",
          report.graphics.cleanup_failures == 0 && memory.mapped_bytes() < mapped &&
              !memory.accessible(GuestGraphicsServices::trampoline_base, 4, a64::Permission::execute));
    check("actual-arm64-jit-draw-calls",
          report.cpu.compiled_blocks > 20 && report.cpu.emitted_bytes > 1000 &&
              report.cpu.interpreter_fallbacks == 0 && report.cpu.rx_failures == 0 &&
              report.graphics.draws == 3 && report.graphics.readbacks == 3 && report.graphics.rejected == 0 &&
              report.graphics.readback_bytes == capture.size());
    check("guest-pages-never-host-executable", memory.host_pages_are_non_executable());
    return report;
}
bool SelftestReport::passed() const {
    return !checks.empty() &&
           std::all_of(checks.begin(), checks.end(), [](const auto &value) { return value.passed; });
}
std::string SelftestReport::json() const {
    std::ostringstream out;
    out << "{\"schemaVersion\":1,\"command\":" << json_quote(command)
        << ",\"passed\":" << (passed() ? "true" : "false")
        << ",\"mode\":\"self-authored-fixtures-only\",\"androidOsStarted\":false,\"guestCallsExecuted\":true,"
           "\"backend\":\"ANGLE-D3D11\",\"fixtureSha256\":"
        << json_quote(fixture_sha256) << ",\"capturePath\":" << json_quote(capture_path)
        << ",\"relocations\":" << relocations << ",\"registryEntries\":" << api_registry().size()
        << ",\"host\":{\"hardware\":" << (host.hardware ? "true" : "false")
        << ",\"adapter\":" << json_quote(host.adapter) << ",\"renderer\":" << json_quote(host.renderer)
        << ",\"vendor\":" << json_quote(host.vendor) << ",\"version\":" << json_quote(host.version)
        << ",\"vendorId\":" << host.vendor_id << ",\"deviceId\":" << host.device_id
        << ",\"featureLevel\":" << host.feature_level << "},\"graphics\":{\"calls\":" << graphics.calls
        << ",\"eglCalls\":" << graphics.egl_calls << ",\"glCalls\":" << graphics.gl_calls
        << ",\"rejected\":" << graphics.rejected << ",\"apiErrors\":" << graphics.api_errors
        << ",\"shaderCompiles\":" << graphics.shader_compiles << ",\"draws\":" << graphics.draws
        << ",\"readbacks\":" << graphics.readbacks << ",\"readbackBytes\":" << graphics.readback_bytes
        << ",\"swaps\":" << graphics.swaps << ",\"windowSwaps\":" << graphics.window_swaps
        << ",\"windowBindings\":" << graphics.window_bindings
        << ",\"windowSurfaces\":" << graphics.window_surfaces << ",\"contexts\":" << graphics.contexts
        << ",\"surfaces\":" << graphics.surfaces << ",\"shaders\":" << graphics.shaders
        << ",\"programs\":" << graphics.programs << ",\"buffers\":" << graphics.buffers
        << ",\"bufferBytes\":" << graphics.buffer_bytes
        << ",\"cleanupFailures\":" << graphics.cleanup_failures
        << "},\"cpu\":{\"compiledBlocks\":" << cpu.compiled_blocks
        << ",\"emittedBytes\":" << cpu.emitted_bytes << ",\"hostCalls\":" << cpu.host_calls
        << ",\"guestTicks\":" << cpu.guest_ticks << ",\"rxFailures\":" << cpu.rx_failures
        << ",\"interpreterFallbacks\":" << cpu.interpreter_fallbacks << "},\"checks\":[";
    for (std::size_t n = 0; n < checks.size(); ++n) {
        if (n)
            out << ',';
        out << "{\"name\":" << json_quote(checks[n].name)
            << ",\"passed\":" << (checks[n].passed ? "true" : "false") << '}';
    }
    out << "],\"isolation\":" << (isolation_json.empty() ? "null" : isolation_json) << '}';
    return out.str();
}
std::string SelftestReport::text(bool verbose) const {
    std::ostringstream out;
    out << "ARM64 EGL/GLES self-test: " << (passed() ? "PASS" : "FAIL") << " (" << checks.size()
        << " checks)\n"
        << "ANGLE D3D11 hardware: " << host.adapter << '\n'
        << graphics.calls << " translated graphics calls; " << cpu.compiled_blocks
        << " compiled ARM64 blocks; " << graphics.draws << " draws\n";
    if (verbose || !passed())
        for (const auto &value : checks)
            out << (value.passed ? "  PASS " : "  FAIL ") << value.name << '\n';
    return out.str();
}
} // namespace aether::graphics
