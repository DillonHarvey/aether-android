#include "aether/apk/inspect.hpp"
#include "aether/security/graphics_session.hpp"
namespace aether::security {
namespace {
constexpr std::array<std::string_view, 10> names{
    "translated-egl-setup-and-shaders", "red-readback-canaries",     "green-readback-canaries",
    "translated-pbuffer-resize",        "resized-readback-canaries", "hardware-d3d11-device",
    "guest-explicit-cleanup",           "bridge-resource-release",   "actual-arm64-jit-draw-calls",
    "guest-pages-never-host-executable"};
void require(bool value) {
    if (!value)
        throw ProtocolError("AETHER_GRAPHICS_RESULT: invalid fixture report");
}
} // namespace
std::vector<std::uint8_t> encode_graphics_result(const graphics::SelftestReport &r) {
    require(r.checks.size() == names.size() && r.fixture_sha256.size() == 64 &&
            r.capture_sha256.size() == 64);
    graphics::GraphicsReply snapshot;
    snapshot.metrics = r.graphics;
    snapshot.host = r.host;
    const auto data = encode_graphics_reply(snapshot);
    std::vector<std::uint8_t> bytes;
    append_u64(bytes, data.size());
    bytes.insert(bytes.end(), data.begin(), data.end());
    append_text(bytes, r.fixture_sha256);
    append_text(bytes, r.capture_sha256);
    for (auto n : {static_cast<std::uint64_t>(r.relocations), r.cpu.compiled_blocks, r.cpu.emitted_bytes,
                   r.cpu.host_calls, r.cpu.guest_ticks, r.cpu.rx_failures, r.cpu.interpreter_fallbacks})
        append_u64(bytes, n);
    std::uint64_t mask = 0;
    for (std::size_t i = 0; i < names.size(); ++i) {
        require(r.checks[i].name == names[i]);
        if (r.checks[i].passed)
            mask |= 1ULL << i;
    }
    append_u64(bytes, mask);
    return bytes;
}
graphics::SelftestReport decode_graphics_result(std::span<const std::uint8_t> bytes) {
    const auto size = read_u64(bytes, 0);
    require(bytes.size() <= maximum_payload && size <= bytes.size() - 8);
    const auto snapshot = decode_graphics_reply(bytes.subspan(8, static_cast<std::size_t>(size)));
    require(snapshot.value == 0 && snapshot.fault == a64::Fault::none && !snapshot.string_result &&
            snapshot.outputs.empty() && snapshot.text.empty() && snapshot.error.empty());
    graphics::SelftestReport r;
    r.graphics = snapshot.metrics;
    r.host = snapshot.host;
    std::size_t offset = 8 + static_cast<std::size_t>(size);
    r.fixture_sha256 = read_text(bytes, offset, 64);
    r.capture_sha256 = read_text(bytes, offset, 64);
    const auto next = [&] {
        const auto n = read_u64(bytes, offset);
        offset += 8;
        return n;
    };
    r.relocations = static_cast<std::size_t>(next());
    r.cpu.compiled_blocks = next();
    r.cpu.emitted_bytes = next();
    r.cpu.host_calls = next();
    r.cpu.guest_ticks = next();
    r.cpu.rx_failures = next();
    r.cpu.interpreter_fallbacks = next();
    const auto mask = next();
    require(offset == bytes.size() && mask < (1ULL << names.size()) && r.fixture_sha256.size() == 64 &&
            r.capture_sha256.size() == 64);
    for (std::size_t i = 0; i < names.size(); ++i)
        r.checks.push_back({std::string(names[i]), (mask & (1ULL << i)) != 0, {}});
    return r;
}
void run_graphics_worker(HANDLE reader, HANDLE writer, std::uint64_t session, std::uint64_t app_id) {
    BrokerClient client(reader, writer, session);
    BrokerGraphicsChannel channel(client);
    auto bytes = client.read_package();
    std::vector<std::uint8_t> capture, result;
    try {
        auto report = graphics::execute_graphics_fixture(std::move(bytes), app_id, client, channel, capture);
        report.capture_sha256 = apk::sha256(capture);
        result = encode_graphics_result(report);
    } catch (const a64::GuestError &e) {
        throw ProtocolError(e.code + ": " + e.what());
    }
    const auto size = static_cast<std::uint32_t>(result.size());
    write_pipe_frame(writer, {{Operation::finished, client.next_sequence(), session, size, Status::ok},
                              std::move(result)});
}
} // namespace aether::security
