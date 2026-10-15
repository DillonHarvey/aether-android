#include "aether/security/graphics_window_protocol.hpp"
#include <algorithm>
#include <bit>

namespace aether::security {
namespace {
void require(bool value) {
    if (!value)
        throw ProtocolError("AETHER_GRAPHICS_WINDOW_WIRE: invalid bounded record");
}
bool digest(std::string_view value) {
    return value.size() == 64 && std::all_of(value.begin(), value.end(), [](char c) {
               return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
           });
}
void validate(const GraphicsWindowCommand &c) {
    const auto &a = c.arguments;
    unsigned used = 0;
    switch (c.kind) {
    case GraphicsWindowKind::read:
    case GraphicsWindowKind::close:
        break;
    case GraphicsWindowKind::open:
        used = 3;
        require(a[0] >= a64::GuestMemory::address_limit && a[1] && a[1] <= 1024 && a[2] && a[2] <= 1024);
        break;
    case GraphicsWindowKind::draw:
        used = 2;
        require(a[0] <= 1 && a[1] <= 1); // Resize first; optionally capture this draw.
        break;
    case GraphicsWindowKind::pointer:
        used = 4;
        require(a[0] <= 3 && (a[3] == 0x1002 || a[3] == 0x2002));
        for (unsigned i = 1; i <= 2; ++i)
            require(std::bit_cast<std::int64_t>(a[i]) >= -1048576 &&
                    std::bit_cast<std::int64_t>(a[i]) <= 1048576);
        break;
    case GraphicsWindowKind::key:
        used = 3;
        require(a[0] <= 1 && a[1] <= 1000 && a[2] <= 65535);
        break;
    case GraphicsWindowKind::focus:
        used = 1;
        require(a[0] <= 1);
        break;
    default:
        require(false);
    }
    for (unsigned i = used; i < a.size(); ++i)
        require(a[i] == 0);
}
void validate(const GraphicsWindowState &s) {
    const auto &g = s.graphics;
    require(g.value == 0 && g.fault == a64::Fault::none && !g.string_result && g.text.empty() &&
            g.error.empty() && g.outputs.empty() && digest(s.fixture_hash) && s.relocations <= 65536);
    for (auto value : s.guest)
        require(value <= UINT32_MAX);
    require(s.guest[0] <= 1 && s.guest[9] <= 1024 && s.guest[10] <= 1024 && s.guest[12] <= 1 &&
            s.guest[13] <= 1 && (s.guest[14] == 0 || s.guest[14] == 62 || s.guest[14] == 66));
    require(s.capture_bytes <= 65504);
    if (s.capture_bytes)
        require(!s.closed && digest(s.capture_hash) && s.guest[9] && s.guest[10] &&
                s.capture_bytes == s.guest[9] * s.guest[10] * 4);
    else
        require(s.capture_hash.empty() && !s.canaries);
    if (s.closed) {
        const auto &m = g.metrics;
        require(!m.contexts && !m.surfaces && !m.shaders && !m.programs && !m.buffers && !m.buffer_bytes &&
                !m.window_bindings && !m.window_surfaces && !m.cleanup_failures);
    }
}
} // namespace
std::vector<std::uint8_t> GraphicsWindowCommand::encode() const {
    validate(*this);
    std::vector<std::uint8_t> bytes;
    append_u64(bytes, 1);
    append_u64(bytes, static_cast<std::uint64_t>(kind));
    for (auto n : arguments)
        append_u64(bytes, n);
    return bytes;
}
GraphicsWindowCommand GraphicsWindowCommand::decode(std::span<const std::uint8_t> bytes) {
    require(bytes.size() == 48 && read_u64(bytes, 0) == 1);
    GraphicsWindowCommand command;
    const auto kind = read_u64(bytes, 8);
    require(kind <= static_cast<std::uint64_t>(GraphicsWindowKind::close));
    command.kind = static_cast<GraphicsWindowKind>(kind);
    for (std::size_t i = 0; i < command.arguments.size(); ++i)
        command.arguments[i] = read_u64(bytes, 16 + i * 8);
    validate(command);
    return command;
}
std::vector<std::uint8_t> GraphicsWindowState::encode() const {
    validate(*this);
    const auto snapshot = encode_graphics_reply(graphics);
    std::vector<std::uint8_t> bytes;
    append_u64(bytes, 1);
    append_u64(bytes, snapshot.size());
    bytes.insert(bytes.end(), snapshot.begin(), snapshot.end());
    append_text(bytes, fixture_hash);
    append_text(bytes, capture_hash);
    for (auto n :
         {relocations, capture_bytes, static_cast<std::uint64_t>(non_executable),
          static_cast<std::uint64_t>(closed), static_cast<std::uint64_t>(canaries), cpu.compiled_blocks,
          cpu.emitted_bytes, cpu.host_calls, cpu.guest_ticks, cpu.rx_failures, cpu.interpreter_fallbacks})
        append_u64(bytes, n);
    for (auto n : guest)
        append_u64(bytes, n);
    require(bytes.size() <= maximum_payload);
    return bytes;
}
GraphicsWindowState GraphicsWindowState::decode(std::span<const std::uint8_t> bytes) {
    require(bytes.size() <= maximum_payload && read_u64(bytes, 0) == 1);
    const auto length = read_u64(bytes, 8);
    require(length <= bytes.size() - 16);
    GraphicsWindowState state;
    state.graphics = decode_graphics_reply(bytes.subspan(16, static_cast<std::size_t>(length)));
    std::size_t offset = 16 + static_cast<std::size_t>(length);
    state.fixture_hash = read_text(bytes, offset, 64);
    state.capture_hash = read_text(bytes, offset, 64);
    const auto next = [&] {
        const auto n = read_u64(bytes, offset);
        offset += 8;
        return n;
    };
    state.relocations = next();
    state.capture_bytes = next();
    for (auto *flag : {&state.non_executable, &state.closed, &state.canaries}) {
        const auto n = next();
        require(n <= 1);
        *flag = n != 0;
    }
    for (auto *n : {&state.cpu.compiled_blocks, &state.cpu.emitted_bytes, &state.cpu.host_calls,
                    &state.cpu.guest_ticks, &state.cpu.rx_failures, &state.cpu.interpreter_fallbacks})
        *n = next();
    for (auto &n : state.guest)
        n = next();
    require(offset == bytes.size());
    validate(state);
    return state;
}
void validate_graphics_window_refusal(const Frame &f, std::uint64_t sequence, std::uint64_t session,
                                      bool reading, bool began) {
    require(reading && !began && sequence && f.header.operation == Operation::graphics_window_unavailable &&
            f.header.sequence == sequence && f.header.session == session && f.header.status == Status::ok &&
            !f.header.payload_size && f.payload.empty());
}
} // namespace aether::security
