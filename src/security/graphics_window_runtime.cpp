#include "../graphics/fixture_runtime.hpp"
#include "aether/apk/inspect.hpp"
#include "aether/security/graphics_channel.hpp"
#include "aether/security/graphics_window_protocol.hpp"
#include <algorithm>

namespace aether::security {
namespace {
void require(bool value, const char *message) {
    if (!value)
        throw ProtocolError(std::string("AETHER_GRAPHICS_WINDOW_RUNTIME: ") + message);
}
class Runtime {
    graphics::detail::FixtureRuntime fixture;
    GraphicsWindowState state;
    bool opened = false;
    void observe() {
        for (unsigned i = 0; i < state.guest.size(); ++i)
            state.guest[i] = fixture.value("aether_gles_state", {i});
    }
    void snapshot() {
        state.graphics.metrics = fixture.graphics.metrics();
        state.graphics.host = fixture.graphics.host_info();
        state.cpu = fixture.cpu_metrics();
        state.non_executable = fixture.memory.host_pages_are_non_executable();
    }

  public:
    Runtime(BrokerClient &client, BrokerGraphicsChannel &channel, std::uint64_t app_id)
        : fixture(client.read_package(), app_id, client, channel) {
        state.fixture_hash = fixture.hash();
        state.relocations = fixture.relocations();
        observe();
        snapshot();
    }
    const GraphicsWindowState &initial() const { return state; }
    const GraphicsWindowState &execute(const GraphicsWindowCommand &command) {
        require(!state.closed, "Closed fixture");
        state.capture_bytes = 0;
        state.capture_hash.clear();
        state.canaries = false;
        const auto &a = command.arguments;
        const auto kind = command.kind;
        require(opened || kind == GraphicsWindowKind::open || kind == GraphicsWindowKind::read ||
                    kind == GraphicsWindowKind::close,
                "Graphics window is not open");
        if (kind == GraphicsWindowKind::open) {
            require(!opened, "Duplicate graphics window open");
            fixture.call("aether_gles_open_window", {a[0], a[1], a[2]});
            opened = true;
        } else if (kind == GraphicsWindowKind::draw) {
            if (a[0])
                fixture.call("aether_gles_window_resize");
            observe();
            const auto size = state.guest[9] * state.guest[10] * 4;
            std::vector<std::uint8_t> guard;
            constexpr auto output = graphics::detail::FixtureRuntime::output;
            if (a[1]) {
                require(size && size <= graphics::detail::FixtureRuntime::output_size - 32,
                        "Capture exceeds the fixture output buffer");
                guard.assign(graphics::detail::FixtureRuntime::output_size, 0xa5);
                require(fixture.memory.write(output, guard), "Cannot initialize capture canaries");
            }
            fixture.call("aether_gles_window_draw", {a[1] ? output + 16 : 0});
            if (a[1]) {
                require(fixture.memory.read(output, guard), "Cannot read captured guest pixels");
                state.canaries =
                    std::all_of(guard.begin(), guard.begin() + 16, [](auto n) { return n == 0xa5; }) &&
                    std::all_of(guard.begin() + 16 + static_cast<std::size_t>(size), guard.end(),
                                [](auto n) { return n == 0xa5; });
                state.capture_bytes = size;
                state.capture_hash =
                    apk::sha256(std::span(guard).subspan(16, static_cast<std::size_t>(size)));
            }
        } else if (kind == GraphicsWindowKind::pointer)
            fixture.call("aether_gles_pointer", {a[0], a[1], a[2], a[3]});
        else if (kind == GraphicsWindowKind::key)
            fixture.call("aether_gles_key", {a[0], a[1], a[2]});
        else if (kind == GraphicsWindowKind::focus)
            fixture.call("aether_gles_focus", {a[0]});
        observe();
        if (kind == GraphicsWindowKind::close) {
            if (opened)
                fixture.call("aether_gles_close");
            fixture.finalize();
            fixture.graphics.shutdown();
            state.closed = true;
        }
        snapshot();
        return state;
    }
};
void send(HANDLE writer, const GraphicsWindowState &state, std::uint64_t sequence, std::uint64_t session) {
    auto bytes = state.encode();
    const auto size = static_cast<std::uint32_t>(bytes.size());
    write_pipe_frame(
        writer, {{Operation::graphics_window_state, sequence, session, size, Status::ok}, std::move(bytes)});
}
} // namespace
void run_graphics_window_worker(HANDLE reader, HANDLE writer, std::uint64_t session, std::uint64_t app_id,
                                bool recovery) {
    try {
        BrokerClient client(reader, writer, session, true);
        BrokerGraphicsChannel channel(client);
        Runtime runtime(client, channel, app_id);
        send(writer, runtime.initial(), 0, session);
        for (std::uint64_t sequence = 1; sequence != UINT64_MAX; ++sequence) {
            const auto request = read_pipe_frame(reader);
            require(request.header.operation == Operation::graphics_window_command &&
                        request.header.sequence == sequence && request.header.session == session &&
                        request.header.status == Status::ok,
                    "Invalid command identity");
            const auto command = GraphicsWindowCommand::decode(request.payload);
            if (recovery && command.kind == GraphicsWindowKind::read) {
                Sleep(1500); // Controlled fixture: no guest call or graphics mutation before refusal.
                write_pipe_frame(
                    writer, {{Operation::graphics_window_unavailable, sequence, session, 0, Status::ok}, {}});
                recovery = false;
                continue;
            }
            send(writer, runtime.execute(command), sequence, session);
            if (command.kind == GraphicsWindowKind::close)
                return;
        }
        require(false, "Command sequence exhausted");
    } catch (const a64::GuestError &e) {
        throw ProtocolError(e.code + ": " + e.what());
    }
}
} // namespace aether::security
