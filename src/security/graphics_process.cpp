#include "aether/security/graphics_process.hpp"
#include "aether/security/graphics_channel.hpp"
#include <atomic>
#include <bcrypt.h>
#include <thread>

namespace aether::security {
namespace {
void require(bool value, const char *message) {
    if (!value)
        throw ProtocolError(std::string("AETHER_GRAPHICS_PROCESS: ") + message);
}
std::uint64_t identity() {
    std::uint64_t result = 0;
    require(BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&result), sizeof(result),
                            BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0 &&
                result,
            "Cannot create service session identity");
    return result;
}
} // namespace
struct GraphicsProcess::Impl {
    const std::thread::id owner = std::this_thread::get_id();
    const std::uint64_t session = identity();
    const std::uint64_t app_id;
    WorkerProcess worker;
    BrokerGraphicsChannel channel;
    graphics::GraphicsReply last;
    std::unique_ptr<host::GraphicsPresenter> presenter;
    host::PresentationMetrics presentation;
    std::atomic<bool> cancelled = false;
    std::uint64_t sequence = 0;
    bool broken = false, closed = false;
    Impl(const std::filesystem::path &path, std::uint64_t id)
        : app_id(id), worker({path, L"Aether.Development.GraphicsService." + std::to_wstring(app_id), true,
                              command_timeout_ms, true, WorkerRole::graphics}),
          channel([this](Operation op, std::vector<std::uint8_t> bytes) {
              return request(op, std::move(bytes));
          }) {
        require(app_id != 0, "Missing app identity");
        std::vector<std::uint8_t> boot;
        append_u64(boot, app_id);
        require(request(Operation::boot, std::move(boot)).payload.empty(), "Invalid startup reply");
        worker.end_exchange(); // The launcher supervises startup before any caller can block.
    }
    void check() const {
        require(owner == std::this_thread::get_id(), "Service channel belongs to another thread");
        require(!broken && !cancelled, "Service channel is permanently closed after failure or cancellation");
    }
    Frame request(Operation op, std::vector<std::uint8_t> bytes = {}) {
        check();
        require(sequence < 100000, "Service frame quota reached");
        Frame frame{{op, sequence++, session, static_cast<std::uint32_t>(bytes.size()), Status::ok},
                    std::move(bytes)};
        worker.send(frame);
        auto response = worker.receive();
        require(response.header.operation == op && response.header.sequence == frame.header.sequence &&
                    response.header.session == session && response.header.status == Status::ok,
                "Invalid service response identity or status");
        return response;
    }
    void fail(std::exception_ptr failure) {
        const bool first = !broken;
        broken = true;
        worker.request_stop();
        if (presenter)
            presentation = presenter->metrics();
        if (first) {
            last.fault = a64::Fault::windows_service;
            try {
                std::rethrow_exception(failure);
            } catch (const std::exception &error) {
                last.error = std::string_view(error.what()).substr(0, 512);
            } catch (...) {
                last.error = "AETHER_GRAPHICS_PROCESS: Unknown service failure";
            }
        }
    }
    void reclaim() {
        worker.request_stop();
        (void)worker.wait();
        const auto usage = worker.accounting();
        require(usage.active_processes == 0 && usage.active_process_ids.empty(),
                "Terminated graphics service remains live");
        auto &m = last.metrics;
        m.contexts = m.surfaces = m.shaders = m.programs = m.buffers = m.buffer_bytes = 0;
        m.window_bindings = m.window_surfaces = 0; // Windows reclaimed this process, not an EGL shutdown.
        last.value = 0;
        last.string_result = false;
        last.outputs.clear();
        last.text.clear();
        presenter.reset(); // The I/O owner releases all parent GPU resources before the HWND goes away.
        closed = true;
    }
};
GraphicsProcess::GraphicsProcess(const std::filesystem::path &path, std::uint64_t app_id)
    : impl_(std::make_unique<Impl>(path, app_id)) {}
GraphicsProcess::~GraphicsProcess() = default; // WorkerProcess kills/reaps even after a broken pipe.
graphics::GraphicsReply GraphicsProcess::exchange(const graphics::GraphicsCommand &command) {
    auto &p = *impl_;
    p.check();
    require(!p.closed, "Service is closed");
    // Validate before arming or sending anything; malformed commands never reach ANGLE.
    graphics::validate_command(command, p.last.pack_alignment);
    try {
        p.worker.begin_exchange();
        auto result = p.channel.exchange(command);
        if (result.fault == a64::Fault::windows_service) {
            p.last = result;
            throw ProtocolError("AETHER_GRAPHICS_PROCESS: " + result.error);
        }
        require(result.metrics.window_swaps >= p.last.metrics.window_swaps &&
                    result.metrics.window_swaps - p.last.metrics.window_swaps <= 1,
                "Invalid presented-frame sequence");
        const bool present = result.metrics.window_swaps != p.last.metrics.window_swaps;
        // Preserve the renderer's acknowledged work even when parent presentation fails.
        p.last = result;
        if (present) {
            require(p.presenter && command.operation == graphics::Operation::swap_buffers && result.value,
                    "Unbound or unsolicited rendered frame");
            p.presenter->present();
            p.presentation = p.presenter->metrics();
        }
        p.worker.end_exchange();
        return result;
    } catch (...) {
        p.fail(std::current_exception());
        throw;
    }
}
graphics::GraphicsReply GraphicsProcess::close() {
    auto &p = *impl_;
    require(p.owner == std::this_thread::get_id(), "Graphics close belongs to another thread");
    if (p.closed)
        return p.last;
    if (p.broken || p.cancelled) {
        p.reclaim();
        return p.last;
    }
    try {
        p.worker.begin_exchange();
        auto result = p.channel.close();
        require(p.request(Operation::finished).payload.empty(), "Invalid shutdown acknowledgement");
        require(p.worker.wait() == 0 && !p.worker.timed_out(), "Graphics service did not exit cleanly");
        const auto usage = p.worker.accounting();
        require(usage.active_processes == 0 && usage.active_process_ids.empty(),
                "Graphics service left a live process");
        p.last = result;
        p.presenter.reset();
        p.closed = true;
        return result;
    } catch (...) {
        p.fail(std::current_exception());
        p.reclaim();
        ++p.last.metrics.cleanup_failures;
        return p.last; // Keep the failure and the actual post-reap resource counts together.
    }
}
std::uint32_t GraphicsProcess::process_id() const noexcept { return impl_->worker.process_id(); }
WorkerAccounting GraphicsProcess::accounting() const { return impl_->worker.accounting(); }
WorkerImageAccess GraphicsProcess::image_access() const noexcept { return impl_->worker.image_access(); }
bool GraphicsProcess::timed_out() const noexcept { return impl_->worker.timed_out(); }
void GraphicsProcess::request_stop() noexcept {
    impl_->cancelled = true;
    impl_->worker.request_stop();
}
void GraphicsProcess::bind_window(const host::SurfaceSnapshot &surface, std::uint64_t token, bool capture) {
    auto &p = *impl_;
    p.check();
    require(!p.closed, "Cannot bind a closed service");
    try {
        if (!p.presenter)
            p.presenter = std::make_unique<host::GraphicsPresenter>(surface, token, capture);
        else {
            require(p.presenter->grant().token == token, "Cannot replace a window identity");
            if (!p.presenter->resize(surface))
                return;
        }
        auto grant = p.presenter->grant();
        p.worker.begin_exchange();
        grant.handle = p.worker.duplicate_graphics_handle(reinterpret_cast<HANDLE>(grant.handle));
        std::vector<std::uint8_t> bytes;
        for (const std::uint64_t value :
             {std::uint64_t{1}, p.app_id, grant.token, grant.generation, grant.handle,
              std::uint64_t{grant.width}, std::uint64_t{grant.height}, std::uint64_t{grant.luid_low},
              std::uint64_t{grant.luid_high}})
            append_u64(bytes, value);
        auto reply =
            decode_graphics_reply(p.request(Operation::graphics_bind_surface, std::move(bytes)).payload);
        const auto &before = p.last.metrics;
        const auto &after = reply.metrics;
        require(!reply.value && !reply.string_result && reply.outputs.empty() && reply.text.empty() &&
                    after.calls == before.calls && after.egl_calls == before.egl_calls &&
                    after.gl_calls == before.gl_calls && after.shader_compiles == before.shader_compiles &&
                    after.draws == before.draws && after.readbacks == before.readbacks &&
                    after.readback_bytes == before.readback_bytes && after.swaps == before.swaps &&
                    after.window_swaps == before.window_swaps,
                "Invalid shared-window acknowledgement");
        if (reply.fault == a64::Fault::windows_service) {
            require(!reply.error.empty() && after.rejected == before.rejected + 1 && !after.contexts &&
                        !after.surfaces && !after.shaders && !after.programs && !after.buffers &&
                        !after.buffer_bytes && !after.window_bindings && !after.window_surfaces,
                    "Invalid failed shared-window acknowledgement");
            p.last = reply;
            throw ProtocolError("AETHER_GRAPHICS_PROCESS: " + reply.error);
        }
        require(reply.fault == a64::Fault::none && reply.error.empty() && after.window_bindings == 1 &&
                    after.rejected == before.rejected && after.contexts == before.contexts &&
                    after.surfaces == before.surfaces && after.window_surfaces == before.window_surfaces &&
                    after.shaders == before.shaders && after.programs == before.programs &&
                    after.buffers == before.buffers && after.buffer_bytes == before.buffer_bytes &&
                    after.cleanup_failures == before.cleanup_failures,
                "Invalid shared-window acknowledgement");
        p.worker.end_exchange();
        p.last = std::move(reply);
        p.presentation = p.presenter->metrics();
    } catch (...) {
        // Any unsent/partially accepted duplicate dies with its process; never replay the grant.
        p.fail(std::current_exception());
        throw;
    }
}
host::PresentationMetrics GraphicsProcess::presentation_metrics() const noexcept {
    return impl_->presentation;
}
const std::vector<std::uint8_t> &GraphicsProcess::presentation_pixels() const noexcept {
    static const std::vector<std::uint8_t> empty;
    return impl_->presenter ? impl_->presenter->pixels() : empty;
}
} // namespace aether::security
