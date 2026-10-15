#include "aether/security/graphics_window_session.hpp"
#include "aether/apk/inspect.hpp"
#include "aether/common/text.hpp"
#include "aether/graphics/fixture_hash.hpp"
#include "aether/host/windows/unique_handle.hpp"
#include "aether/security/broker.hpp"
#include "aether/security/graphics_channel.hpp"
#include "aether/security/graphics_process.hpp"
#include <algorithm>
#include <atomic>
#include <bcrypt.h>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <sstream>
#include <thread>

namespace aether::security {
namespace {
void require(bool value, const char *message) {
    if (!value)
        throw ProtocolError(std::string("AETHER_GRAPHICS_WINDOW_HOST: ") + message);
}
std::filesystem::path directory() {
    std::array<wchar_t, 32768> path{};
    const auto n = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    require(n && n < path.size(), "Cannot locate the graphics worker");
    return std::filesystem::path(std::wstring(path.data(), n)).parent_path();
}
std::atomic<std::uint64_t> next_window{1};
struct Request {
    std::uint64_t ticket;
    GraphicsWindowCommand command;
    host::SurfaceSnapshot surface;
};
struct Cache {
    graphics::Metrics graphics;
    graphics::HostInfo host;
    std::shared_ptr<const std::vector<std::uint8_t>> pixels =
        std::make_shared<const std::vector<std::uint8_t>>();
    std::vector<AuditEntry> audit;
    std::string durable_audit = "{}";
    std::uint64_t broker_requests = 0, retained_bytes = 0, verified_captures = 0;
    host::PresentationMetrics presentation;
    WorkerAccounting graphics_usage;
    std::uint32_t graphics_pid = 0;
    bool graphics_exited = false;
};
} // namespace
struct GraphicsWindowSession::Impl {
    const std::thread::id owner = std::this_thread::get_id();
    host::UniqueHandle event{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    std::uint64_t session = 0;
    std::shared_ptr<AuditTrail> journal;
    std::vector<std::uint8_t> fixture_bytes;
    std::unique_ptr<Broker> broker;
    GraphicsBroker *provider = nullptr;
    mutable std::mutex mutex;
    std::condition_variable wake;
    std::deque<Request> requests;
    std::vector<GraphicsWindowCompletion> completions;
    Cache latest, published;
    host::UniqueHandle io_finished{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    std::unique_ptr<host::HostSurface> surface; // UI-owned until the I/O owner has exited.
    std::uint64_t window_token = 0;
    GraphicsProcess *graphics = nullptr; // Only request_stop crosses to this I/O-owned object.
    std::uint64_t verified_captures = 0;
    std::shared_ptr<const GraphicsWindowState> visible;
    std::exception_ptr failure;
    WorkerProcess *active = nullptr; // Only request_stop crosses to this I/O-owned object.
    GraphicsWindowDispatchMetrics metrics;
    std::uint64_t next = 1, outstanding = 0, read_ticket = 0;
    std::size_t validated_pixels = 0;
    std::uint32_t pid = 0;
    bool stopping = false, closing = false, worker_exited = false, read_failed = false;
    HWND notification = nullptr;
    UINT message = 0;
    bool posted = false;
    std::jthread io;
    explicit Impl(const std::filesystem::path &path, bool probe) {
        require(event && io_finished, "Cannot create graphics completion events");
        metrics.window_thread = GetCurrentThreadId();
        apk::InspectLimits limits;
        limits.archive_bytes = 1024 * 1024;
        auto bytes = apk::read_package(path, limits);
        if (apk::sha256(bytes) != graphics::fixture::sha256)
            throw a64::GuestError(
                "AETHER_GRAPHICS_FIXTURE_NOT_TRUSTED",
                "Only the exact built-in first-party GLES ELF fixture may execute before Phase 7");
        require(BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&session), sizeof(session),
                                BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0 &&
                    session,
                "Cannot create graphics window session identity");
        (void)probe;
        fixture_bytes = std::move(bytes);
        journal = make_file_audit(directory() / "audit-data");
    }
    void check_owner() const { require(std::this_thread::get_id() == owner, "Wrong window owner thread"); }
    void notify() {
        require(SetEvent(event.get()) != FALSE, "Cannot signal graphics completion");
        if (notification && !posted) {
            require(PostMessageW(notification, message, 0, 0) != FALSE, "Cannot notify graphics window");
            posted = true;
        }
    }
    void abort() noexcept {
        std::lock_guard lock(mutex);
        stopping = true;
        requests.clear();
        if (active)
            active->request_stop();
        if (graphics)
            graphics->request_stop();
        wake.notify_all();
    }
    void join() {
        if (!io.joinable())
            return;
        const HANDLE done = io_finished.get();
        while (WaitForSingleObject(done, 0) == WAIT_TIMEOUT) {
            // DXGI can send synchronous window messages. Dispatch only sent messages;
            // do not run queued app input or recursively process a posted close while joining.
            const auto result = MsgWaitForMultipleObjects(1, &done, FALSE, 1000, QS_SENDMESSAGE);
            require(result != WAIT_FAILED, "Cannot join the graphics I/O owner");
            MSG sent{};
            PeekMessageW(&sent, nullptr, WM_NULL, WM_NULL, PM_NOREMOVE);
        }
        io.join();
        std::lock_guard lock(mutex);
        published = latest;
    }
    ~Impl() {
        abort();
        join();
    }
    Cache make_cache() {
        if (!provider || !broker) {
            std::lock_guard lock(mutex);
            return latest;
        }
        Cache state_cache;
        state_cache.graphics = provider->metrics();
        state_cache.host = provider->host_info();
        const auto &pixels = provider->fixture_pixels();
        {
            std::lock_guard lock(mutex);
            state_cache.pixels = latest.pixels;
        }
        if (state_cache.pixels->size() != pixels.size())
            state_cache.pixels = std::make_shared<const std::vector<std::uint8_t>>(pixels);
        state_cache.audit = broker->audit();
        state_cache.durable_audit = journal->json();
        state_cache.broker_requests = broker->total_requests();
        state_cache.retained_bytes = provider->retained_transfer_bytes();
        state_cache.verified_captures = verified_captures;
        state_cache.presentation = graphics->presentation_metrics();
        state_cache.graphics_pid = graphics->process_id();
        state_cache.graphics_usage = graphics->accounting();
        state_cache.graphics_exited = state_cache.graphics_usage.active_processes == 0;
        return state_cache;
    }
    std::shared_ptr<const GraphicsWindowState> receive(WorkerProcess &worker, std::uint64_t sequence,
                                                       const GraphicsWindowCommand *command) {
        bool began = false;
        for (;;) {
            auto frame = worker.receive();
            if (frame.header.operation == Operation::graphics_window_unavailable) {
                validate_graphics_window_refusal(frame, sequence, session,
                                                 command && command->kind == GraphicsWindowKind::read, began);
                return {};
            }
            if (frame.header.operation == Operation::finished) {
                require(frame.header.session == session && frame.header.sequence == 0 &&
                            frame.header.status == Status::invalid && frame.payload.size() <= 512,
                        "Invalid failed-worker completion");
                throw ProtocolError("AETHER_GRAPHICS_WINDOW_WORKER: " +
                                    std::string(frame.payload.begin(), frame.payload.end()));
            }
            if (frame.header.operation == Operation::graphics_window_state) {
                require(frame.header.sequence == sequence && frame.header.session == session &&
                            frame.header.status == Status::ok,
                        "Invalid graphics window state identity");
                auto state =
                    std::make_shared<const GraphicsWindowState>(GraphicsWindowState::decode(frame.payload));
                const bool closing_command = command && command->kind == GraphicsWindowKind::close;
                const bool capture =
                    command && command->kind == GraphicsWindowKind::draw && command->arguments[1];
                require(state->closed == closing_command && (state->capture_bytes != 0) == capture,
                        "State does not match the outstanding command");
                validate(*state); // All provider calls, audit I/O and validation share the I/O owner.
                return state;
            }
            began = true;
            require(!worker.timed_out(), "Worker deadline expired before host dispatch");
            worker.send(broker->dispatch(frame)); // Durable intent before action; outcome before reply.
        }
    }
    void publish(GraphicsWindowCompletion completion) {
        auto state_cache = make_cache();
        std::lock_guard lock(mutex);
        latest = std::move(state_cache);
        if (completion.ticket) {
            ++metrics.completed;
            if (completion.unavailable) {
                ++metrics.read_failures;
                read_failed = true;
            } else if (completion.kind == GraphicsWindowKind::read && read_failed) {
                ++metrics.recovered_reads;
                read_failed = false;
            }
        }
        completions.push_back(std::move(completion));
        notify();
    }
    void run(bool probe) noexcept {
        std::unique_ptr<WorkerProcess> worker;
        std::exception_ptr caught;
        try {
            auto renderer = std::make_unique<GraphicsProcess>(directory() / "runtime" /
#ifdef AETHER_GRAPHICS_REBIND_TESTING
                                                                  "aether_graphics_context_worker.exe",
#else
                                                                  "aether_graphics_worker.exe",
#endif
                                                              83);
            auto *renderer_pointer = renderer.get();
            auto service = std::make_unique<GraphicsBroker>(std::move(renderer), probe);
            provider = service.get();
            broker = std::make_unique<Broker>(BrokerPolicy{83, session, true, 256, false, true, false, true},
                                              journal, nullptr, std::move(fixture_bytes), nullptr, false,
                                              std::move(service));
            {
                std::lock_guard lock(mutex);
                graphics = renderer_pointer;
                metrics.io_thread = GetCurrentThreadId();
                require(!stopping, "Graphics startup cancelled");
            }
            worker = std::make_unique<WorkerProcess>(
                WorkerOptions{directory() / "runtime" / "aether_worker.exe",
                              L"Aether.Development.GraphicsWindow.83", true, 15000, true});
            {
                std::lock_guard lock(mutex);
                active = worker.get();
                pid = worker->process_id();
                require(!stopping, "Guest startup cancelled");
            }
            journal->bind_worker(worker->process_id());
            Frame boot{{Operation::boot, 0, session, 40, Status::ok}, {}};
            for (auto n :
                 {std::uint64_t{probe ? 16u : 15u}, static_cast<std::uint64_t>(GetCurrentProcessId()),
                  std::uint64_t{83}, std::uint64_t{1}, std::uint64_t{0}})
                append_u64(boot.payload, n);
            worker->send(boot);
            const auto ack = worker->receive();
            require(ack.header.operation == Operation::boot && ack.header.sequence == 0 &&
                        ack.header.session == session && ack.header.status == Status::ok &&
                        ack.payload.empty(),
                    "Invalid graphics worker startup acknowledgement");
            auto state = receive(*worker, 0, nullptr);
            worker->end_exchange();
            publish({0, GraphicsWindowKind::read, false, state});
            for (;;) {
                Request request;
                {
                    std::unique_lock lock(mutex);
                    wake.wait(lock, [&] { return stopping || !requests.empty(); });
                    if (stopping)
                        break;
                    request = std::move(requests.front());
                    requests.pop_front();
                }
                worker->begin_exchange();
                broker->begin_turn();
                if (request.surface.window)
                    graphics->bind_window(request.surface, window_token, probe);
                auto bytes = request.command.encode();
                const auto size = static_cast<std::uint32_t>(bytes.size());
                worker->send({{Operation::graphics_window_command, request.ticket, session, size, Status::ok},
                              std::move(bytes)});
                auto update = receive(*worker, request.ticket, &request.command);
                const bool unavailable = !update;
                if (update)
                    state = std::move(update);
                if (request.command.kind == GraphicsWindowKind::close) {
                    require(worker->wait() == 0 && !worker->timed_out(), "Graphics guest failed on close");
                    journal->finish();
                    std::lock_guard lock(mutex);
                    worker_exited = true;
                } else
                    worker->end_exchange();
                publish({request.ticket, request.command.kind, unavailable, state});
                if (request.command.kind == GraphicsWindowKind::close)
                    break;
            }
        } catch (...) {
            caught = std::current_exception();
        }
        // Every GPU/context/provider destructor runs on its I/O owner, before the UI can release the HWND.
        try {
            if (broker)
                broker->revoke_graphics();
            journal->finish_aborted();
            auto state_cache = make_cache();
            std::lock_guard lock(mutex);
            latest = std::move(state_cache);
        } catch (...) {
            if (!caught)
                caught = std::current_exception();
        }
        {
            std::lock_guard lock(mutex);
            active = nullptr;
            graphics = nullptr;
        }
        broker.reset();
        provider = nullptr;
        try {
            if (worker) {
                worker->request_stop();
                (void)worker->wait();
                const auto usage = worker->accounting();
                require(usage.active_processes == 0 && usage.active_process_ids.empty(),
                        "Terminated graphics guest remains live");
                std::lock_guard lock(mutex);
                worker_exited = true;
            }
        } catch (...) {
            if (!caught)
                caught = std::current_exception();
        }
        worker.reset();
        {
            std::lock_guard lock(mutex);
            if (caught && !stopping) {
                failure = caught;
                stopping = true;
                requests.clear();
            }
            SetEvent(event.get());
            if (notification)
                PostMessageW(notification, message, 0, 0);
        }
        SetEvent(io_finished.get());
    }
    void validate(const GraphicsWindowState &state) {
        require(state.fixture_hash == graphics::fixture::sha256 && state.relocations == 59 &&
                    state.non_executable,
                "Worker fixture identity or page policy differs");
        graphics::GraphicsReply expected;
        expected.metrics = provider->metrics();
        expected.host = provider->host_info();
        require(encode_graphics_reply(expected) == encode_graphics_reply(state.graphics),
                "Worker graphics metrics differ from the trusted service");
        const auto &pixels = provider->fixture_pixels();
        require(pixels.size() >= validated_pixels && pixels.size() - validated_pixels == state.capture_bytes,
                "Unexpected parent readback bytes");
        if (state.capture_bytes)
            require(state.canaries &&
                        apk::sha256(std::span(pixels).subspan(validated_pixels)) == state.capture_hash,
                    "Worker capture differs from trusted readback or changed its canaries");
        if (state.capture_bytes) {
            const auto &presented = graphics->presentation_pixels();
            const auto width = static_cast<std::size_t>(state.guest[9]);
            const auto height = static_cast<std::size_t>(state.guest[10]);
            require(presented.size() == state.capture_bytes && presented.size() == width * height * 4,
                    "Presented back-buffer extent differs from guest readback");
            for (std::size_t y = 0; y < height; ++y)
                require(std::equal(presented.begin() + y * width * 4, presented.begin() + (y + 1) * width * 4,
                                   pixels.begin() + validated_pixels + (height - 1 - y) * width * 4),
                        "HWND back-buffer pixels differ from guest readback");
            ++verified_captures;
        }
        validated_pixels = pixels.size();
    }
};
GraphicsWindowSession::GraphicsWindowSession(const std::filesystem::path &path, bool probe)
    : impl_(std::make_unique<Impl>(path, probe)) {
    impl_->io = std::jthread([p = impl_.get(), probe] { p->run(probe); });
}
GraphicsWindowSession::~GraphicsWindowSession() = default;
std::uint64_t GraphicsWindowSession::attach_window(std::unique_ptr<host::HostSurface> surface) {
    impl_->check_owner();
    require(idle(), "Graphics startup must complete before attaching the window");
    require(surface && surface->alive() && !impl_->surface, "Invalid or repeated host window binding");
    const auto id = next_window.fetch_add(1);
    require(id && id <= 0x0000ffffffffffffULL, "Window identity space exhausted");
    impl_->window_token = graphics::SharedWindowGrant::token_prefix | id;
    impl_->surface = std::move(surface);
    return impl_->window_token;
}
std::uint64_t GraphicsWindowSession::submit(GraphicsWindowCommand command) {
    auto &p = *impl_;
    p.check_owner();
    (void)command.encode();
    host::SurfaceSnapshot surface;
    if (command.kind == GraphicsWindowKind::open ||
        (command.kind == GraphicsWindowKind::draw && command.arguments[0])) {
        require(p.surface != nullptr, "Missing native window binding");
        surface = p.surface->snapshot();
        require(host::HostSurface::valid_snapshot(surface), "Cannot submit an empty or retired window");
        if (command.kind == GraphicsWindowKind::open)
            require(command.arguments[0] == p.window_token && command.arguments[1] == surface.width &&
                        command.arguments[2] == surface.height,
                    "Open command differs from the host binding");
    }
    std::lock_guard lock(p.mutex);
    require(!p.stopping && !p.closing && p.next != UINT64_MAX, "Closed graphics command queue");
    if (command.kind == GraphicsWindowKind::read) {
        ++p.metrics.read_requests;
        if (p.read_ticket) {
            ++p.metrics.coalesced_reads;
            return p.read_ticket;
        }
    }
    require(p.outstanding < (command.kind == GraphicsWindowKind::close ? 257u : 256u),
            "Graphics command quota exceeded");
    const auto ticket = p.next++;
    if (command.kind == GraphicsWindowKind::read)
        p.read_ticket = ticket;
    if (command.kind == GraphicsWindowKind::close)
        p.closing = true;
    p.requests.push_back({ticket, std::move(command), surface});
    ++p.outstanding;
    ++p.metrics.submitted;
    p.metrics.peak_outstanding = std::max(p.metrics.peak_outstanding, p.outstanding);
    p.wake.notify_one();
    return ticket;
}
std::vector<GraphicsWindowCompletion> GraphicsWindowSession::pump() {
    auto &p = *impl_;
    p.check_owner();
    std::exception_ptr failure;
    std::vector<GraphicsWindowCompletion> completed;
    {
        std::lock_guard lock(p.mutex);
        failure = p.failure;
        p.published = p.latest;
        completed = std::move(p.completions);
        p.completions.clear();
        for (const auto &c : completed) {
            if (c.state)
                p.visible = c.state;
            if (c.ticket)
                --p.outstanding;
            if (c.ticket == p.read_ticket)
                p.read_ticket = 0;
        }
        p.posted = false;
        require(ResetEvent(p.event.get()) != FALSE, "Cannot reset graphics completion event");
    }
    if (failure)
        std::rethrow_exception(failure);
    return completed;
}
void GraphicsWindowSession::set_notification(HWND window, UINT message) {
    auto &p = *impl_;
    p.check_owner();
    require(!window || message >= WM_APP, "Invalid graphics completion notification");
    std::lock_guard lock(p.mutex);
    p.notification = window;
    p.message = message;
    p.posted = false;
    if (window && (!p.completions.empty() || p.failure))
        p.notify();
}
HANDLE GraphicsWindowSession::event() const noexcept { return impl_->event.get(); }
void GraphicsWindowSession::abort() noexcept { impl_->abort(); }
void GraphicsWindowSession::shutdown() {
    impl_->check_owner();
    set_notification(nullptr, 0);
    impl_->abort();
    impl_->join();
    impl_->surface.reset();
}
bool GraphicsWindowSession::ready() const { return impl_->visible != nullptr; }
bool GraphicsWindowSession::idle() const {
    std::lock_guard lock(impl_->mutex);
    return impl_->visible && impl_->outstanding == 0 && !impl_->stopping;
}
bool GraphicsWindowSession::read_pending() const {
    std::lock_guard lock(impl_->mutex);
    return impl_->read_ticket != 0;
}
bool GraphicsWindowSession::exited() const {
    std::lock_guard lock(impl_->mutex);
    return impl_->worker_exited;
}
std::uint32_t GraphicsWindowSession::process_id() const {
    std::lock_guard lock(impl_->mutex);
    return impl_->pid;
}
std::uint32_t GraphicsWindowSession::graphics_process_id() const {
    std::lock_guard lock(impl_->mutex);
    return impl_->latest.graphics_pid;
}
const GraphicsWindowState &GraphicsWindowSession::snapshot() const {
    impl_->check_owner();
    require(ready(), "Graphics worker has not published startup state");
    return *impl_->visible;
}
const graphics::Metrics &GraphicsWindowSession::graphics_metrics() const noexcept {
    return impl_->published.graphics;
}
const graphics::HostInfo &GraphicsWindowSession::host_info() const noexcept { return impl_->published.host; }
const std::vector<std::uint8_t> &GraphicsWindowSession::fixture_pixels() const noexcept {
    return *impl_->published.pixels;
}
GraphicsWindowDispatchMetrics GraphicsWindowSession::dispatch_metrics() const {
    std::lock_guard lock(impl_->mutex);
    return impl_->metrics;
}
std::string GraphicsWindowSession::isolation_json() const {
    const auto &p = *impl_;
    p.check_owner();
    std::lock_guard lock(p.mutex);
    std::ostringstream out;
    out << "{\"mode\":\"LPAC\",\"windowsCapabilities\":0,\"brokerOwnsAngle\":false,"
           "\"graphicsServiceOwnsAngle\":true,"
           "\"graphicsServiceMode\":\"LPAC\",\"graphicsServiceCapabilities\":1,"
           "\"graphicsServiceCapabilityNames\":[\"registryRead\"],\"graphicsDynamicCodeProhibited\":true,"
           "\"externalApkExecution\":false,\"appId\":83,\"profile\":\"Aether.Development.GraphicsWindow.83\","
           "\"parentProcessId\":"
        << GetCurrentProcessId() << ",\"processId\":" << p.pid
        << ",\"workerExited\":" << (p.worker_exited ? "true" : "false")
        << ",\"graphicsProcessId\":" << p.latest.graphics_pid
        << ",\"graphicsWorkerExited\":" << (p.latest.graphics_exited ? "true" : "false")
        << ",\"presentationThread\":" << p.latest.presentation.thread
        << ",\"presentedFrames\":" << p.latest.presentation.frames
        << ",\"presentOccluded\":" << p.latest.presentation.occluded
        << ",\"presentBusy\":" << p.latest.presentation.busy
        << ",\"presentationResizes\":" << p.latest.presentation.resizes
        << ",\"presentationReadbacks\":" << p.latest.presentation.captures
        << ",\"verifiedPresentationCaptures\":" << p.latest.verified_captures
        << ",\"graphicsJob\":{\"activeProcesses\":" << p.latest.graphics_usage.active_processes
        << ",\"totalProcesses\":" << p.latest.graphics_usage.total_processes
        << ",\"memoryLimitBytes\":" << p.latest.graphics_usage.memory_limit_bytes
        << ",\"peakCommitBytes\":" << p.latest.graphics_usage.peak_commit_bytes
        << ",\"userTimeLimit100ns\":" << p.latest.graphics_usage.user_time_limit_100ns
        << ",\"userTime100ns\":" << p.latest.graphics_usage.user_time_100ns
        << ",\"limitFlags\":" << p.latest.graphics_usage.limit_flags << '}'
        << ",\"brokerRequests\":" << p.latest.broker_requests
        << ",\"retainedTransferBytes\":" << p.latest.retained_bytes
        << ",\"submitted\":" << p.metrics.submitted << ",\"completed\":" << p.metrics.completed
        << ",\"readRequests\":" << p.metrics.read_requests
        << ",\"coalescedReads\":" << p.metrics.coalesced_reads
        << ",\"readFailures\":" << p.metrics.read_failures
        << ",\"recoveredReads\":" << p.metrics.recovered_reads
        << ",\"peakOutstanding\":" << p.metrics.peak_outstanding << ",\"ioThread\":" << p.metrics.io_thread
        << ",\"windowThread\":" << p.metrics.window_thread << ",\"durableAudit\":" << p.latest.durable_audit
        << ",\"audit\":[";
    bool comma = false;
    for (const auto &e : p.latest.audit) {
        if (comma)
            out << ',';
        comma = true;
        out << "{\"appId\":" << e.app_id << ",\"sequence\":" << e.sequence
            << ",\"operation\":" << static_cast<unsigned>(e.operation)
            << ",\"status\":" << static_cast<unsigned>(e.status) << ",\"payloadBytes\":" << e.payload_bytes
            << ",\"graphicsOperation\":"
            << (e.graphics_operation == UINT32_MAX ? "null" : std::to_string(e.graphics_operation)) << '}';
    }
    return out.str() + "]}";
}
} // namespace aether::security
