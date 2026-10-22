#include "aether/security/activity_dispatcher.hpp"
#include "aether/host/windows/unique_handle.hpp"
#include <algorithm>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>

namespace aether::security {
namespace {
void require(bool value, const char *message) {
    if (!value)
        throw ProtocolError(std::string("AETHER_ACTIVITY_DISPATCH: ") + message);
}
struct Request {
    std::uint64_t ticket;
    ActivityCommand command;
};
} // namespace
struct ActivityDispatcher::Impl {
    const std::thread::id owner = std::this_thread::get_id();
    host::UniqueHandle event{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    mutable std::mutex mutex;
    std::condition_variable wake;
    std::deque<Request> requests;
    std::vector<ActivityCompletion> completions;
    ActivityPublication pending, visible;
    ActivityDispatchMetrics metrics;
    std::exception_ptr failure;
    IsolatedActivity *active = nullptr; // Protected by mutex; only cancel crosses threads.
    std::uint64_t next = 1, outstanding = 0, read_ticket = 0;
    bool stopping = false, closing = false, read_failed = false;
    HWND notification_window = nullptr;
    UINT notification_message = 0;
    bool notification_posted = false;
    std::jthread io;
    Impl() { require(static_cast<bool>(event), "Cannot create completion event"); }
    void check_owner() const { require(std::this_thread::get_id() == owner, "Wrong UI owner thread"); }
    void notify() {
        require(SetEvent(event.get()) != FALSE, "Cannot signal completion event");
        if (notification_window && !notification_posted) {
            require(PostMessageW(notification_window, notification_message, 0, 0) != FALSE,
                    "Cannot post completion notification");
            notification_posted = true;
        }
    }
    void abort() noexcept {
        std::lock_guard lock(mutex);
        stopping = true;
        requests.clear();
        if (active)
            active->cancel();
        wake.notify_all();
    }
    ~Impl() {
        abort();
        if (io.joinable())
            io.join();
    }
    void publish(IsolatedActivity &session, ActivityCompletion completion) {
        // Copy outside the mailbox lock. Only the I/O thread touches the connection.
        ActivityPublication update;
        update.state = std::make_shared<const ActivityState>(session.snapshot());
        update.process_id = session.process_id();
        update.commands = session.command_count();
        update.broker_calls = session.broker_calls();
        update.exited = session.exited();
        update.audit = session.audit_json();
        update.durable_audit = session.durable_audit_json();
        std::lock_guard lock(mutex);
        update.last_live = update.state->content ? update.state : pending.last_live;
        pending = std::move(update);
        completions.push_back(completion);
        if (completion.ticket) {
            ++metrics.completed;
            if (completion.read_unavailable) {
                ++metrics.read_failures;
                read_failed = true;
            } else if (completion.kind == ActivityCommandKind::refresh && read_failed) {
                ++metrics.recovered_reads;
                read_failed = false;
            }
        }
        notify();
    }
    void run(std::filesystem::path apk, ActivityMode mode,
             const InstalledActivity *application = nullptr) noexcept {
        try {
            auto owned = application ? std::make_unique<IsolatedActivity>(*application)
                                     : std::make_unique<IsolatedActivity>(apk, mode);
            auto &session = *owned;
            {
                std::lock_guard lock(mutex);
                if (stopping)
                    return;
                active = &session;
                metrics.io_thread = GetCurrentThreadId();
            }
            // Always detach the cross-thread cancellation pointer before destruction.
            struct Detach {
                Impl &self;
                ~Detach() {
                    std::lock_guard lock(self.mutex);
                    self.active = nullptr;
                }
            } detach{*this};
            publish(session, {});
            for (;;) {
                Request request;
                {
                    std::unique_lock lock(mutex);
                    wake.wait_for(lock, std::chrono::milliseconds(10), [&] { return stopping || !requests.empty(); });
                    if (stopping)
                        break;
                    if (requests.empty()) {
                        lock.unlock();
                        (void)session.service_background();
                        continue;
                    }
                    request = std::move(requests.front());
                    requests.pop_front();
                }
                ActivityCompletion completion{request.ticket, request.command.kind};
                try {
                    session.dispatch(request.command);
                    completion.handled = session.snapshot().handled;
                } catch (const ActivityReadUnavailable &) {
                    require(request.command.kind == ActivityCommandKind::refresh,
                            "A mutation cannot be retried as a state read");
                    completion.read_unavailable = true;
                }
                publish(session, completion);
                if (request.command.kind == ActivityCommandKind::close)
                    break;
            }
        } catch (...) {
            std::lock_guard lock(mutex);
            if (!stopping)
                failure = std::current_exception();
            stopping = true;
            requests.clear();
            SetEvent(event.get());
            if (notification_window)
                PostMessageW(notification_window, notification_message, 0, 0);
        }
    }
};
ActivityDispatcher::ActivityDispatcher(const std::filesystem::path &apk, ActivityMode mode)
    : impl_(std::make_unique<Impl>()) {
    impl_->io = std::jthread([self = impl_.get(), apk, mode] { self->run(apk, mode); });
}
ActivityDispatcher::~ActivityDispatcher() = default;
ActivityDispatcher::ActivityDispatcher(InstalledActivity application) : impl_(std::make_unique<Impl>()) {
    impl_->io = std::jthread(
        [self = impl_.get(), app = std::move(application)] { self->run({}, ActivityMode::normal, &app); });
}
std::uint64_t ActivityDispatcher::submit(ActivityCommand command) {
    auto &p = *impl_;
    p.check_owner();
    (void)command.encode(); // Bound copied command storage before adding it to the queue.
    std::lock_guard lock(p.mutex);
    require(!p.stopping && !p.closing && p.next != UINT64_MAX, "Closed command queue");
    if (command.kind == ActivityCommandKind::refresh) {
        ++p.metrics.read_requests;
        if (p.read_ticket) {
            ++p.metrics.coalesced_reads;
            return p.read_ticket;
        }
    }
    // Reserve a final slot for ordered close. Completed but unconsumed replies also count.
    require(p.outstanding < (command.kind == ActivityCommandKind::close ? 257u : 256u),
            "Pending command quota exceeded");
    const auto ticket = p.next++;
    p.requests.push_back({ticket, std::move(command)});
    const auto kind = p.requests.back().command.kind;
    if (kind == ActivityCommandKind::refresh)
        p.read_ticket = ticket;
    if (kind == ActivityCommandKind::close)
        p.closing = true;
    ++p.outstanding;
    ++p.metrics.submitted;
    p.metrics.peak_outstanding = std::max(p.metrics.peak_outstanding, p.outstanding);
    p.wake.notify_one();
    return ticket;
}
void ActivityDispatcher::signal(android::WindowSignal value) {
    ActivityCommand command;
    command.kind =
        value == android::WindowSignal::close ? ActivityCommandKind::close : ActivityCommandKind::signal;
    command.signal = value;
    (void)submit(std::move(command));
}
void ActivityDispatcher::place_views(std::span<const android::ViewPlacement> placements) {
    ActivityCommand command;
    command.kind = ActivityCommandKind::place;
    command.placements.assign(placements.begin(), placements.end());
    (void)submit(std::move(command));
}
void ActivityDispatcher::pointer(const android::PointerInput &input) {
    ActivityCommand command;
    command.kind = ActivityCommandKind::pointer;
    command.pointer = input;
    (void)submit(std::move(command));
}
std::uint64_t ActivityDispatcher::key(const android::KeyInput &input) {
    ActivityCommand command;
    command.kind = ActivityCommandKind::key;
    command.key = input;
    return submit(std::move(command));
}
std::uint64_t ActivityDispatcher::refresh() { return submit({}); }
void ActivityDispatcher::close() {
    ActivityCommand command;
    command.kind = ActivityCommandKind::close;
    (void)submit(std::move(command));
}
void ActivityDispatcher::abort() noexcept { impl_->abort(); }
HANDLE ActivityDispatcher::completion_event() const noexcept { return impl_->event.get(); }
void ActivityDispatcher::set_notification(HWND window, UINT message) {
    auto &p = *impl_;
    p.check_owner();
    require(!window || message >= WM_APP, "Invalid host notification message");
    std::lock_guard lock(p.mutex);
    p.notification_window = window;
    p.notification_message = message;
    p.notification_posted = false;
    if (window && (!p.completions.empty() || p.failure))
        p.notify();
}
std::vector<ActivityCompletion> ActivityDispatcher::consume() {
    auto &p = *impl_;
    p.check_owner();
    std::lock_guard lock(p.mutex);
    if (p.failure)
        std::rethrow_exception(p.failure);
    if (p.pending.state)
        p.visible = p.pending;
    auto result = std::move(p.completions);
    p.completions.clear();
    p.notification_posted = false;
    for (const auto &completion : result) {
        if (completion.ticket)
            --p.outstanding;
        if (completion.ticket == p.read_ticket)
            p.read_ticket = 0;
    }
    require(ResetEvent(p.event.get()) != FALSE, "Cannot reset completion event");
    return result;
}
bool ActivityDispatcher::idle() const {
    std::lock_guard lock(impl_->mutex);
    return impl_->pending.state && impl_->outstanding == 0 && !impl_->stopping;
}
bool ActivityDispatcher::read_pending() const {
    std::lock_guard lock(impl_->mutex);
    return impl_->read_ticket != 0;
}
ActivityDispatchMetrics ActivityDispatcher::dispatch_metrics() const {
    std::lock_guard lock(impl_->mutex);
    return impl_->metrics;
}
const ActivityPublication &ActivityDispatcher::publication() const noexcept { return impl_->visible; }
const ActivityState &ActivityDispatcher::snapshot() const {
    impl_->check_owner();
    require(impl_->visible.state != nullptr, "Activity has not published startup state");
    return *impl_->visible.state;
}
std::uint32_t ActivityDispatcher::probe(std::string_view name) const {
    for (std::size_t i = 0; i < activity_probes.size(); ++i)
        if (activity_probes[i] == name)
            return snapshot().probes[i];
    throw ProtocolError("AETHER_ACTIVITY_PROBE: unknown first-party input probe");
}
} // namespace aether::security
