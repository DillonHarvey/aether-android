#include "aether/host/native_window_context.hpp"
#include "aether/graphics/shared_window.hpp"
#include "aether/host/entropy.hpp"
#include <array>
#include <algorithm>
#include <condition_variable>
#include <exception>
#include <limits>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <thread>
#include <utility>

namespace aether::host {
namespace {
[[noreturn]] void fail(const char *message) {
    throw std::runtime_error(message);
}
std::uint64_t create_token() {
    std::array<std::uint8_t, 16> bytes{};
    if (!secure_random_128(bytes))
        fail("AETHER_NATIVE_WINDOW_CONTEXT: operating-system entropy is unavailable");
    std::uint64_t identity = 0;
    for (unsigned i = 0; i < 6; ++i) identity |= std::uint64_t{bytes[i]} << (8 * i);
    // The shared-window protocol allocates48 identity bits below its prefix.
    // A zero draw is refused, never replaced with a counter, clock or retry.
    if (!identity)
        fail("AETHER_NATIVE_WINDOW_CONTEXT: random native-window identity is zero");
    return graphics::SharedWindowGrant::token_prefix | identity;
}
} // namespace

struct NativeWindowContext::Impl {
    const std::thread::id ui_owner = std::this_thread::get_id();
    const DWORD window_owner = GetCurrentThreadId();
    const std::uint64_t token = create_token();
    mutable std::mutex mutex;
    mutable std::condition_variable changed;
    std::optional<SurfaceSnapshot> surface;
    bool closed = false;
    HWND request_window = nullptr;
    SurfaceOwner surface_owner;
    bool owner_bound = false, servicing = false;
    std::optional<std::thread::id> request_owner;
    std::uint64_t next_request = 1;
    struct Request {
        std::uint64_t sequence = 0;
        android::NativeSurfaceRequest value;
        std::chrono::steady_clock::time_point deadline;
        std::optional<android::NativeSurfaceAdmission> result;
        std::exception_ptr failure;
        bool cancelled = false, done = false;
    };
    std::shared_ptr<Request> request;
    HWND viewport_window = nullptr;
    ViewportOwner viewport_owner;
    bool viewport_owner_bound = false, servicing_viewport = false;
    std::optional<std::thread::id> viewport_request_owner;
    std::uint64_t next_viewport_request = 1;
    struct ViewportQuery {
        std::uint64_t sequence = 0;
        android::ViewportRequest value;
        std::chrono::steady_clock::time_point deadline;
        std::optional<android::ViewportAdmission> result;
        std::exception_ptr failure;
        bool cancelled = false, done = false;
    };
    std::shared_ptr<ViewportQuery> viewport_request;

    NativeWindowSnapshot checked_snapshot() const {
        if (closed) fail("AETHER_NATIVE_WINDOW_CONTEXT: native-window context is closed");
        if (!surface) fail("AETHER_NATIVE_WINDOW_CONTEXT: native window is not published");
        if (!HostSurface::valid_snapshot(*surface))
            fail("AETHER_NATIVE_WINDOW_CONTEXT: published native-window lifetime is retired");
        return {*surface, token};
    }
};

NativeWindowContext::NativeWindowContext() : impl_(std::make_unique<Impl>()) {}
NativeWindowContext::~NativeWindowContext() { close(); }
void NativeWindowContext::publish(const SurfaceSnapshot &surface) {
    auto &p = *impl_;
    if (p.ui_owner != std::this_thread::get_id() || surface.owner != p.window_owner)
        fail("AETHER_NATIVE_WINDOW_CONTEXT: publication belongs to the Activity UI owner");
    if (!HostSurface::valid_snapshot(surface))
        fail("AETHER_NATIVE_WINDOW_CONTEXT: publication requires a live bounded native window");
    {
        std::lock_guard lock(p.mutex);
        if (p.closed) fail("AETHER_NATIVE_WINDOW_CONTEXT: native-window context cannot reopen");
        if (p.surface && (p.surface->window != surface.window || p.surface->binding != surface.binding ||
                          p.surface->owner != surface.owner))
            fail("AETHER_NATIVE_WINDOW_CONTEXT: native-window identity cannot be replaced");
        p.surface = surface;
    }
    p.changed.notify_all();
}
NativeWindowSnapshot NativeWindowContext::wait_snapshot(std::chrono::steady_clock::time_point deadline) const {
    auto &p = *impl_;
    std::unique_lock lock(p.mutex);
    if (std::chrono::steady_clock::now() >= deadline)
        fail("AETHER_NATIVE_WINDOW_CONTEXT: native-window publication deadline expired");
    if (!p.changed.wait_until(lock, deadline, [&p] { return p.closed || p.surface.has_value(); }) ||
        std::chrono::steady_clock::now() >= deadline)
        fail("AETHER_NATIVE_WINDOW_CONTEXT: native-window publication deadline expired");
    return p.checked_snapshot();
}
NativeWindowSnapshot NativeWindowContext::snapshot() const {
    const auto &p = *impl_;
    std::lock_guard lock(p.mutex);
    return p.checked_snapshot();
}
std::uint64_t NativeWindowContext::token() const noexcept { return impl_->token; }
void NativeWindowContext::bind_surface_owner(HWND window, SurfaceOwner owner) {
    auto &p = *impl_;
    DWORD process = 0;
    if (p.ui_owner != std::this_thread::get_id() || !window || !owner ||
        GetWindowThreadProcessId(window, &process) != p.window_owner || process != GetCurrentProcessId())
        fail("AETHER_NATIVE_WINDOW_CONTEXT: surface service requires its actual UI window owner");
    {
        std::lock_guard lock(p.mutex);
        if (p.closed || p.owner_bound || !p.surface)
            fail("AETHER_NATIVE_WINDOW_CONTEXT: surface owner is closed, unprepared or already bound");
        p.request_window = window;
        p.surface_owner = std::move(owner);
        p.owner_bound = true;
    }
    p.changed.notify_all();
}
android::NativeSurfaceAdmission NativeWindowContext::request_surface(
    const android::NativeSurfaceRequest &value, std::chrono::steady_clock::time_point deadline) {
    auto &p = *impl_;
    const auto now = std::chrono::steady_clock::now();
    deadline = (std::min)(deadline, now + std::chrono::seconds(5));
    if (p.ui_owner == std::this_thread::get_id() || now >= deadline)
        fail("AETHER_NATIVE_WINDOW_CONTEXT: surface request requires a bounded I/O owner");
    auto request = std::make_shared<Impl::Request>();
    request->value = value;
    request->deadline = deadline;
    HWND window = nullptr;
    {
        std::unique_lock lock(p.mutex);
        // The worker may reach a startup callback before run_window has had
        // its first UI turn. Wait for the real owner binding, not invented
        // geometry, within the same original five-second-capped deadline.
        if (!p.changed.wait_until(lock, deadline, [&p] { return p.closed || p.owner_bound; }) ||
            std::chrono::steady_clock::now() >= deadline)
            fail("AETHER_NATIVE_WINDOW_CONTEXT: surface owner preparation deadline expired");
        if (p.closed || p.request || p.servicing || p.viewport_request || p.servicing_viewport ||
            (p.request_owner && *p.request_owner != std::this_thread::get_id()) ||
            (p.viewport_request_owner && *p.viewport_request_owner != std::this_thread::get_id()) ||
            p.next_request == (std::numeric_limits<std::uint64_t>::max)())
            fail("AETHER_NATIVE_WINDOW_CONTEXT: surface request owner, lifetime or sequence is invalid");
        p.request_owner = std::this_thread::get_id();
        request->sequence = p.next_request++;
        p.request = request;
        window = p.request_window;
    }
    // The mailbox owns all payload/result lifetime, including after a timeout.
    // Neither this call nor the UI callback holds the context/dispatcher lock.
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
        deadline - std::chrono::steady_clock::now()).count();
    DWORD_PTR ignored = 0;
    const bool sent = remaining >= 0 && SendMessageTimeoutW(window, surface_request_message,
        static_cast<WPARAM>(request->sequence), 0, SMTO_ABORTIFHUNG | SMTO_ERRORONEXIT,
        static_cast<UINT>((std::min)(remaining + 1, std::int64_t{5000})), &ignored) != 0;
    std::optional<android::NativeSurfaceAdmission> result;
    std::exception_ptr failure;
    bool cancelled = false;
    {
        std::lock_guard lock(p.mutex);
        cancelled = !sent || p.closed || request->cancelled || !request->done ||
            std::chrono::steady_clock::now() >= deadline;
        request->cancelled = cancelled;
        if (!cancelled) { result = request->result; failure = request->failure; }
        if (p.request == request) p.request.reset();
    }
    if (cancelled) {
        close(); // A late owner response must never revive a failed admission.
        fail("AETHER_NATIVE_WINDOW_CONTEXT: surface owner exchange expired or was cancelled");
    }
    if (failure) std::rethrow_exception(failure);
    if (!result) fail("AETHER_NATIVE_WINDOW_CONTEXT: surface owner returned no admission");
    return *result;
}
void NativeWindowContext::service_surface_request(std::uint64_t sequence) noexcept {
    auto &p = *impl_;
    std::shared_ptr<Impl::Request> request;
    SurfaceOwner owner;
    try {
        {
            std::lock_guard lock(p.mutex);
            if (p.ui_owner != std::this_thread::get_id() || p.closed || p.servicing || !p.request ||
                p.request->sequence != sequence || p.request->cancelled || p.request->done ||
                std::chrono::steady_clock::now() >= p.request->deadline) return;
            request = p.request;
            owner = p.surface_owner;
            p.servicing = true;
        }
        std::optional<android::NativeSurfaceAdmission> result;
        std::exception_ptr failure;
        try { result = owner(request->value); } catch (...) { failure = std::current_exception(); }
        std::lock_guard lock(p.mutex);
        p.servicing = false;
        if (p.closed || request->cancelled || p.request != request ||
            std::chrono::steady_clock::now() >= request->deadline) return;
        request->result = result;
        request->failure = failure;
        request->done = true;
    } catch (...) {
        // No exception crosses a WindowProc or makes it recursively drain I/O
        // while that same I/O owner waits for this synchronous message.
        close();
    }
}
void NativeWindowContext::bind_viewport_owner(HWND window, ViewportOwner owner) {
    auto &p = *impl_;
    DWORD process = 0;
    if (p.ui_owner != std::this_thread::get_id() || !window || !owner ||
        GetWindowThreadProcessId(window, &process) != p.window_owner || process != GetCurrentProcessId())
        fail("AETHER_VIEWPORT: viewport service requires its actual UI window owner");
    {
        std::lock_guard lock(p.mutex);
        if (p.closed || p.viewport_owner_bound)
            fail("AETHER_VIEWPORT: viewport owner is closed or already bound");
        p.viewport_window = window;
        p.viewport_owner = std::move(owner);
        p.viewport_owner_bound = true;
    }
    p.changed.notify_all();
}
android::ViewportAdmission NativeWindowContext::request_viewport(
    const android::ViewportRequest &value, std::chrono::steady_clock::time_point deadline) {
    auto &p = *impl_;
    const auto now = std::chrono::steady_clock::now();
    deadline = (std::min)(deadline, now + std::chrono::seconds(5));
    if (p.ui_owner == std::this_thread::get_id() || now >= deadline)
        fail("AETHER_VIEWPORT: viewport query requires a bounded I/O owner");
    auto request = std::make_shared<Impl::ViewportQuery>();
    request->value = value;
    request->deadline = deadline;
    HWND window = nullptr;
    {
        std::unique_lock lock(p.mutex);
        if (!p.changed.wait_until(lock, deadline, [&p] { return p.closed || p.viewport_owner_bound; }) ||
            std::chrono::steady_clock::now() >= deadline)
            fail("AETHER_VIEWPORT: actual UI viewport preparation deadline expired");
        if (p.closed || p.viewport_request || p.servicing_viewport || p.request || p.servicing ||
            (p.viewport_request_owner && *p.viewport_request_owner != std::this_thread::get_id()) ||
            (p.request_owner && *p.request_owner != std::this_thread::get_id()) ||
            p.next_viewport_request == (std::numeric_limits<std::uint64_t>::max)())
            fail("AETHER_VIEWPORT: viewport query owner, lifetime or sequence is invalid");
        p.viewport_request_owner = std::this_thread::get_id();
        request->sequence = p.next_viewport_request++;
        p.viewport_request = request;
        window = p.viewport_window;
    }
    // The context owns the request across timeout and a late sent message.
    // No guest address, DTO pointer or borrowed stack object enters WPARAM.
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
        deadline - std::chrono::steady_clock::now()).count();
    DWORD_PTR ignored = 0;
    const bool sent = remaining >= 0 && SendMessageTimeoutW(window, viewport_request_message,
        static_cast<WPARAM>(request->sequence), 0, SMTO_ABORTIFHUNG | SMTO_ERRORONEXIT,
        static_cast<UINT>((std::min)(remaining + 1, std::int64_t{5000})), &ignored) != 0;
    std::optional<android::ViewportAdmission> result;
    std::exception_ptr failure;
    bool cancelled = false;
    {
        std::lock_guard lock(p.mutex);
        cancelled = !sent || p.closed || request->cancelled || !request->done ||
            std::chrono::steady_clock::now() >= deadline;
        request->cancelled = cancelled;
        if (!cancelled) { result = request->result; failure = request->failure; }
        if (p.viewport_request == request) p.viewport_request.reset();
    }
    if (cancelled) {
        close(); // A late callback cannot revive an expired geometry query.
        fail("AETHER_VIEWPORT: viewport owner exchange expired or was cancelled");
    }
    if (failure) std::rethrow_exception(failure);
    if (!result) fail("AETHER_VIEWPORT: actual UI owner returned no viewport admission");
    return *result;
}
void NativeWindowContext::service_viewport_request(std::uint64_t sequence) noexcept {
    auto &p = *impl_;
    std::shared_ptr<Impl::ViewportQuery> request;
    ViewportOwner owner;
    try {
        {
            std::lock_guard lock(p.mutex);
            if (p.ui_owner != std::this_thread::get_id() || p.closed || p.servicing_viewport ||
                !p.viewport_request || p.viewport_request->sequence != sequence ||
                p.viewport_request->cancelled || p.viewport_request->done ||
                std::chrono::steady_clock::now() >= p.viewport_request->deadline) return;
            request = p.viewport_request;
            owner = p.viewport_owner;
            p.servicing_viewport = true;
        }
        std::optional<android::ViewportAdmission> result;
        std::exception_ptr failure;
        try { result = owner(request->value); } catch (...) { failure = std::current_exception(); }
        std::lock_guard lock(p.mutex);
        p.servicing_viewport = false;
        if (p.closed || request->cancelled || p.viewport_request != request ||
            std::chrono::steady_clock::now() >= request->deadline) return;
        request->result = result;
        request->failure = failure;
        request->done = true;
    } catch (...) {
        // The HWND callback never propagates C++ failures or drains the I/O
        // owner while that same owner waits for this synchronous query.
        close();
    }
}
void NativeWindowContext::close() noexcept {
    auto &p = *impl_;
    {
        std::lock_guard lock(p.mutex);
        p.closed = true;
        if (p.request) p.request->cancelled = true;
        if (p.viewport_request) p.viewport_request->cancelled = true;
        p.request_window = nullptr;
        p.surface_owner = {};
        p.viewport_window = nullptr;
        p.viewport_owner = {};
    }
    p.changed.notify_all();
}
} // namespace aether::host
