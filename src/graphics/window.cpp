#include "aether/graphics/window.hpp"
#include "aether/common/text.hpp"
#include "aether/host/graphics_surface.hpp"
#include "aether/host/window.hpp"
#include "aether/security/graphics_window_session.hpp"
#include "fixture_runtime.hpp"
#include <Windows.h>
#include <algorithm>
#include <exception>
#include <sstream>
#include <windowsx.h>

namespace aether::graphics {
namespace {
constexpr wchar_t window_class[] = L"Aether.GraphicsWindow.v1";
constexpr UINT exercise_message = WM_APP + 2, completion_message = WM_APP + 3;
using Kind = security::GraphicsWindowKind;
constexpr UINT_PTR read_timer = 1, heartbeat_timer = 2;
constexpr DWORD window_style = WS_OVERLAPPEDWINDOW;
[[noreturn]] void fail(std::string message) {
    throw a64::GuestError("AETHER_GRAPHICS_WINDOW", std::move(message));
}
void check_win(BOOL result, const char *operation) {
    if (!result)
        fail(std::string(operation) + " failed (Win32 " + std::to_string(GetLastError()) + ")");
}
struct DpiScope {
    DPI_AWARENESS_CONTEXT previous = SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    DpiScope() {
        if (!previous)
            fail("Cannot enable per-monitor V2 DPI awareness");
    }
    ~DpiScope() { SetThreadDpiAwarenessContext(previous); }
};
class GraphicsWindow {
    security::GraphicsWindowSession &session_;
    WindowReport &report_;
    HINSTANCE instance_ = GetModuleHandleW(nullptr);
    HWND window_ = nullptr;
    ATOM registered_ = 0;
    std::uint64_t binding_ = 0;
    bool ready_ = false, released_ = false, closing_ = false, suspended_ = false;
    bool resize_pending_ = false, drawing_ = false, exercised_ = false, draw_again_ = false;
    bool completing_ = false;
    std::uint64_t draw_ticket_ = 0;
    std::shared_ptr<const security::GraphicsWindowState> captured_;
    bool mouse_down_ = false, touch_down_ = false;
    UINT32 touch_id_ = 0;
    std::array<std::uint32_t, 256> repeats_{};
    std::vector<std::uint8_t> capture_;
    std::exception_ptr failure_;

    void check(std::string name, bool passed) {
        report_.rendering.checks.push_back({std::move(name), passed, {}});
    }
    std::uint64_t state(unsigned index) {
        wait_idle(); // Test harness only; ordinary window callbacks consume cached publications.
        return session_.snapshot().guest.at(index);
    }
    void consume() {
        if (completing_ || released_)
            return;
        completing_ = true;
        struct Reset {
            bool &value;
            ~Reset() { value = false; }
        } reset{completing_};
        for (const auto &done : session_.pump()) {
            if (done.state) {
                report_.guest = done.state->guest;
                report_.width = static_cast<unsigned>(done.state->guest[9]);
                report_.height = static_cast<unsigned>(done.state->guest[10]);
                report_.rendering.fixture_sha256 = done.state->fixture_hash;
                report_.rendering.relocations = static_cast<std::size_t>(done.state->relocations);
                report_.rendering.cpu = done.state->cpu;
                report_.rendering.host = done.state->graphics.host;
            }
            if (done.ticket == draw_ticket_) {
                draw_ticket_ = 0;
                if (done.state && done.state->capture_bytes)
                    captured_ = done.state;
            }
            if (done.kind == Kind::close) {
                finish_close();
                return;
            }
            if (done.ticket && done.kind == Kind::read && !done.unavailable && ready_) {
                render();
                if (report_.selftest && exercised_) {
                    const auto &g = session_.snapshot().guest;
                    const auto m = session_.dispatch_metrics();
                    check("one-second-update-preserves-guest-input-state",
                          g[0] == 1 && g[11] == 3 && g[12] == 1 && g[13] == 0 && g[14] == 0);
                    check("lpac-window-has-separate-io-and-graphics-owners",
                          m.window_thread == GetCurrentThreadId() && m.io_thread &&
                              m.io_thread != m.window_thread);
                    check("async-window-remains-responsive-during-read", report_.responsive_ticks >= 10);
                    check("one-second-read-recovers-without-replaying-input",
                          m.read_failures == 1 && m.recovered_reads == 1 && m.coalesced_reads >= 25 &&
                              g[1] == 2 && g[2] == 7 && g[11] == 3);
                    exercised_ = false;
                    check_win(PostMessageW(window_, WM_CLOSE, 0, 0),
                              "Close completed isolated graphics test");
                }
            }
        }
        if (draw_again_ && !draw_ticket_ && ready_ && !suspended_ && !drawing_) {
            draw_again_ = false;
            render();
        }
    }
    void wait_idle() {
        const auto event = session_.event();
        while (!session_.idle() && !session_.exited()) {
            consume();
            if (failure_)
                std::rethrow_exception(failure_);
            if (session_.idle() || session_.exited())
                break;
            const auto result = MsgWaitForMultipleObjects(1, &event, FALSE, 1000, QS_ALLINPUT);
            check_win(result != WAIT_FAILED, "Wait for graphics startup/test exchange");
            MSG pending{};
            while (PeekMessageW(&pending, nullptr, 0, 0, PM_REMOVE)) {
                if (pending.message == WM_QUIT) {
                    PostQuitMessage(static_cast<int>(pending.wParam));
                    if (failure_)
                        std::rethrow_exception(failure_);
                    if (!session_.exited())
                        fail("Window ended during graphics startup/test exchange");
                    return;
                }
                TranslateMessage(&pending);
                DispatchMessageW(&pending);
            }
        }
    }
    void remember_failure() noexcept {
        if (!failure_)
            failure_ = std::current_exception();
    }
    void resize_client(unsigned width, unsigned height) {
        RECT bounds{0, 0, static_cast<LONG>(width), static_cast<LONG>(height)};
        const auto dpi = GetDpiForWindow(window_);
        check_win(dpi != 0, "GetDpiForWindow");
        check_win(AdjustWindowRectExForDpi(&bounds, window_style, FALSE, 0, dpi), "AdjustWindowRectExForDpi");
        check_win(SetWindowPos(window_, nullptr, 0, 0, bounds.right - bounds.left, bounds.bottom - bounds.top,
                               SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE),
                  "Resize graphics client area");
    }
    void render(bool capture = false, std::string name = {}) {
        if (!ready_ || suspended_ || drawing_)
            return;
        if (draw_ticket_ && !capture) {
            draw_again_ = true;
            return;
        }
        drawing_ = true;
        struct Reset {
            bool &value;
            ~Reset() { value = false; }
        } reset{drawing_};
        if (capture)
            wait_idle();
        const auto before = session_.fixture_pixels().size();
        captured_.reset();
        draw_ticket_ = session_.submit({Kind::draw, {resize_pending_ ? 1ULL : 0ULL, capture ? 1ULL : 0ULL}});
        resize_pending_ = false;
        if (capture) {
            wait_idle();
            if (!captured_)
                fail("Isolated draw did not return capture metadata");
            const auto &pixels = session_.fixture_pixels();
            const auto size = static_cast<std::size_t>(captured_->capture_bytes);
            if (pixels.size() - before != size)
                fail("Unexpected isolated window capture size");
            check(name + "-readback-canaries", captured_->canaries);
            report_.frames.push_back({std::move(name), report_.width, report_.height, capture_.size(), size});
            capture_.insert(capture_.end(), pixels.begin() + before, pixels.end());
        }
    }
    void pointer(android::PointerAction action, int x, int y, unsigned source) {
        if (!ready_)
            return;
        // EGL window coordinates are client pixels. The native fixture consumes Android action/source values.
        const auto event = host::logical_pointer(action, 0, source, x, y, 96);
        session_.submit(
            {Kind::pointer,
             {static_cast<unsigned>(event.action), static_cast<std::uint64_t>(static_cast<std::int64_t>(x)),
              static_cast<std::uint64_t>(static_cast<std::int64_t>(y)), event.source}});
        InvalidateRect(window_, nullptr, FALSE);
    }
    void cancel_pointer() {
        const auto source = touch_down_ ? 0x1002u : 0x2002u;
        const bool active = mouse_down_ || touch_down_;
        mouse_down_ = touch_down_ = false;
        if (GetCapture() == window_)
            ReleaseCapture();
        if (active)
            pointer(android::PointerAction::cancel, 0, 0, source);
    }
    void focus(bool value) {
        if (!ready_)
            return;
        if (!value) {
            cancel_pointer();
            repeats_ = {};
        }
        session_.submit({Kind::focus, {value ? 1ULL : 0ULL}});
    }
    void release_guest() noexcept {
        if (released_)
            return;
        released_ = true;
        ready_ = false;
        if (window_) {
            KillTimer(window_, read_timer);
            KillTimer(window_, heartbeat_timer);
        }
        try {
            session_.shutdown();
        } catch (...) {
            remember_failure();
        }
    }
    void finish_close() {
        const auto &g = session_.graphics_metrics();
        check("guest-window-resources-released",
              session_.exited() && !g.surfaces && !g.contexts && !g.buffers);
        release_guest();
        if (window_)
            check_win(DestroyWindow(window_), "Destroy isolated graphics window");
    }
    void close() {
        if (closing_)
            return;
        closing_ = true;
        KillTimer(window_, read_timer);
        KillTimer(window_, heartbeat_timer);
        if (ready_ && !session_.exited()) {
            focus(false);
            session_.submit({Kind::close});
            ready_ = false;
        } else {
            release_guest();
            if (window_)
                check_win(DestroyWindow(window_), "Destroy graphics window");
        }
    }
    void exercise() {
        check("real-window-egl-surface", report_.created &&
                                             session_.graphics_metrics().window_surfaces == 1 &&
                                             session_.graphics_metrics().window_bindings == 1 &&
                                             binding_ >= a64::GuestMemory::address_limit);
        SendMessageW(window_, WM_SETFOCUS, 0, 0);
        render(true, "initial-red");
        SendMessageW(window_, WM_LBUTTONDOWN, MK_LBUTTON, MAKELPARAM(64, 48));
        SendMessageW(window_, WM_LBUTTONUP, 0, MAKELPARAM(64, 48));
        check("mouse-messages-execute-arm64-callbacks", state(1) == 2 && state(4) == 64 && state(5) == 48 &&
                                                            state(6) == 0x2002 && state(0) == 1 &&
                                                            state(11) == 1);
        render(true, "mouse-green");
        SendMessageW(window_, WM_KEYDOWN, VK_SPACE, 1);
        SendMessageW(window_, WM_KEYDOWN, VK_SPACE, (LPARAM{1} << 30) | 1);
        check("key-repeat-preserves-guest-color", state(7) == 62 && state(8) == 1 && state(11) == 1);
        SendMessageW(window_, WM_KEYUP, VK_SPACE, (LPARAM{1} << 31) | (LPARAM{1} << 30) | 1);
        check("keyboard-release-changes-guest-color", state(0) == 0 && state(11) == 2);
        render(true, "keyboard-red");
        SendMessageW(window_, WM_KEYDOWN, VK_RETURN, 1);
        SendMessageW(window_, WM_KILLFOCUS, 0, 0);
        SendMessageW(window_, WM_KEYUP, VK_RETURN, (LPARAM{1} << 31) | (LPARAM{1} << 30) | 1);
        check("focus-loss-cancels-guest-key-activation", state(12) == 0 && state(14) == 0 && state(11) == 2);
        SendMessageW(window_, WM_SETFOCUS, 0, 0);
        SendMessageW(window_, WM_KEYDOWN, VK_RETURN, 1);
        SendMessageW(window_, WM_KEYUP, VK_RETURN, (LPARAM{1} << 31) | (LPARAM{1} << 30) | 1);
        RECT suggested{};
        check_win(GetWindowRect(window_, &suggested), "Read DPI test rectangle");
        const auto original_dpi = report_.dpi;
        SendMessageW(window_, WM_DPICHANGED, MAKELONG(144, 144), reinterpret_cast<LPARAM>(&suggested));
        check("dpi-message-preserves-guest-context",
              report_.dpi == 144 && session_.graphics_metrics().contexts == 1);
        SendMessageW(window_, WM_DPICHANGED, MAKELONG(original_dpi, original_dpi),
                     reinterpret_cast<LPARAM>(&suggested));
        // Stay above Windows' non-client minimum width while changing both client dimensions.
        resize_client(160, 72);
        render(true, "resized-green");
        check("real-window-resize-updates-guest-egl-dimensions",
              state(9) == 160 && state(10) == 72 && state(0) == 1 && state(11) == 3 &&
                  session_.graphics_metrics().window_surfaces == 1);
        SendMessageW(window_, WM_SIZE, SIZE_MINIMIZED, 0);
        const auto before = session_.graphics_metrics().draws;
        render();
        check("minimized-window-suspends-rendering", session_.graphics_metrics().draws == before);
        SendMessageW(window_, WM_SIZE, SIZE_RESTORED, MAKELPARAM(160, 72));
        SendMessageW(window_, WM_SETFOCUS, 0, 0);
        SendMessageW(window_, WM_PAINT, 0, 0);
        check("paint-message-presents-the-guest-surface", report_.paints > 0);
        report_.rendering.capture_path = detail::save_capture("graphics-window.rgba", capture_);
        exercised_ = true;
        check_win(SetTimer(window_, heartbeat_timer, 100, nullptr) != 0, "Set responsiveness timer");
        check_win(SetTimer(window_, read_timer, 1000, nullptr) != 0, "Set graphics update timer");
    }
    static LRESULT CALLBACK procedure(HWND hwnd, UINT message, WPARAM wp, LPARAM lp) noexcept {
        auto *self = reinterpret_cast<GraphicsWindow *>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        if (message == WM_NCCREATE) {
            self = static_cast<GraphicsWindow *>(reinterpret_cast<CREATESTRUCTW *>(lp)->lpCreateParams);
            self->window_ = hwnd;
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
        }
        if (!self)
            return DefWindowProcW(hwnd, message, wp, lp);
        try {
            ++self->report_.messages;
            return self->message(hwnd, message, wp, lp);
        } catch (...) {
            self->remember_failure();
            self->release_guest();
            if (message == WM_NCCREATE)
                return FALSE;
            if (message == WM_CREATE)
                return -1;
            if (self->window_ && !DestroyWindow(self->window_))
                PostQuitMessage(1);
            return 0;
        }
    }
    LRESULT message(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
        switch (msg) {
        case WM_GETMINMAXINFO: {
            auto &limits = *reinterpret_cast<MINMAXINFO *>(lp);
            RECT maximum{0, 0, 1024, 1024}, minimum{0, 0, 80, 60};
            const auto dpi = report_.dpi ? report_.dpi : 96;
            check_win(AdjustWindowRectExForDpi(&maximum, window_style, FALSE, 0, dpi), "Window maximum size");
            check_win(AdjustWindowRectExForDpi(&minimum, window_style, FALSE, 0, dpi), "Window minimum size");
            limits.ptMaxTrackSize = {maximum.right - maximum.left, maximum.bottom - maximum.top};
            limits.ptMaxSize = limits.ptMaxTrackSize;
            limits.ptMinTrackSize = {minimum.right - minimum.left, minimum.bottom - minimum.top};
            return 0;
        }
        case WM_SIZE:
            ++report_.resizes;
            suspended_ = wp == SIZE_MINIMIZED || !LOWORD(lp) || !HIWORD(lp);
            if (suspended_)
                focus(false);
            else
                resize_pending_ = ready_;
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        case WM_DPICHANGED: {
            report_.dpi = HIWORD(wp);
            ++report_.dpi_changes;
            const auto &suggested = *reinterpret_cast<const RECT *>(lp);
            RECT maximum{0, 0, 1024, 1024};
            check_win(AdjustWindowRectExForDpi(&maximum, window_style, FALSE, 0, report_.dpi), "DPI bounds");
            check_win(SetWindowPos(hwnd, nullptr, suggested.left, suggested.top,
                                   std::min(suggested.right - suggested.left, maximum.right - maximum.left),
                                   std::min(suggested.bottom - suggested.top, maximum.bottom - maximum.top),
                                   SWP_NOZORDER | SWP_NOACTIVATE),
                      "DPI window rectangle");
            return 0;
        }
        case WM_SETFOCUS:
            focus(!suspended_);
            return 0;
        case WM_KILLFOCUS:
            focus(false);
            return 0;
        case WM_ACTIVATE:
            focus(LOWORD(wp) != WA_INACTIVE && !suspended_);
            return 0;
        case WM_LBUTTONDOWN:
        case WM_LBUTTONUP:
        case WM_MOUSEMOVE:
            if (!ready_ || touch_down_ || (msg == WM_MOUSEMOVE && !mouse_down_) ||
                (static_cast<ULONG_PTR>(GetMessageExtraInfo()) & 0xffffff00u) == 0xff515700u)
                return 0;
            if (msg == WM_LBUTTONDOWN) {
                mouse_down_ = true;
                if (!report_.selftest) {
                    SetFocus(hwnd);
                    SetCapture(hwnd);
                }
            }
            pointer(msg == WM_LBUTTONDOWN ? android::PointerAction::down
                    : msg == WM_LBUTTONUP ? android::PointerAction::up
                                          : android::PointerAction::move,
                    GET_X_LPARAM(lp), GET_Y_LPARAM(lp), 0x2002);
            if (msg == WM_LBUTTONUP) {
                mouse_down_ = false;
                if (GetCapture() == hwnd)
                    ReleaseCapture();
            }
            return 0;
        case WM_POINTERDOWN:
        case WM_POINTERUPDATE:
        case WM_POINTERUP: {
            if (!ready_)
                return 0;
            POINTER_INFO info{};
            check_win(GetPointerInfo(GET_POINTERID_WPARAM(wp), &info), "GetPointerInfo");
            if (info.pointerType != PT_TOUCH || !(info.pointerFlags & POINTER_FLAG_PRIMARY))
                return 0;
            if (info.pointerFlags & POINTER_FLAG_CANCELED) {
                cancel_pointer();
                return 0;
            }
            if (msg == WM_POINTERDOWN) {
                cancel_pointer();
                touch_id_ = info.pointerId;
                touch_down_ = true;
                SetFocus(hwnd);
            }
            if (!touch_down_ || touch_id_ != info.pointerId)
                return 0;
            POINT point = info.ptPixelLocation;
            check_win(ScreenToClient(hwnd, &point), "ScreenToClient");
            pointer(msg == WM_POINTERDOWN ? android::PointerAction::down
                    : msg == WM_POINTERUP ? android::PointerAction::up
                                          : android::PointerAction::move,
                    point.x, point.y, 0x1002);
            if (msg == WM_POINTERUP)
                touch_down_ = false;
            return 0;
        }
        case WM_CAPTURECHANGED:
        case WM_POINTERCAPTURECHANGED:
        case WM_CANCELMODE:
            cancel_pointer();
            return 0;
        case WM_KEYDOWN:
        case WM_KEYUP:
        case WM_SYSKEYDOWN:
        case WM_SYSKEYUP: {
            if (!ready_)
                return DefWindowProcW(hwnd, msg, wp, lp);
            const bool up = msg == WM_KEYUP || msg == WM_SYSKEYUP;
            const auto key = static_cast<std::uint32_t>(wp);
            std::uint32_t repeat = 0;
            if (key < repeats_.size()) {
                if (up || !(lp & (LPARAM{1} << 30)))
                    repeats_[key] = 0;
                else
                    repeats_[key] =
                        std::min(65535u, repeats_[key] + std::max(1u, static_cast<unsigned>(LOWORD(lp))));
                repeat = repeats_[key];
            }
            session_.submit({Kind::key, {up ? 1ULL : 0ULL, host::android_keycode(key), repeat}});
            InvalidateRect(hwnd, nullptr, FALSE);
            return key == VK_SPACE || key == VK_RETURN ? 0 : DefWindowProcW(hwnd, msg, wp, lp);
        }
        case WM_TIMER:
            if (wp == heartbeat_timer) {
                if (session_.read_pending())
                    ++report_.responsive_ticks;
                return 0;
            }
            if (wp != read_timer || !ready_ || closing_)
                return 0;
            ++report_.timer_reads;
            session_.submit({Kind::read});
            if (report_.selftest && report_.timer_reads == 1)
                for (unsigned i = 0; i < 25; ++i)
                    session_.submit({Kind::read});
            return 0;
        case completion_message:
            consume();
            return 0;
        case WM_ERASEBKGND:
            return 1;
        case WM_PAINT: {
            PAINTSTRUCT paint{};
            BeginPaint(hwnd, &paint);
            try {
                render();
            } catch (...) {
                EndPaint(hwnd, &paint);
                throw;
            }
            EndPaint(hwnd, &paint);
            ++report_.paints;
            return 0;
        }
        case exercise_message:
            exercise();
            return 0;
        case WM_CLOSE:
            close();
            return 0;
        case WM_DESTROY:
            release_guest();
            PostQuitMessage(0);
            return 0;
        case WM_NCDESTROY:
            release_guest();
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            window_ = nullptr;
            report_.closed = true;
            return DefWindowProcW(hwnd, msg, wp, lp);
        default:
            return DefWindowProcW(hwnd, msg, wp, lp);
        }
    }

  public:
    GraphicsWindow(security::GraphicsWindowSession &session, WindowReport &report)
        : session_(session), report_(report) {}
    ~GraphicsWindow() {
        release_guest();
        if (window_)
            DestroyWindow(window_);
        if (registered_)
            UnregisterClassW(window_class, instance_);
    }
    void run() {
        WNDCLASSEXW wc{};
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = procedure;
        wc.hInstance = instance_;
        wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        wc.lpszClassName = window_class;
        registered_ = RegisterClassExW(&wc);
        check_win(registered_ != 0, "Register graphics window class");
        const auto hwnd = CreateWindowExW(
            0, window_class, L"Aether Graphics - click or Space to change color (first-party fixture)",
            window_style, CW_USEDEFAULT, CW_USEDEFAULT, 400, 300, nullptr, nullptr, instance_, this);
        if (failure_)
            std::rethrow_exception(failure_);
        check_win(hwnd != nullptr, "Create graphics window");
        report_.created = true;
        session_.set_notification(hwnd, completion_message);
        wait_idle();
        report_.dpi = GetDpiForWindow(hwnd);
        resize_client(report_.selftest ? 128 : 320, report_.selftest ? 96 : 240);
        auto surface = std::make_unique<host::HostSurface>(hwnd);
        const auto size = surface->extent();
        binding_ = session_.attach_window(std::move(surface));
        session_.submit({Kind::open, {binding_, size[0], size[1]}});
        wait_idle();
        ready_ = true;
        report_.rendering.host = session_.host_info();
        render();
        wait_idle();
        if (report_.selftest)
            check_win(PostMessageW(hwnd, exercise_message, 0, 0), "Post graphics exercise");
        else {
            check_win(SetTimer(hwnd, read_timer, 1000, nullptr) != 0, "Set graphics update timer");
            ShowWindow(hwnd, SW_SHOWNORMAL);
            UpdateWindow(hwnd);
        }
        MSG message{};
        for (;;) {
            const auto status = GetMessageW(&message, nullptr, 0, 0);
            if (status == -1)
                fail("Graphics GetMessage failed");
            if (!status)
                break;
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
        if (window_)
            close();
        if (failure_)
            std::rethrow_exception(failure_);
    }
};
} // namespace
WindowReport run_graphics_window(const std::filesystem::path &path, bool selftest) {
    security::GraphicsWindowSession session(path, selftest); // Parent hash gate precedes HWND creation.
    WindowReport report;
    report.selftest = selftest;
    report.rendering.command = selftest ? "graphics-window-selftest" : "graphics-run";
    DpiScope dpi;
    {
        GraphicsWindow window(session, report);
        window.run();
    }
    report.rendering.graphics = session.graphics_metrics();
    report.rendering.cpu = session.snapshot().cpu;
    report.rendering.isolation_json = session.isolation_json();
    const auto &g = report.rendering.graphics;
    report.rendering.checks.push_back({"window-and-owned-graphics-closed",
                                       report.created && report.closed && g.contexts == 0 &&
                                           g.surfaces == 0 && g.shaders == 0 && g.programs == 0 &&
                                           g.buffers == 0 && g.buffer_bytes == 0 && g.window_bindings == 0 &&
                                           g.window_surfaces == 0 && g.cleanup_failures == 0,
                                       {}});
    report.rendering.checks.push_back(
        {"actual-arm64-hardware-window-presentation",
         report.rendering.host.hardware && report.rendering.cpu.compiled_blocks > 200 &&
             report.rendering.cpu.emitted_bytes > 10000 && report.rendering.cpu.rx_failures == 0 &&
             report.rendering.cpu.interpreter_fallbacks == 0 && g.window_swaps >= g.draws && g.draws > 0 &&
             g.rejected == 0,
         {}});
    report.rendering.checks.push_back(
        {"guest-pages-remain-non-executable", session.snapshot().non_executable, {}});
    return report;
}
bool WindowReport::passed() const { return rendering.passed() && created && closed; }
std::string WindowReport::json() const {
    std::ostringstream out;
    out << "{\"schemaVersion\":1,\"command\":" << json_quote(rendering.command)
        << ",\"passed\":" << (passed() ? "true" : "false")
        << ",\"selftest\":" << (selftest ? "true" : "false")
        << ",\"windowCreated\":" << (created ? "true" : "false")
        << ",\"windowClosed\":" << (closed ? "true" : "false") << ",\"rendering\":" << rendering.json()
        << ",\"window\":{\"messages\":" << messages << ",\"paints\":" << paints << ",\"resizes\":" << resizes
        << ",\"dpiChanges\":" << dpi_changes << ",\"responsiveTicks\":" << responsive_ticks
        << ",\"timerReads\":" << timer_reads << ",\"dpi\":" << dpi << ",\"width\":" << width
        << ",\"height\":" << height << "},\"guestState\":[";
    for (std::size_t n = 0; n < guest.size(); ++n) {
        if (n)
            out << ',';
        out << guest[n];
    }
    out << "],\"frames\":[";
    for (std::size_t n = 0; n < frames.size(); ++n) {
        if (n)
            out << ',';
        const auto &f = frames[n];
        out << "{\"name\":" << json_quote(f.name) << ",\"width\":" << f.width << ",\"height\":" << f.height
            << ",\"offset\":" << f.offset << ",\"bytes\":" << f.bytes << '}';
    }
    return out.str() + "]}";
}
std::string WindowReport::text(bool verbose) const {
    std::ostringstream out;
    out << "ARM64 GLES Win32 window: " << (passed() ? "PASS" : "FAIL") << '\n'
        << "ANGLE D3D11 hardware: " << rendering.host.adapter << '\n'
        << rendering.graphics.window_swaps << " window swaps; " << guest[1] << " native pointer events; "
        << guest[2] << " native key events\n";
    if (verbose || !passed())
        for (const auto &check : rendering.checks)
            out << (check.passed ? "  PASS " : "  FAIL ") << check.name << '\n';
    return out.str();
}
} // namespace aether::graphics
