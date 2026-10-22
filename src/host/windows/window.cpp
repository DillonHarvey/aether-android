#include "aether/host/window.hpp"
#include "aether/apk/artwork.hpp"
#include "aether/apk/package.hpp"
#include "aether/common/text.hpp"
#include "aether/security/activity_dispatcher.hpp"
#include <Windows.h>
#include <propsys.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cmath>
#include <exception>
#include <propkey.h>
#include <propvarutil.h>
#include <shellapi.h>
#include <shobjidl.h>
#include <sstream>
#include <wincodec.h>
#include <windowsx.h>
#include <wrl/client.h>

namespace aether::host {
namespace {
using namespace android;
using Microsoft::WRL::ComPtr;
constexpr wchar_t window_class[] = L"Aether.ActivityWindow.v1";
constexpr UINT exercise_message = WM_APP + 1;
constexpr UINT completion_message = WM_APP + 2;
constexpr UINT_PTR read_timer = 1;
constexpr UINT_PTR responsiveness_timer = 2;
const std::array window_identity_keys{
    PKEY_AppUserModel_ID, PKEY_AppUserModel_RelaunchCommand, PKEY_AppUserModel_RelaunchDisplayNameResource,
    PKEY_AppUserModel_RelaunchIconResource, PKEY_AppUserModel_PreventPinning};
[[noreturn]] void fail(std::string message) { throw dex::DexError("AETHER_WINDOW_HOST", std::move(message)); }
void check_win(BOOL result, const char *operation) {
    if (!result)
        fail(std::string(operation) + " failed (Win32 " + std::to_string(GetLastError()) + ")");
}
void check_hr(HRESULT result, const char *operation) {
    if (FAILED(result))
        fail(std::string(operation) + " failed (HRESULT " + std::to_string(result) + ")");
}
std::string narrow(std::u16string_view value) { return utf8(std::wstring(value.begin(), value.end())); }
std::wstring wide(std::u16string_view value) { return {value.begin(), value.end()}; }
struct DpiScope {
    DPI_AWARENESS_CONTEXT previous = SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    DpiScope() {
        if (!previous)
            fail("Cannot enable per-monitor V2 DPI awareness");
    }
    ~DpiScope() { SetThreadDpiAwarenessContext(previous); }
};
struct DcState {
    HDC dc;
    int saved;
    explicit DcState(HDC dc) : dc(dc), saved(SaveDC(dc)) { check_win(saved != 0, "SaveDC"); }
    ~DcState() { RestoreDC(dc, saved); }
};
struct PaintScope {
    HWND window;
    PAINTSTRUCT paint{};
    HDC dc;
    explicit PaintScope(HWND window) : window(window), dc(BeginPaint(window, &paint)) {}
    ~PaintScope() { EndPaint(window, &paint); }
};
struct Buffer {
    HDC dc = nullptr;
    HBITMAP bitmap = nullptr;
    HGDIOBJ previous = nullptr;
    std::uint32_t *pixels = nullptr;
    int width = 0, height = 0;
    ~Buffer() { clear(); }
    void clear() noexcept {
        if (dc && previous)
            SelectObject(dc, previous);
        if (bitmap)
            DeleteObject(bitmap);
        if (dc)
            DeleteDC(dc);
        dc = nullptr;
        bitmap = nullptr;
        previous = nullptr;
        pixels = nullptr;
        width = height = 0;
    }
    void resize(int w, int h) {
        if (w == width && h == height)
            return;
        if (w <= 0 || h <= 0 || w > 16384 || h > 16384 || std::uint64_t(w) * h > 16'777'216)
            fail("Window backing surface exceeds the 16-million-pixel quota");
        clear();
        dc = CreateCompatibleDC(nullptr);
        check_win(dc != nullptr, "CreateCompatibleDC");
        BITMAPINFO info{};
        info.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        info.bmiHeader.biWidth = w;
        info.bmiHeader.biHeight = -h;
        info.bmiHeader.biPlanes = 1;
        info.bmiHeader.biBitCount = 32;
        info.bmiHeader.biCompression = BI_RGB;
        void *storage = nullptr;
        bitmap = CreateDIBSection(dc, &info, DIB_RGB_COLORS, &storage, nullptr, 0);
        check_win(bitmap != nullptr && storage != nullptr, "CreateDIBSection");
        pixels = static_cast<std::uint32_t *>(storage);
        previous = SelectObject(dc, bitmap);
        check_win(previous != nullptr && previous != HGDI_ERROR, "SelectObject bitmap");
        width = w;
        height = h;
    }
    std::span<const std::uint32_t> data() const { return {pixels, std::size_t(width) * height}; }
    void capture(const std::filesystem::path &path) const {
        const auto initialized = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        check_hr(initialized, "CoInitializeEx");
        struct End {
            ~End() { CoUninitialize(); }
        } end;
        ComPtr<IWICImagingFactory> factory;
        check_hr(CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER,
                                  IID_PPV_ARGS(factory.GetAddressOf())),
                 "WIC factory");
        ComPtr<IWICStream> stream;
        check_hr(factory->CreateStream(stream.GetAddressOf()), "WIC stream");
        check_hr(stream->InitializeFromFilename(path.c_str(), GENERIC_WRITE), "PNG destination");
        ComPtr<IWICBitmapEncoder> encoder;
        check_hr(factory->CreateEncoder(GUID_ContainerFormatPng, nullptr, encoder.GetAddressOf()),
                 "PNG encoder");
        check_hr(encoder->Initialize(stream.Get(), WICBitmapEncoderNoCache), "PNG initialize");
        ComPtr<IWICBitmapFrameEncode> frame;
        check_hr(encoder->CreateNewFrame(frame.GetAddressOf(), nullptr), "PNG frame");
        check_hr(frame->Initialize(nullptr), "PNG frame initialize");
        check_hr(frame->SetSize(static_cast<UINT>(width), static_cast<UINT>(height)), "PNG size");
        auto format = GUID_WICPixelFormat32bppBGRA;
        check_hr(frame->SetPixelFormat(&format), "PNG format");
        if (format != GUID_WICPixelFormat32bppBGRA)
            fail("Unexpected PNG pixel format");
        std::vector<std::uint32_t> opaque(data().begin(), data().end());
        for (auto &pixel : opaque)
            pixel |= 0xff000000u;
        check_hr(frame->WritePixels(static_cast<UINT>(height), static_cast<UINT>(width * 4),
                                    static_cast<UINT>(data().size_bytes()),
                                    reinterpret_cast<BYTE *>(opaque.data())),
                 "PNG pixels");
        check_hr(frame->Commit(), "PNG frame commit");
        check_hr(encoder->Commit(), "PNG commit");
    }
};
class ActivityWindow {
    DpiScope dpi_scope;
    security::ActivityDispatcher &session;
    WindowReport &report;
    HWND window = nullptr;
    HINSTANCE instance = GetModuleHandleW(nullptr);
    ATOM registered = 0;
    HFONT font = nullptr;
    HICON large_icon = nullptr, small_icon = nullptr;
    std::vector<std::uint8_t> icon_bytes;
    Buffer buffer;
    unsigned dpi = 96;
    std::uint64_t observed_revision = ~std::uint64_t{0};
    std::exception_ptr failure;
    std::array<std::uint32_t, 256> repeats{};
    bool mouse_down = false, exercised = false, shutting_down = false;
    std::uint32_t touch_id = 0;
    bool touch_down = false;
    bool selftest_focus = false;
    std::uint64_t selftest_revision = 0;
    std::map<dex::ObjectId, ViewBounds> layout_bounds;
    struct NativeKey {
        UINT message;
        WPARAM wp;
        LPARAM lp;
    };
    std::map<std::uint64_t, NativeKey> pending_keys;
    unsigned exercise_stage = 0;
    int initial_width = 0;
    RECT suggested{};
    std::vector<std::uint32_t> before_click;
    bool queued_probe_key = false, released_probe_key = false;
    std::uint64_t last_read_ticket = 0, selftest_read_floor = 0;
    static LRESULT CALLBACK procedure(HWND hwnd, UINT message, WPARAM wp, LPARAM lp) noexcept {
        auto *self = reinterpret_cast<ActivityWindow *>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        if (message == WM_NCCREATE) {
            self = static_cast<ActivityWindow *>(reinterpret_cast<CREATESTRUCTW *>(lp)->lpCreateParams);
            self->window = hwnd;
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
        }
        if (!self)
            return DefWindowProcW(hwnd, message, wp, lp);
        try {
            ++self->report.messages;
            return self->message(hwnd, message, wp, lp);
        } catch (...) {
            if (!self->failure)
                self->failure = std::current_exception();
            // No C++ exception crosses the system callback boundary.
            self->shutting_down = true;
            KillTimer(hwnd, read_timer);
            DestroyWindow(hwnd);
            PostQuitMessage(1);
            return 0;
        }
    }
    void set_icons() {
        if (icon_bytes.empty())
            return;
        // Only the canonical DIB emitted by our bounded bitmap encoder reaches
        // Windows. Raw PNG chunks, resource paths and APK bytes never do.
        const auto integer = [&](std::size_t at) {
            check_win(at + 4 <= icon_bytes.size(), "Canonical icon directory");
            return std::uint32_t(icon_bytes[at]) | (std::uint32_t(icon_bytes[at + 1]) << 8) |
                   (std::uint32_t(icon_bytes[at + 2]) << 16) | (std::uint32_t(icon_bytes[at + 3]) << 24);
        };
        const auto create = [&](int metric) {
            const auto size = GetSystemMetricsForDpi(metric, dpi);
            check_win(size > 0 && icon_bytes.size() >= 6, "Canonical icon dimensions");
            const auto count = unsigned(icon_bytes[4]) | (unsigned(icon_bytes[5]) << 8);
            check_win((count == 4 || count == 7) && 6 + count * 16 <= icon_bytes.size(),
                      "Canonical icon directory count");
            // Both retained four-frame icons and modern seven-frame icons use
            // ascending dimensions. Select by the directory, never by an index
            // tied to one renderer's frame list, including at fractional DPI.
            auto index = count - 1;
            for (unsigned candidate = 0; candidate < count; ++candidate) {
                const auto width = icon_bytes[6 + candidate * 16];
                if ((width ? int(width) : 256) >= size) {
                    index = candidate;
                    break;
                }
            }
            const auto entry = 6 + index * 16;
            const auto length = integer(entry + 8), offset = integer(entry + 12);
            check_win(offset <= icon_bytes.size() && length <= icon_bytes.size() - offset,
                      "Canonical icon image");
            return CreateIconFromResourceEx(icon_bytes.data() + offset, length, TRUE, 0x00030000, size, size,
                                            LR_DEFAULTCOLOR);
        };
        const auto large = create(SM_CXICON), created_small = create(SM_CXSMICON);
        if (!large || !created_small) {
            if (large)
                DestroyIcon(large);
            if (created_small)
                DestroyIcon(created_small);
            fail("Cannot create the canonical application icon");
        }
        SendMessageW(window, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(large));
        SendMessageW(window, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(created_small));
        if (large_icon)
            DestroyIcon(large_icon);
        if (small_icon)
            DestroyIcon(small_icon);
        large_icon = large;
        small_icon = created_small;
    }
    void set_dpi(unsigned value) {
        if (value < 48 || value > 960)
            fail("Unsupported window DPI");
        auto replacement = CreateFontW(-MulDiv(16, static_cast<int>(value), 96), 0, 0, 0, FW_NORMAL, FALSE,
                                       FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                       CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        check_win(replacement != nullptr, "CreateFont");
        if (font)
            DeleteObject(font);
        font = replacement;
        dpi = value;
        observed_revision = ~std::uint64_t{0};
    }
    int px(float logical) const {
        return static_cast<int>(std::lround(logical * static_cast<float>(dpi) / 96.0f));
    }
    RECT rectangle(const ViewBounds &r) const {
        return {px(r.x), px(r.y), px(r.x + r.width), px(r.y + r.height)};
    }
    float text_height(const ViewState &view, float width) {
        auto text = wide(view.text);
        RECT r{0, 0, std::max(1, px(width)), 0};
        DrawTextW(buffer.dc, text.data(), static_cast<int>(text.size()), &r,
                  DT_CALCRECT | DT_WORDBREAK | DT_NOPREFIX);
        return std::max(28.0f, static_cast<float>(r.bottom) * 96.0f / static_cast<float>(dpi));
    }
    float arrange(dex::ObjectId id, float x, float y, float width, std::vector<ViewPlacement> &placements) {
        const auto &view = session.views().at(id);
        width = std::max(width, 0.0f);
        if (view.kind != ViewKind::linear_layout) {
            const auto height = view.kind == ViewKind::button
                                    ? std::max(48.0f, text_height(view, std::max(0.0f, width - 32)) + 16)
                                    : text_height(view, width);
            placements.push_back({id, {x, y, width, height}});
            return height;
        }
        const auto inner = std::max(0.0f, width - 32);
        float used = 0;
        if (view.orientation == 1) {
            for (auto child : view.children) {
                const auto height = arrange(child, x + 16, y + 16 + used, inner, placements);
                used = std::min(32000.0f, used + height + 12);
            }
        } else {
            const auto count = static_cast<float>(view.children.size());
            const float cell = count ? std::max(0.0f, (inner - 12 * (count - 1)) / count) : 0;
            float offset = 0;
            for (auto child : view.children) {
                used = std::max(used, arrange(child, x + 16 + offset, y + 16, cell, placements) + 12);
                offset += cell + 12;
            }
        }
        const auto height = 32 + std::max(0.0f, used - 12);
        placements.push_back({id, {x, y, width, height}});
        return height;
    }
    void synchronize() {
        if (shutting_down || !session.content_view())
            return;
        RECT client{};
        check_win(GetClientRect(window, &client), "GetClientRect");
        const int w = client.right, h = client.bottom;
        if (w <= 0 || h <= 0 || IsIconic(window))
            return;
        const bool resized = buffer.width != w || buffer.height != h;
        buffer.resize(w, h);
        if (resized || observed_revision != session.metrics().view_revision) {
            DcState state(buffer.dc);
            SelectObject(buffer.dc, font);
            const float width = static_cast<float>(w) * 96.0f / static_cast<float>(dpi);
            const float height = static_cast<float>(h) * 96.0f / static_cast<float>(dpi);
            std::vector<ViewPlacement> placements;
            arrange(session.content_view(), 0, 0, width, placements);
            for (auto &p : placements)
                if (p.view == session.content_view())
                    p.bounds = {0, 0, width, height};
            std::map<dex::ObjectId, ViewBounds> desired;
            for (const auto &placement : placements)
                desired.emplace(placement.view, placement.bounds);
            if (desired != layout_bounds) {
                session.place_views(placements);
                layout_bounds = std::move(desired);
            }
            observed_revision = session.metrics().view_revision;
            ++report.layouts;
            InvalidateRect(window, nullptr, FALSE);
        }
    }
    void draw_node(dex::ObjectId id, bool enabled = true) {
        const auto &view = session.views().at(id);
        auto r = rectangle(layout_bounds.at(id));
        DcState state(buffer.dc);
        IntersectClipRect(buffer.dc, r.left, r.top, r.right, r.bottom);
        enabled = enabled && view.enabled;
        if (view.kind == ViewKind::linear_layout) {
            for (auto child : view.children)
                draw_node(child, enabled);
            return;
        }
        SetBkMode(buffer.dc, TRANSPARENT);
        SelectObject(buffer.dc, font);
        if (view.kind == ViewKind::button) {
            SetDCBrushColor(buffer.dc, !enabled       ? RGB(180, 187, 199)
                                       : view.pressed ? RGB(29, 63, 144)
                                                      : RGB(37, 99, 205));
            FillRect(buffer.dc, &r, static_cast<HBRUSH>(GetStockObject(DC_BRUSH)));
            if (view.focused) {
                auto focus = r;
                InflateRect(&focus, -px(3), -px(3));
                SetTextColor(buffer.dc, RGB(255, 255, 255));
                DrawFocusRect(buffer.dc, &focus);
            }
            InflateRect(&r, -px(16), -px(8));
            SetTextColor(buffer.dc, RGB(255, 255, 255));
        } else
            SetTextColor(buffer.dc, enabled ? RGB(24, 36, 52) : RGB(115, 121, 130));
        auto text = wide(view.text);
        DrawTextW(buffer.dc, text.data(), static_cast<int>(text.size()), &r, DT_WORDBREAK | DT_NOPREFIX);
    }
    void render() {
        synchronize();
        if (!buffer.dc || !session.content_view())
            return;
        RECT r{0, 0, buffer.width, buffer.height};
        SetDCBrushColor(buffer.dc, RGB(247, 249, 252));
        FillRect(buffer.dc, &r, static_cast<HBRUSH>(GetStockObject(DC_BRUSH)));
        draw_node(session.content_view());
        GdiFlush();
        ++report.paints;
    }
    void cancel_pointer() {
        if (mouse_down || touch_down) {
            (void)session.pointer(
                {PointerAction::cancel, touch_down ? touch_id : 0, touch_down ? 0x1002u : 0x2002u, 0, 0});
            mouse_down = touch_down = false;
        }
        repeats.fill(0);
    }
    void close() {
        if (!shutting_down) {
            shutting_down = true;
            KillTimer(window, read_timer);
            KillTimer(window, responsiveness_timer);
            report.final_dpi = dpi;
            report.width = static_cast<unsigned>(buffer.width);
            report.height = static_cast<unsigned>(buffer.height);
            for (const auto &[id, view] : session.views()) {
                (void)id;
                if (view.id == 102)
                    report.result_text = view.text;
            }
            session.close();
        }
    }
    void check(std::string name, bool value) { report.checks.push_back({std::move(name), value, {}}); }
    dex::ObjectId fixture_button() const {
        for (const auto &[id, view] : session.views())
            if (view.id == 103)
                return id;
        fail("Fixture did not create its button");
    }
    std::uint32_t probe(std::string_view name) { return session.probe(name); }
    void mouse_click() {
        const auto r = layout_bounds.at(fixture_button());
        const auto packed = MAKELPARAM(px(r.x + r.width / 2), px(r.y + r.height / 2));
        SendMessageW(window, WM_LBUTTONDOWN, MK_LBUTTON, packed);
        SendMessageW(window, WM_LBUTTONUP, 0, packed);
        if (failure)
            std::rethrow_exception(failure);
    }
    void exercise() {
        if (!report.selftest || shutting_down || !session.idle())
            return;
        switch (exercise_stage) {
        case 0:
            check("actual-hwnd-and-resizable-window-style",
                  IsWindow(window) &&
                      (GetWindowLongPtrW(window, GWL_STYLE) & WS_OVERLAPPEDWINDOW) == WS_OVERLAPPEDWINDOW);
            check("per-monitor-v2-awareness",
                  AreDpiAwarenessContextsEqual(GetWindowDpiAwarenessContext(window),
                                               DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2));
            render();
            before_click.assign(buffer.data().begin(), buffer.data().end());
            mouse_click();
            ++exercise_stage;
            break;
        case 1:
            render();
            for (std::size_t i = 0; i < before_click.size(); ++i)
                if ((before_click[i] & 0xffffffu) != (buffer.pixels[i] & 0xffffffu))
                    ++report.changed_pixels;
            before_click.clear();
            check("mouse-messages-reach-dex-motion-event",
                  probe("touches") >= 2 && probe("lastSource") == 0x2002 && probe("lastAction") == 1);
            check("button-result-changes-rendered-pixels",
                  report.changed_pixels > 20 && session.metrics().managed_clicks == 1);
            SendMessageW(window, WM_KEYDOWN, VK_TAB, 1);
            SendMessageW(window, WM_KEYUP, VK_TAB, 1);
            SendMessageW(window, WM_KEYDOWN, VK_RETURN, 1);
            SendMessageW(window, WM_KEYDOWN, VK_RETURN, (LPARAM(1) << 30) | 1);
            ++exercise_stage;
            break;
        case 2:
            check("keyboard-repeat-reaches-dex-without-extra-click",
                  probe("lastKey") == 66 && probe("lastRepeat") == 1 &&
                      session.metrics().managed_clicks == 1);
            SendMessageW(window, WM_KEYUP, VK_RETURN, (LPARAM(1) << 31) | (LPARAM(1) << 30) | 1);
            ++exercise_stage;
            break;
        case 3:
            check("keyboard-release-clicks-focused-view", session.metrics().managed_clicks == 2 &&
                                                              probe("lastAction") == 1 &&
                                                              probe("lastSource") == 0x101);
            initial_width = buffer.width;
            check_win(
                SetWindowPos(window, nullptr, 0, 0, 760, 460, SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE),
                "Resize fixture window");
            synchronize();
            ++exercise_stage;
            break;
        case 4:
            check("real-resize-remeasures-retained-tree", buffer.width != initial_width &&
                                                              report.resizes > 0 &&
                                                              session.state() == Lifecycle::resumed);
            GetWindowRect(window, &suggested);
            SendMessageW(window, WM_DPICHANGED, MAKELONG(144, 144), reinterpret_cast<LPARAM>(&suggested));
            ++exercise_stage;
            break;
        case 5:
            mouse_click();
            ++exercise_stage;
            break;
        case 6: {
            const auto r = layout_bounds.at(fixture_button());
            check("dpi-message-and-scaled-input-reach-dex",
                  dpi == 144 &&
                      std::abs(std::bit_cast<float>(probe("lastX")) - (r.x + r.width / 2)) <= 0.5f &&
                      std::abs(std::bit_cast<float>(probe("lastY")) - (r.y + r.height / 2)) <= 0.5f &&
                      session.metrics().managed_clicks == 3);
            SendMessageW(window, WM_DPICHANGED, MAKELONG(report.initial_dpi, report.initial_dpi),
                         reinterpret_cast<LPARAM>(&suggested));
            SendMessageW(window, WM_SETFOCUS, 0, 0);
            SendMessageW(window, WM_KILLFOCUS, 0, 0);
            SendMessageW(window, WM_ACTIVATE, WA_INACTIVE, 0);
            ++exercise_stage;
            break;
        }
        case 7:
            check("deactivate-message-pauses-activity", session.state() == Lifecycle::paused);
            SendMessageW(window, WM_SIZE, SIZE_MINIMIZED, 0);
            ++exercise_stage;
            break;
        case 8:
            check("minimize-message-stops-activity", session.state() == Lifecycle::stopped);
            SendMessageW(window, WM_SIZE, SIZE_RESTORED, MAKELPARAM(buffer.width, buffer.height));
            ++exercise_stage;
            break;
        case 9:
            check("inactive-restore-restarts-activity", session.state() == Lifecycle::started);
            SendMessageW(window, WM_ACTIVATE, WA_ACTIVE, 0);
            ++exercise_stage;
            break;
        case 10: {
            check("activate-message-resumes-activity", session.state() == Lifecycle::resumed);
            render();
            std::array<wchar_t, 32768> module{};
            const auto count = GetModuleFileNameW(nullptr, module.data(), static_cast<DWORD>(module.size()));
            if (!count || count >= module.size())
                fail("Cannot resolve evidence output directory");
            const auto capture = std::filesystem::path(std::wstring(module.data(), count)).parent_path() /
                                 L"window-capture.png";
            buffer.capture(capture);
            report.capture_path = utf8(capture.wstring());
            exercised = true;
            ++exercise_stage;
            break;
        }
        case 11:
            if (session.dispatch_metrics().read_failures && queued_probe_key) {
                check("temporary-read-failure-preserves-queued-input",
                      session.views().at(fixture_button()).pressed && session.metrics().managed_clicks == 3);
                SendMessageW(window, WM_KEYUP, VK_RETURN, (LPARAM(1) << 31) | (LPARAM(1) << 30) | 1);
                released_probe_key = true;
                ++exercise_stage;
            }
            break;
        case 12:
            selftest_focus = session.views().at(fixture_button()).focused;
            selftest_revision = session.metrics().view_revision;
            selftest_read_floor = session.dispatch_metrics().submitted;
            ++exercise_stage;
            break;
        case 13:
            if (last_read_ticket > selftest_read_floor) {
                const auto metrics = session.dispatch_metrics();
                check("one-second-update-preserves-view-focus",
                      selftest_focus == session.views().at(fixture_button()).focused &&
                          selftest_revision == session.metrics().view_revision);
                check("window-responsive-during-delayed-read",
                      report.responsive_ticks >= 5 && metrics.coalesced_reads >= 1);
                check("automatic-read-recovery-without-input-replay",
                      metrics.read_failures == 1 && metrics.recovered_reads == 1 && released_probe_key &&
                          session.metrics().managed_clicks == 4 && session.snapshot().jni.native_calls == 4);
                ++exercise_stage;
                check_win(PostMessageW(window, WM_CLOSE, 0, 0), "Post selftest close");
            }
            break;
        default:
            break;
        }
    }
    void completed() {
        const auto replies = session.consume();
        for (const auto &reply : replies) {
            if (reply.kind == security::ActivityCommandKind::refresh && !reply.read_unavailable)
                last_read_ticket = reply.ticket;
            const auto key = pending_keys.find(reply.ticket);
            if (key != pending_keys.end()) {
                const auto value = key->second;
                pending_keys.erase(key);
                if (!reply.handled && !shutting_down && window)
                    DefWindowProcW(window, value.message, value.wp, value.lp);
            }
        }
        if (session.publication().exited) {
            const auto &live = session.publication().last_live;
            if (live)
                for (const auto &[id, view] : live->views) {
                    (void)id;
                    if (view.id == 102)
                        report.result_text = view.text;
                }
            check_win(DestroyWindow(window), "DestroyWindow");
            return;
        }
        synchronize();
        exercise();
    }
    LRESULT message(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
        if (shutting_down && msg != WM_DESTROY && msg != WM_NCDESTROY && msg != completion_message &&
            msg != WM_PAINT)
            return DefWindowProcW(hwnd, msg, wp, lp);
        switch (msg) {
        case WM_CREATE:
            set_dpi(GetDpiForWindow(hwnd));
            report.initial_dpi = dpi;
            check_win(SetTimer(hwnd, read_timer, 1000, nullptr) != 0, "SetTimer");
            return 0;
        case WM_GETMINMAXINFO: {
            auto &limits = *reinterpret_cast<MINMAXINFO *>(lp);
            limits.ptMinTrackSize = {px(240), px(220)};
            return 0;
        }
        case WM_SIZE:
            ++report.resizes;
            if (wp == SIZE_MINIMIZED)
                cancel_pointer();
            session.signal(wp == SIZE_MINIMIZED ? WindowSignal::minimize : WindowSignal::restore);
            if (wp != SIZE_MINIMIZED)
                synchronize();
            return 0;
        case WM_SHOWWINDOW:
            if (!report.selftest) {
                if (!wp)
                    cancel_pointer();
                session.signal(wp ? WindowSignal::restore : WindowSignal::minimize);
                synchronize();
            }
            return 0;
        case WM_DPICHANGED: {
            set_dpi(HIWORD(wp));
            set_icons();
            ++report.dpi_changes;
            const auto &r = *reinterpret_cast<const RECT *>(lp);
            check_win(SetWindowPos(hwnd, nullptr, r.left, r.top, r.right - r.left, r.bottom - r.top,
                                   SWP_NOZORDER | SWP_NOACTIVATE),
                      "DPI window size");
            synchronize();
            return 0;
        }
        case WM_ACTIVATE:
            if (LOWORD(wp) == WA_INACTIVE)
                cancel_pointer();
            session.signal(LOWORD(wp) == WA_INACTIVE ? WindowSignal::deactivate : WindowSignal::activate);
            synchronize();
            return 0;
        case WM_SETFOCUS:
            session.signal(WindowSignal::focus_gained);
            return 0;
        case WM_KILLFOCUS:
            cancel_pointer();
            session.signal(WindowSignal::focus_lost);
            synchronize();
            return 0;
        case WM_LBUTTONDOWN:
        case WM_LBUTTONUP:
        case WM_MOUSEMOVE: {
            // Suppress touch-promoted mouse messages; the pointer path already delivered them.
            if ((static_cast<ULONG_PTR>(GetMessageExtraInfo()) & 0xffffff00u) == 0xff515700u)
                return 0;
            if (touch_down || (msg == WM_MOUSEMOVE && !mouse_down))
                return 0;
            if (msg == WM_LBUTTONDOWN) {
                mouse_down = true;
                SetFocus(hwnd);
                SetCapture(hwnd);
            }
            const auto action = msg == WM_LBUTTONDOWN ? PointerAction::down
                                : msg == WM_LBUTTONUP ? PointerAction::up
                                                      : PointerAction::move;
            (void)session.pointer(
                logical_pointer(action, 0, 0x2002, GET_X_LPARAM(lp), GET_Y_LPARAM(lp), dpi));
            if (msg == WM_LBUTTONUP) {
                mouse_down = false;
                if (GetCapture() == hwnd)
                    ReleaseCapture();
            }
            synchronize();
            return 0;
        }
        case WM_POINTERDOWN:
        case WM_POINTERUPDATE:
        case WM_POINTERUP: {
            POINTER_INFO pointer{};
            check_win(GetPointerInfo(GET_POINTERID_WPARAM(wp), &pointer), "GetPointerInfo");
            if (pointer.pointerType != PT_TOUCH || !(pointer.pointerFlags & POINTER_FLAG_PRIMARY))
                return 0;
            if (pointer.pointerFlags & POINTER_FLAG_CANCELED) {
                cancel_pointer();
                synchronize();
                return 0;
            }
            if (msg == WM_POINTERDOWN) {
                touch_id = pointer.pointerId;
                touch_down = true;
                SetFocus(hwnd);
            }
            if (!touch_down || touch_id != pointer.pointerId)
                return 0;
            POINT point = pointer.ptPixelLocation;
            check_win(ScreenToClient(hwnd, &point), "ScreenToClient");
            const auto action = msg == WM_POINTERDOWN ? PointerAction::down
                                : msg == WM_POINTERUP ? PointerAction::up
                                                      : PointerAction::move;
            (void)session.pointer(logical_pointer(action, touch_id, 0x1002, point.x, point.y, dpi));
            if (msg == WM_POINTERUP)
                touch_down = false;
            synchronize();
            return 0;
        }
        case WM_CAPTURECHANGED:
        case WM_POINTERCAPTURECHANGED:
        case WM_CANCELMODE:
            cancel_pointer();
            synchronize();
            return 0;
        case WM_KEYDOWN:
        case WM_KEYUP:
        case WM_SYSKEYDOWN:
        case WM_SYSKEYUP: {
            const bool up = msg == WM_KEYUP || msg == WM_SYSKEYUP;
            const auto vk = static_cast<std::uint32_t>(wp);
            auto normalized = vk;
            if (vk == VK_SHIFT)
                normalized = MapVirtualKeyW((static_cast<UINT>(lp) >> 16) & 0xff, MAPVK_VSC_TO_VK_EX);
            if (vk == VK_CONTROL)
                normalized = (lp & (LPARAM(1) << 24)) ? VK_RCONTROL : VK_LCONTROL;
            if (vk == VK_MENU)
                normalized = (lp & (LPARAM(1) << 24)) ? VK_RMENU : VK_LMENU;
            const auto modifiers = android_modifiers(GetKeyState(VK_SHIFT) < 0, GetKeyState(VK_MENU) < 0,
                                                     GetKeyState(VK_CONTROL) < 0,
                                                     GetKeyState(VK_LWIN) < 0 || GetKeyState(VK_RWIN) < 0);
            std::uint32_t repeat = 0;
            if (vk < repeats.size()) {
                if (up)
                    repeats[vk] = 0;
                else if (lp & (LPARAM(1) << 30))
                    repeats[vk] =
                        std::min(65535u, repeats[vk] + std::max(1u, static_cast<unsigned>(LOWORD(lp))));
                else
                    repeats[vk] = 0;
                repeat = repeats[vk];
            }
            const auto ticket = session.key({up, android_keycode(normalized), modifiers, repeat});
            pending_keys.emplace(ticket, NativeKey{msg, wp, lp});
            return 0; // The completion applies an unhandled native default exactly once.
        }
        case WM_TIMER:
            if (wp == responsiveness_timer && report.selftest) {
                if (exercised && session.read_pending()) {
                    ++report.responsive_ticks;
                    if (!queued_probe_key) {
                        SendMessageW(hwnd, WM_KEYDOWN, VK_RETURN, 1);
                        queued_probe_key = true;
                    }
                }
                return 0;
            }
            if (wp != read_timer || (report.selftest && !exercised))
                return 0;
            // Drain even if a posted notification was delayed by a native modal loop.
            completed();
            if (!window || shutting_down)
                return 0;
            ++report.timer_reads;
            (void)session.refresh(); // Coalesces a pending read; never replays input/writes.
            return 0;
        case completion_message:
            completed();
            return 0;
        case WM_ERASEBKGND:
            return 1;
        case WM_PAINT: {
            PaintScope paint(hwnd);
            render();
            if (buffer.dc && paint.dc)
                check_win(BitBlt(paint.dc, 0, 0, buffer.width, buffer.height, buffer.dc, 0, 0, SRCCOPY),
                          "BitBlt");
            return 0;
        }
        case exercise_message:
            exercise();
            return 0;
        case WM_CLOSE:
            close();
            return 0;
        case WM_DESTROY:
            if (!report.app_user_model_id.empty()) {
                ComPtr<IPropertyStore> properties;
                PROPVARIANT empty{};
                bool cleared = SUCCEEDED(SHGetPropertyStoreForWindow(hwnd, IID_PPV_ARGS(&properties)));
                if (properties)
                    for (const auto &key : window_identity_keys) {
                        const auto status = properties->SetValue(key, empty);
                        cleared = SUCCEEDED(status) && cleared;
                    }
                report.checks.push_back({"window-application-identity-cleared", cleared, {}});
            }
            session.set_notification(nullptr, 0);
            if (!session.publication().exited)
                session.abort();
            shutting_down = true;
            KillTimer(hwnd, read_timer);
            KillTimer(hwnd, responsiveness_timer);
            PostQuitMessage(0);
            return 0;
        case WM_NCDESTROY:
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            window = nullptr;
            report.closed = true;
            return DefWindowProcW(hwnd, msg, wp, lp);
        default:
            return DefWindowProcW(hwnd, msg, wp, lp);
        }
    }

  public:
    ActivityWindow(security::ActivityDispatcher &session, WindowReport &report,
                   const std::shared_ptr<const apk::Artwork> &presentation)
        : session(session), report(report) {
        if (presentation) {
            icon_bytes = apk::icon_file(presentation->bitmap, presentation->renderer_version);
            report.display_name = presentation->label;
            report.icon_sha256 = apk::sha256(icon_bytes);
        }
    }
    ~ActivityWindow() {
        session.set_notification(nullptr, 0);
        if (window) {
            shutting_down = true;
            DestroyWindow(window);
        }
        if (font)
            DeleteObject(font);
        if (large_icon)
            DestroyIcon(large_icon);
        if (small_icon)
            DestroyIcon(small_icon);
        if (registered)
            UnregisterClassW(window_class, instance);
    }
    void run() {
        WNDCLASSEXW wc{};
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = procedure;
        wc.hInstance = instance;
        wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        wc.lpszClassName = window_class;
        registered = RegisterClassExW(&wc);
        check_win(registered != 0, "RegisterClassEx");
        const auto title =
            utf16((report.display_name.empty() ? report.package : report.display_name) + " - Aether");
        const auto hwnd = CreateWindowExW(0, window_class, title.c_str(), WS_OVERLAPPEDWINDOW, CW_USEDEFAULT,
                                          CW_USEDEFAULT, 560, 380, nullptr, nullptr, instance, this);
        if (failure)
            std::rethrow_exception(failure);
        check_win(hwnd != nullptr, "CreateWindowEx");
        report.created = true;
        set_icons();
        if (!report.app_user_model_id.empty()) {
            ComPtr<IPropertyStore> properties;
            check_hr(SHGetPropertyStoreForWindow(hwnd, IID_PPV_ARGS(&properties)),
                     "Window application identity store");
            const auto set = [&](const PROPERTYKEY &key, const std::string &text) {
                PROPVARIANT value{};
                check_hr(InitPropVariantFromString(utf16(text).c_str(), &value),
                         "Window application property value");
                const auto status = properties->SetValue(key, value);
                PropVariantClear(&value);
                check_hr(status, ("Set window application property " + std::to_string(key.pid)).c_str());
            };
            // Windows snapshots these properties when the explicit ID is set.
            // Set all relaunch information before the ID and before showing HWND.
            if (report.relaunch.command.empty()) {
                PROPVARIANT prevent{};
                prevent.vt = VT_BOOL;
                prevent.boolVal = VARIANT_TRUE;
                check_hr(properties->SetValue(PKEY_AppUserModel_PreventPinning, prevent),
                         "Disable unavailable taskbar pinning");
            } else {
                set(PKEY_AppUserModel_RelaunchCommand, report.relaunch.command);
                set(PKEY_AppUserModel_RelaunchDisplayNameResource, report.relaunch.display_name);
                set(PKEY_AppUserModel_RelaunchIconResource, report.relaunch.icon_resource);
            }
            set(PKEY_AppUserModel_ID, report.app_user_model_id);
        }
        session.set_notification(hwnd, completion_message);
        synchronize();
        if (report.selftest) {
            check_win(SetTimer(hwnd, responsiveness_timer, 100, nullptr) != 0, "Set responsiveness timer");
            check_win(PostMessageW(hwnd, exercise_message, 0, 0), "Post selftest");
        } else {
            ShowWindow(hwnd, SW_SHOWNORMAL);
            UpdateWindow(hwnd);
        }
        MSG msg{};
        for (;;) {
            const auto result = GetMessageW(&msg, nullptr, 0, 0);
            if (result == -1)
                fail("GetMessage failed");
            if (!result)
                break;
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        if (failure)
            std::rethrow_exception(failure);
    }
};
} // namespace

namespace {
WindowReport run_window(security::ActivityDispatcher &session, bool selftest, std::string installed_id = {},
                        std::shared_ptr<const apk::Artwork> presentation = {},
                        security::InstalledRelaunch relaunch = {}) {
    // Startup precedes HWND creation; subsequent I/O never blocks the window thread.
    check_win(WaitForSingleObject(session.completion_event(), 30000) == WAIT_OBJECT_0, "Activity startup");
    (void)session.consume();
    WindowReport report;
    report.installed_id = std::move(installed_id);
    report.relaunch = std::move(relaunch);
    if (!report.installed_id.empty())
        report.app_user_model_id = "Aether.App." + report.installed_id;
    report.selftest = selftest;
    report.apk_sha256 = session.snapshot().apk_hash;
    report.package = session.snapshot().package;
    report.activity = session.snapshot().activity;
    report.window_process = GetCurrentProcessId();
    report.worker_process = session.publication().process_id;
    {
        ActivityWindow window(session, report, presentation);
        window.run();
    }
    const auto &state = session.snapshot();
    report.trace = state.trace;
    report.framework = state.framework;
    report.managed = state.managed;
    report.jni = state.jni;
    report.cpu = state.cpu;
    report.worker_exited = session.publication().exited;
    report.worker_commands = session.publication().commands;
    report.broker_calls = session.publication().broker_calls;
    report.broker_audit = session.publication().audit;
    report.durable_audit = session.publication().durable_audit;
    const auto dispatch = session.dispatch_metrics();
    report.io_thread = dispatch.io_thread;
    report.coalesced_reads = dispatch.coalesced_reads;
    report.read_failures = dispatch.read_failures;
    report.recovered_reads = dispatch.recovered_reads;
    report.peak_pending = dispatch.peak_outstanding;
    report.checks.push_back({"worker-io-owned-by-separate-thread",
                             dispatch.io_thread && dispatch.io_thread != GetCurrentThreadId() &&
                                 dispatch.submitted == dispatch.completed,
                             {}});
    report.checks.push_back({"lpac-worker-executed-and-exited",
                             report.worker_process != report.window_process && report.worker_process &&
                                 report.worker_exited && report.worker_commands > 0 &&
                                 report.broker_calls > 0,
                             {}});
    report.checks.push_back({"window-and-activity-closed",
                             report.created && report.closed && session.state() == Lifecycle::destroyed,
                             {}});
    report.checks.push_back({"framework-and-jni-roots-released",
                             report.managed.pinned_references == 0 && report.jni.local_references == 0 &&
                                 report.jni.global_references == 0 && report.jni.string_buffers == 0,
                             {}});
    if (selftest)
        report.checks.push_back({"actual-dex-jni-a64-result",
                                 report.result_text == u"ARM64 result: 42" && report.jni.native_calls == 4 &&
                                     report.jni.managed_callbacks == 4 && report.cpu.compiled_blocks > 0 &&
                                     report.cpu.emitted_bytes > 0 && report.cpu.rx_failures == 0 &&
                                     report.cpu.interpreter_fallbacks == 0,
                                 {}});
    return report;
}
} // namespace
WindowReport run_fixture_window(const std::filesystem::path &path, bool selftest) {
    security::ActivityDispatcher session(path, selftest ? security::ActivityMode::read_recovery_probe
                                                        : security::ActivityMode::normal);
    return run_window(session, selftest);
}
WindowReport run_installed_window(security::InstalledActivity application) {
    const auto id = application.id;
    const auto relaunch = application.relaunch;
    check_win(application.package != nullptr, "Installed artwork package");
    const auto presentation =
        apk::inspect_package(*application.package, {}, {.modern = application.icon_renderer >= 2,
                                  .metadata_preview = application.icon_renderer >= 3},
                             apk::ScanScope::installation)
            .presentation;
    security::ActivityDispatcher session(std::move(application));
    return run_window(session, false, id, presentation, relaunch);
}
bool WindowReport::passed() const {
    return !checks.empty() &&
           std::all_of(checks.begin(), checks.end(), [](const auto &check) { return check.passed; });
}
std::string WindowReport::json() const {
    std::ostringstream out;
    out << "{\"schemaVersion\":1,\"mode\":"
        << json_quote(installed_id.empty() ? "self-authored-fixtures-only" : "installed-isolated-apk")
        << ",\"androidOsStarted\":false,"
           "\"renderer\":\"Win32-GDI\",\"gpuGlesImplemented\":false,\"touchHardwareTested\":false,\"passed\":"
        << (passed() ? "true" : "false") << ",\"selftest\":" << (selftest ? "true" : "false")
        << ",\"windowCreated\":" << (created ? "true" : "false")
        << ",\"windowClosed\":" << (closed ? "true" : "false") << ",\"apkSha256\":" << json_quote(apk_sha256)
        << ",\"package\":" << json_quote(package) << ",\"launchActivity\":" << json_quote(activity)
        << ",\"installedAppId\":" << json_quote(installed_id)
        << ",\"appUserModelId\":" << json_quote(app_user_model_id)
        << ",\"displayName\":" << json_quote(display_name) << ",\"iconSha256\":" << json_quote(icon_sha256)
        << ",\"relaunch\":{\"command\":" << json_quote(relaunch.command)
        << ",\"displayName\":" << json_quote(relaunch.display_name)
        << ",\"iconResource\":" << json_quote(relaunch.icon_resource)
        << ",\"unavailableReason\":" << json_quote(relaunch.unavailable_reason)
        << ",\"preventPinning\":" << (!installed_id.empty() && relaunch.command.empty() ? "true" : "false")
        << '}' << ",\"isolation\":{\"kind\":\"LPAC\",\"windowsCapabilities\":0,\"windowProcessId\":"
        << window_process << ",\"executionProcessId\":" << worker_process
        << ",\"workerExited\":" << (worker_exited ? "true" : "false") << ",\"commands\":" << worker_commands
        << ",\"brokerCalls\":" << broker_calls << ",\"audit\":" << broker_audit
        << ",\"durableAudit\":" << durable_audit << '}' << ",\"dispatch\":{\"ioThreadId\":" << io_thread
        << ",\"coalescedReads\":" << coalesced_reads << ",\"readFailures\":" << read_failures
        << ",\"recoveredReads\":" << recovered_reads << ",\"peakPending\":" << peak_pending
        << ",\"responsiveTicks\":" << responsive_ticks << '}'
        << ",\"resultText\":" << json_quote(narrow(result_text))
        << ",\"managedTrace\":" << json_quote(narrow(trace))
        << ",\"capturePath\":" << json_quote(capture_path) << ",\"window\":{\"messages\":" << messages
        << ",\"paints\":" << paints << ",\"layouts\":" << layouts << ",\"resizes\":" << resizes
        << ",\"dpiChanges\":" << dpi_changes << ",\"timerReads\":" << timer_reads
        << ",\"initialDpi\":" << initial_dpi << ",\"finalDpi\":" << final_dpi << ",\"width\":" << width
        << ",\"height\":" << height << ",\"changedPixels\":" << changed_pixels
        << "},\"framework\":{\"apiCalls\":" << framework.api_calls
        << ",\"managedClicks\":" << framework.managed_clicks
        << ",\"pointerEvents\":" << framework.pointer_events << ",\"keyEvents\":" << framework.key_events
        << ",\"lifecycleCallbacks\":" << framework.lifecycle_callbacks
        << "},\"managed\":{\"instructions\":" << managed.instructions
        << ",\"pinnedReferences\":" << managed.pinned_references
        << "},\"jni\":{\"nativeCalls\":" << jni.native_calls
        << ",\"managedCallbacks\":" << jni.managed_callbacks
        << ",\"localReferences\":" << jni.local_references
        << ",\"globalReferences\":" << jni.global_references << ",\"stringBuffers\":" << jni.string_buffers
        << "},\"cpu\":{\"compiledBlocks\":" << cpu.compiled_blocks
        << ",\"emittedBytes\":" << cpu.emitted_bytes << ",\"rxFailures\":" << cpu.rx_failures
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
std::string WindowReport::text(bool verbose) const {
    std::ostringstream out;
    out << (selftest ? "Window self-test: " : "Window session: ") << (passed() ? "PASS" : "FAIL") << "\n"
        << activity << " -> LPAC worker -> Win32 HWND/GDI -> " << narrow(result_text) << "\n"
        << "Window closed; " << framework.pointer_events << " pointer and " << framework.key_events
        << " key events; " << jni.native_calls << " translated native calls.\n";
    if (verbose || !passed())
        for (const auto &check : checks)
            out << (check.passed ? "  PASS " : "  FAIL ") << check.name << '\n';
    return out.str();
}
} // namespace aether::host
