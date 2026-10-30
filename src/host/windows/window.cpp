#include "aether/host/window.hpp"
#include "aether/apk/artwork.hpp"
#include "aether/apk/package.hpp"
#include "aether/common/text.hpp"
#include "aether/host/windows/unique_handle.hpp"
#include "aether/host/windows/accessibility.hpp"
#include "aether/host/windows/text_layout.hpp"
#include "aether/host/windows/native_ime.hpp"
#include "aether/host/windows/input_pane.hpp"
#include "aether/host/windows/file_drop.hpp"
#include "aether/security/activity_dispatcher.hpp"
#include <Windows.h>
#include <imm.h>
#include <objbase.h>
#include <ole2.h>
#include <shellapi.h>
#include <oleauto.h>
#include <UIAutomation.h>
#include <propsys.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cmath>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <exception>
#include <limits>
#include <mutex>
#include <new>
#include <optional>
#include <propkey.h>
#include <propvarutil.h>
#include <shellapi.h>
#include <shobjidl.h>
#include <sstream>
#include <thread>
#include <utility>
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
constexpr UINT accessibility_action_message = WM_APP + 3;
constexpr UINT input_pane_message = WM_APP + 4;
constexpr UINT file_drop_message = WM_APP + 5;
constexpr UINT_PTR read_timer = 1;
constexpr UINT_PTR responsiveness_timer = 2;
const std::array window_identity_keys{
    PKEY_AppUserModel_ID, PKEY_AppUserModel_RelaunchCommand, PKEY_AppUserModel_RelaunchDisplayNameResource,
    PKEY_AppUserModel_RelaunchIconResource, PKEY_AppUserModel_PreventPinning};
struct CloseComScope {
    HRESULT initialized = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    ~CloseComScope() {
        if (SUCCEEDED(initialized))
            CoUninitialize();
    }
};
bool same_path(std::wstring_view left, std::wstring_view right) noexcept {
    return left.size() == right.size() &&
           CompareStringOrdinal(left.data(), static_cast<int>(left.size()), right.data(),
                                static_cast<int>(right.size()), TRUE) == CSTR_EQUAL;
}
std::wstring close_image_path(const std::filesystem::path &path) {
    auto value = path.native();
    if (value.starts_with(L"\\\\?\\"))
        value.erase(0, 4);
    std::replace(value.begin(), value.end(), L'/', L'\\');
    const std::filesystem::path normalized = std::filesystem::path(value).lexically_normal();
    value = normalized.native();
    // Only absolute DOS executable paths, including their extended-length spelling.
    if (value.size() < 4 || value.size() >= 32768 || value[1] != L':' || value[2] != L'\\' ||
        !((value[0] >= L'A' && value[0] <= L'Z') || (value[0] >= L'a' && value[0] <= L'z')) ||
        value.find(L'\0') != std::wstring::npos || value.find(L':', 2) != std::wstring::npos)
        return {};
    return value;
}
struct InstalledCloseSearch {
    InstalledCloseResult result;
    std::wstring application_id;
    std::array<std::wstring, 2> images;
    std::array<std::wstring, 3> relaunch;
    HWND candidate = nullptr;
    DWORD process_id = 0;
    UniqueHandle process;

    void error(DWORD value) noexcept {
        if (!result.error)
            result.error = value ? value : ERROR_GEN_FAILURE;
    }
    static void increment(std::uint32_t &value) noexcept {
        if (value != std::numeric_limits<std::uint32_t>::max())
            ++value;
    }
    static bool activity_class(HWND window) noexcept {
        std::array<wchar_t, 64> name{};
        return GetClassNameW(window, name.data(), static_cast<int>(name.size())) ==
                   static_cast<int>(std::size(window_class) - 1) &&
               std::wstring_view(name.data()) == window_class;
    }
    bool property(IPropertyStore *store, const PROPERTYKEY &key, std::wstring_view expected) noexcept {
        PROPVARIANT value{};
        const auto status = store->GetValue(key, &value);
        bool equal = false;
        if (SUCCEEDED(status) && value.vt == VT_LPWSTR && value.pwszVal) {
            // Compare only the expected bounded length and its terminating NUL.
            equal = true;
            for (std::size_t i = 0; i <= expected.size(); ++i) {
                const auto wanted = i == expected.size() ? L'\0' : expected[i];
                if (value.pwszVal[i] != wanted) {
                    equal = false;
                    break;
                }
            }
        }
        PropVariantClear(&value);
        if (FAILED(status))
            error(static_cast<DWORD>(status));
        return equal;
    }
    bool identity(HWND window) noexcept {
        ComPtr<IPropertyStore> properties;
        const auto status = SHGetPropertyStoreForWindow(window, IID_PPV_ARGS(&properties));
        if (FAILED(status)) {
            error(static_cast<DWORD>(status));
            return false;
        }
        return property(properties.Get(), PKEY_AppUserModel_ID, application_id) &&
               property(properties.Get(), PKEY_AppUserModel_RelaunchCommand, relaunch[0]) &&
               property(properties.Get(), PKEY_AppUserModel_RelaunchDisplayNameResource, relaunch[1]) &&
               property(properties.Get(), PKEY_AppUserModel_RelaunchIconResource, relaunch[2]);
    }
    bool image(HANDLE handle) {
        std::array<wchar_t, 32768> buffer{};
        DWORD length = static_cast<DWORD>(buffer.size());
        if (!QueryFullProcessImageNameW(handle, 0, buffer.data(), &length)) {
            error(GetLastError());
            return false;
        }
        const auto observed = close_image_path(std::filesystem::path(std::wstring(buffer.data(), length)));
        return !observed.empty() && (same_path(observed, images[0]) || same_path(observed, images[1]));
    }
    bool live(HANDLE handle) noexcept {
        const auto status = WaitForSingleObject(handle, 0);
        if (status == WAIT_TIMEOUT)
            return true;
        error(status == WAIT_FAILED ? GetLastError() : ERROR_PROCESS_ABORTED);
        return false;
    }
    static BOOL CALLBACK enumerate(HWND window, LPARAM context) noexcept {
        auto &search = *reinterpret_cast<InstalledCloseSearch *>(context);
        if (!activity_class(window))
            return TRUE;
        try {
            if (!search.identity(window)) {
                increment(search.result.rejected);
                return TRUE;
            }
            DWORD pid = 0;
            if (!GetWindowThreadProcessId(window, &pid) || !pid) {
                search.error(GetLastError());
                increment(search.result.rejected);
                return TRUE;
            }
            UniqueHandle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid));
            if (!process || !search.image(process.get()) || !search.live(process.get())) {
                if (!process)
                    search.error(GetLastError());
                increment(search.result.rejected);
                return TRUE;
            }
            increment(search.result.matched);
            if (search.result.matched == 1) {
                search.candidate = window;
                search.process_id = pid;
                search.process = std::move(process);
            }
            return TRUE;
        } catch (const std::bad_alloc &) {
            search.error(ERROR_NOT_ENOUGH_MEMORY);
        } catch (...) {
            search.error(ERROR_GEN_FAILURE);
        }
        SetLastError(search.result.error);
        return FALSE;
    }
};
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
class NativeKeyMapper {
  public:
    struct Request {
        std::array<BYTE, 256> keyboard{};
        HKL layout = nullptr;
        UINT virtual_key = 0, scan = 0;
        std::uint32_t meta = 0;
    };
    struct Result {
        KeyCharacterStatus status = KeyCharacterStatus::unsupported;
        std::uint32_t unicode = 0;
    };
  private:
    std::mutex mutex;
    std::condition_variable requested, replied;
    std::optional<std::pair<std::uint64_t, Request>> request;
    Result result;
    std::uint64_t submitted = 0, completed = 0;
    bool stopping = false, disabled = false;
    std::jthread worker;
    static Result translate(const Request &input) {
        if (!input.layout || input.virtual_key > 255 || ImmIsIME(input.layout) ||
            input.virtual_key == VK_PROCESSKEY || input.virtual_key == VK_PACKET ||
            (input.meta & ~(key_lock_meta_mask | 1u))) return {};
        std::array<wchar_t, 16> units{};
        // This private thread never translates messages or attaches input queues.
        // Its pristine dead-buffer state is a construction inference, awaiting
        // runtime acceptance; flag 0x4 prevents these calls from changing it.
        const auto count = ToUnicodeEx(input.virtual_key, input.scan, input.keyboard.data(), units.data(),
                                       static_cast<int>(units.size()), 0x4, input.layout);
        if (!count) return {KeyCharacterStatus::none, 0};
        if (count != 1) return {};
        auto unit = static_cast<std::uint32_t>(units[0]);
        // Android Generic.kcm maps Enter to LF, Tab to TAB, and DEL to no text.
        if (unit == 8 && input.virtual_key == VK_BACK) return {KeyCharacterStatus::none, 0};
        if (unit == 13 && input.virtual_key == VK_RETURN) unit = 10;
        if (unit >= 0xd800 && unit <= 0xdfff) return {};
        if (unit < 0x20 && !(unit == 9 && input.virtual_key == VK_TAB) &&
            !(unit == 10 && input.virtual_key == VK_RETURN)) return {};
        if (unit >= 0x7f && unit <= 0x9f) return {};
        return {KeyCharacterStatus::bmp, unit};
    }
    void run() noexcept {
        try {
            MSG unused{};
            (void)PeekMessageW(&unused, nullptr, WM_USER, WM_USER, PM_NOREMOVE); // Create only this thread's queue.
            std::unique_lock lock(mutex);
            for (;;) {
                requested.wait(lock, [&] { return stopping || request.has_value(); });
                if (stopping) return;
                const auto copied = *request;
                request.reset();
                lock.unlock();
                const auto mapped = translate(copied.second);
                lock.lock();
                if (stopping) return;
                result = mapped;
                completed = copied.first;
                replied.notify_one();
            }
        } catch (...) {
            std::lock_guard lock(mutex);
            disabled = stopping = true;
            replied.notify_one();
        }
    }
  public:
    NativeKeyMapper() : worker([this] { run(); }) {}
    ~NativeKeyMapper() {
        {
            std::lock_guard lock(mutex);
            stopping = true;
            request.reset();
        }
        requested.notify_one();
        if (worker.joinable()) worker.join();
    }
    Result map(const Request &input) {
        std::unique_lock lock(mutex);
        if (disabled || stopping) return {};
        if (submitted == std::numeric_limits<std::uint64_t>::max()) {
            disabled = stopping = true;
            requested.notify_one();
            return {};
        }
        const auto sequence = ++submitted;
        request.emplace(sequence, input);
        requested.notify_one();
        // wait_for releases the only shared lock. No GUI pumping, callbacks or
        // session access can reorder input while this single request completes.
        if (!replied.wait_for(lock, std::chrono::milliseconds(100), [&] { return disabled || completed == sequence; })) {
            disabled = stopping = true;
            request.reset();
            requested.notify_one();
            return {}; // Never retry a timed-out mapping or publish its late reply.
        }
        return disabled ? Result{} : result;
    }
};
class ActivityWindow {
    DpiScope dpi_scope;
    security::ActivityDispatcher &session;
    WindowReport &report;
    std::filesystem::path developer_output_root;
    HWND window = nullptr;
    HINSTANCE instance = GetModuleHandleW(nullptr);
    ATOM registered = 0;
    HICON large_icon = nullptr, small_icon = nullptr;
    std::vector<std::uint8_t> icon_bytes;
    Buffer buffer;
    unsigned dpi = 96;
    RECT viewport{};
    RECT presentation_clip{};
    int presentation_pan = 0;
    std::shared_ptr<InputPane> input_pane;
    bool caret_created = false;
    int caret_height = 0;
    struct SoftClaim {
        android::SoftInputRequest request;
        std::uint64_t ticket = 0, generation = 0, token = 0;
        bool attempted = false;
        std::uint64_t baseline_revision = 0;
    };
    std::optional<SoftClaim> soft_claim;
    std::uint64_t soft_claimed_revision = 0;
    bool consuming_soft_input = false;
    std::unique_ptr<FileDrop> file_drop;
    std::unique_ptr<FileDropReview> drop_review;
    std::unique_ptr<TextDropReview> text_drop_review;
    struct DropProvenance {
        std::uint64_t generation = 0, revision = 0;
        dex::ObjectId content = 0;
        RECT viewport{}, clip{};
        POINT origin{};
        unsigned dpi = 96;
        int pan = 0;
        std::map<dex::ObjectId, std::pair<dex::ObjectId, ViewBounds>> geometry;
    };
    std::optional<DropProvenance> native_drop;
    struct DropTransfer {
        DropProvenance provenance;
        FileDropCapture capture;
        std::optional<PreparedDocumentSource> source;
        std::uint64_t ticket = 0;
        android::DragAction phase = android::DragAction::started;
        bool started = false, location_sent = false, cancel = false;
        bool dropped = false, drop_result = false;
        std::optional<std::u16string> approved_text;
    };
    std::optional<DropTransfer> drop_transfer;
    std::uint64_t next_drop_generation = 0;
    bool processing_drop = false;
    std::int32_t observed_orientation = -2;
    bool synchronizing = false;
    std::optional<DisplayConfiguration> pending_configuration;
    std::uint64_t configuration_ticket = 0;
    std::uint64_t placement_ticket = 0;
    unsigned unsettled_configurations = 0;
    std::uint64_t observed_revision = ~std::uint64_t{0};
    std::exception_ptr failure;
    std::array<std::uint32_t, 256> repeats{};
    bool mouse_down = false, exercised = false, shutting_down = false;
    std::uint32_t touch_id = 0;
    bool touch_down = false;
    bool selftest_focus = false;
    bool power_suspended = false;
    HPOWERNOTIFY power_notification = nullptr;
    std::unique_ptr<WindowAccessibility> accessibility;
    struct PendingInvocation {
        std::uint64_t ticket = 0;
        std::uint64_t publication = 0;
        std::uint64_t view = 0, revision = 0;
        std::shared_ptr<AccessibilityInvocation> origin;
        bool ready = false;
    };
    // Reserve before submitting a guest mutation. Ticket assignment and ready
    // transitions allocate nothing, including when a callback removes its View.
    std::array<PendingInvocation, 256> pending_invocations;
    bool delivering_invocations = false;
    bool terminal_activation_mode = false, consuming_terminal_activations = false;
    std::uint64_t accessibility_state_generation = 0, published_accessibility_state_generation = 0;
    std::uint64_t accessibility_metadata_ticket = 0, failed_metadata_invalidation = 0;
    std::uint64_t requested_metadata_root = 0, requested_metadata_view_revision = 0;
    std::uint64_t requested_metadata_invalidation = 0;
    bool accessibility_metadata_enabled = false, accessibility_metadata_pending = false;
    bool accessibility_metadata_failed = false;
    std::uint64_t completed_metadata_attempt = 0;
    std::shared_ptr<const android::TextEditObservation> streamed_text_edit;
    std::uint64_t streamed_text_edit_floor = 0;
    bool consuming_streamed_text_edit = false;
    bool deferred_text_completion = false;
    std::deque<AccessibilityTextEditEvent> pending_text_edits;
    std::map<std::uint64_t, AccessibilityTextEditGap> pending_text_edit_gaps;
    std::size_t pending_text_edit_units = 0;
    std::uint64_t selftest_revision = 0;
    std::map<dex::ObjectId, ViewBounds> layout_bounds;
    std::map<dex::ObjectId, ViewBounds> natural_layout_bounds;
    std::map<dex::ObjectId, std::shared_ptr<const TextLayout>> text_layouts;
    std::shared_ptr<NativeIme> native_ime;
    struct ImeTicket {
        std::uint64_t ticket, generation, token, conversion_epoch;
        bool metadata_only = false, known_metadata = false;
    };
    std::array<std::optional<ImeTicket>, 16> ime_tickets;
    std::uint64_t ime_generation = 1, ime_next_token = 0, ime_token = 0;
    std::uint64_t ime_conversion_epoch = 0;
    bool ime_conversion_unknown = false;
    dex::ObjectId ime_view = 0;
    bool ime_composing = false, ime_retiring = false;
    unsigned ime_candidate_mask = 1;
    bool ime_position_force = false;
    struct ImeCharacter {
        std::uint64_t generation, ticket;
        LPARAM key;
        HKL layout;
        std::optional<char16_t> high;
    };
    std::deque<ImeCharacter> ime_characters;
    struct NativeKey {
        UINT message;
        WPARAM wp;
        LPARAM lp;
        std::uint64_t generation;
        MSG original{};
        HKL layout = nullptr;
        bool ime = false, allow_character = false;
        dex::ObjectId editor = 0;
        std::array<BYTE, 256> keyboard{};
    };
    std::map<std::uint64_t, NativeKey> pending_keys;
    std::uint64_t native_key_generation = 0;
    NativeKeyMapper key_mapper;
    struct CapturedKey {
        UINT message;
        WPARAM wp;
        LPARAM lp;
        KeyInput input;
        std::uint64_t generation;
        MSG original{};
        HKL layout = nullptr;
        std::array<BYTE, 256> keyboard{};
    };
    std::optional<CapturedKey> captured_key;
    void retire_native_keys() {
        if (native_key_generation == std::numeric_limits<std::uint64_t>::max())
            fail("Native key generation exhausted");
        ++native_key_generation;
        pending_keys.clear();
        captured_key.reset();
        ime_characters.clear();
    }
    static bool equal_rect(const RECT &left, const RECT &right) noexcept {
        return left.left == right.left && left.top == right.top && left.right == right.right && left.bottom == right.bottom;
    }
    void drop_diagnostic(const char *code) noexcept { OutputDebugStringA(code); }
    bool drop_surface_ready(bool foreground) const {
        if (!window || shutting_down || power_suspended || report.installed_id.empty() ||
            !IsWindowVisible(window) || !IsWindowEnabled(window) || IsIconic(window) || configuration_ticket || placement_ticket ||
            mouse_down || touch_down || text_publication_pending() || soft_claim ||
            session.publication().exited || !session.content_view()) return false;
        const auto lifecycle = session.state();
        if (foreground ? lifecycle != Lifecycle::resumed :
            lifecycle != Lifecycle::started && lifecycle != Lifecycle::paused && lifecycle != Lifecycle::resumed) return false;
        if (foreground && (GetFocus() != window || GetForegroundWindow() != window)) return false;
        GUITHREADINFO info{sizeof(GUITHREADINFO)};
        return GetGUIThreadInfo(GetCurrentThreadId(), &info) &&
            !(info.flags & (GUI_INMENUMODE | GUI_POPUPMENUMODE | GUI_SYSTEMMENUMODE));
    }
    bool drop_matches(const DropProvenance &provenance, bool foreground, bool after_started = false) const {
        if (!drop_surface_ready(foreground) || provenance.content != session.content_view() ||
            (!after_started && provenance.revision != session.metrics().view_revision) || provenance.dpi != dpi ||
            !equal_rect(provenance.viewport, viewport) || !equal_rect(provenance.clip, presentation_clip) ||
            provenance.pan != presentation_pan || (!after_started && provenance.geometry.size() != layout_bounds.size())) return false;
        if (after_started) return true; // Actual drag callback output is authoritative.
        for (const auto &[id, geometry] : provenance.geometry) {
            const auto found = session.views().find(id);
            if (found == session.views().end() || found->second.parent != geometry.first ||
                found->second.bounds != geometry.second || !layout_bounds.contains(id)) return false;
        }
        return true;
    }
    std::uint64_t native_drop_begin(POINT screen) {
        if (drop_transfer || drop_review || text_drop_review || !drop_surface_ready(false) || next_drop_generation == UINT64_MAX) return 0;
        POINT point = screen, origin{};
        if (!ScreenToClient(window, &point) || !ClientToScreen(window, &origin) || !in_viewport(point.x, point.y)) return 0;
        const auto generation = ++next_drop_generation;
        native_drop = DropProvenance{generation, session.metrics().view_revision, session.content_view(),
            viewport, presentation_clip, origin, dpi, presentation_pan, {}};
        for (const auto &[id, bounds] : layout_bounds)
            native_drop->geometry.emplace(id, std::pair{session.views().at(id).parent, bounds});
        return generation;
    }
    bool native_drop_over(std::uint64_t generation, POINT screen) const {
        if (!native_drop || native_drop->generation != generation || !drop_matches(*native_drop, false)) return false;
        POINT point = screen, origin{};
        return ScreenToClient(window, &point) && ClientToScreen(window, &origin) &&
            origin.x == native_drop->origin.x && origin.y == native_drop->origin.y && in_viewport(point.x, point.y);
    }
    bool native_drop_accept(FileDropCapture capture) {
        if (!native_drop || drop_transfer || drop_review || text_drop_review ||
            !native_drop_over(capture.generation, capture.dropped)) return false;
        const bool file = capture.kind == DropPayloadKind::file && !capture.file.empty() && !capture.text;
        const bool text = capture.kind == DropPayloadKind::plain_text && capture.file.empty() &&
            capture.text && valid_drop_text(*capture.text);
        if (!file && !text) return false;
        drop_transfer.emplace(DropTransfer{*native_drop, std::move(capture), {}, 0, DragAction::started, false, false, false});
        native_drop.reset();
        // Native COPY means the path transfer is incorporated in this single
        // owned pending review. It never reports a guest handler result.
        if (!PostMessageW(window, file_drop_message, 0, 0)) { drop_transfer.reset(); return false; }
        drop_diagnostic("AETHER_DROP_NATIVE_INTAKE_PENDING_REVIEW");
        return true;
    }
    void cancel_drop_transfer() noexcept {
        native_drop.reset();
        if (drop_review) drop_review->cancel();
        if (text_drop_review) text_drop_review->cancel();
        if (drop_transfer) drop_transfer->cancel = true;
    }
    void open_drop_review() {
        if (!drop_transfer || drop_review || text_drop_review) return;
        if (!drop_matches(drop_transfer->provenance, false)) { drop_transfer.reset(); return; }
        try {
            const auto recipient = utf16(report.display_name.empty() ? report.package : report.display_name) +
                L" [" + utf16(report.installed_id) + L"]";
            if (drop_transfer->capture.kind == DropPayloadKind::plain_text)
                text_drop_review = std::make_unique<TextDropReview>(window, recipient, *drop_transfer->capture.text);
            else drop_review = std::make_unique<FileDropReview>(window, recipient, drop_transfer->capture.file);
        } catch (const std::exception &) {
            drop_transfer.reset();
            drop_diagnostic("AETHER_DROP_REVIEW_UNAVAILABLE");
            if (window && !shutting_down) MessageBoxW(window, L"The dropped content could not be prepared for review.",
                L"Document not shared", MB_OK | MB_ICONWARNING);
        }
    }
    security::ActivityCommand drag_command(DragAction action, POINT screen) const {
        security::ActivityCommand command;
        command.kind = security::ActivityCommandKind::drag;
        command.drag.action = action;
        command.drag.id = drop_transfer->capture.generation;
        command.drag.kind = drop_transfer->capture.kind;
        command.drag.mime_type = command.drag.kind == DropPayloadKind::plain_text ? "text/plain" : drop_transfer->source->info.mime_type;
        if (action != DragAction::ended) {
            const auto &provenance = drop_transfer->provenance;
            const auto logical = logical_pointer(PointerAction::move, 0, 0x2002,
                screen.x - provenance.origin.x - provenance.viewport.left,
                screen.y - provenance.origin.y - provenance.viewport.top + provenance.pan, provenance.dpi);
            command.drag.x = logical.x; command.drag.y = logical.y;
        }
        if (action == DragAction::started) command.expected_view_revision = drop_transfer->provenance.revision;
        if (action == DragAction::drop) {
            if (command.drag.kind == DropPayloadKind::plain_text)
                command.drag.text_info = describe_drop_text(*drop_transfer->approved_text);
            else command.drag.document = drop_transfer->source->info;
        }
        return command;
    }
    void finish_drop_transfer(bool accepted) {
        const bool text = drop_transfer && drop_transfer->capture.kind == DropPayloadKind::plain_text;
        drop_transfer.reset();
        drop_review.reset();
        text_drop_review.reset();
        drop_diagnostic(accepted ? "AETHER_DROP_GUEST_ACCEPTED" : "AETHER_DROP_GUEST_DECLINED_OR_CANCELLED");
        if (!accepted && window && !shutting_down && GetForegroundWindow() == window && GetFocus() == window)
            MessageBoxW(window, text ? L"The text drop was not accepted or could no longer be delivered. Text already received by the app cannot be revoked." :
                L"The drop was not accepted or could no longer be delivered. The original file was not changed.",
                L"Drop not accepted", MB_OK | MB_ICONINFORMATION);
    }
    void progress_drop_transfer() {
        if (terminal_activation_mode || processing_drop || !drop_transfer) return;
        processing_drop = true;
        struct Reset { bool &flag; ~Reset() { flag = false; } } reset{processing_drop};
        if (drop_review && drop_review->closed()) {
            auto approved = drop_review->take();
            drop_review.reset();
            if (!approved) { drop_transfer.reset(); drop_diagnostic("AETHER_DROP_REVIEW_CANCELLED"); return; }
            drop_transfer->source = std::move(approved);
        }
        if (text_drop_review && text_drop_review->closed()) {
            auto approved = text_drop_review->take();
            text_drop_review.reset();
            if (!approved) { drop_transfer.reset(); drop_diagnostic("AETHER_DROP_REVIEW_CANCELLED"); return; }
            drop_transfer->approved_text = std::move(approved);
        }
        const bool approved = drop_transfer->capture.kind == DropPayloadKind::plain_text ?
            drop_transfer->approved_text.has_value() : drop_transfer->source.has_value();
        if (drop_transfer->ticket || !approved) {
            if (drop_transfer->cancel && !drop_transfer->ticket && !drop_transfer->started) {
                drop_transfer.reset(); drop_review.reset(); text_drop_review.reset();
            }
            return;
        }
        // A review owns native focus temporarily. Wait for the genuine restored
        // focus/activation commands to settle, never manufacture a lifecycle ACK.
        if (!drop_transfer->cancel && !drop_transfer->dropped && !drop_surface_ready(true)) return;
        if (!drop_transfer->dropped && !drop_matches(drop_transfer->provenance, true, drop_transfer->started))
            drop_transfer->cancel = true;
        if (drop_transfer->cancel || drop_transfer->dropped) {
            if (!drop_transfer->started || session.publication().exited || !window || shutting_down) {
                finish_drop_transfer(false); return;
            }
            auto command = drag_command(DragAction::ended, {});
            drop_transfer->phase = DragAction::ended;
            drop_transfer->ticket = session.submit(std::move(command));
            return;
        }
        if (!drop_transfer->started) {
            auto command = drag_command(DragAction::started, drop_transfer->capture.entered);
            drop_transfer->phase = DragAction::started;
            drop_transfer->ticket = session.submit(std::move(command));
        } else if (drop_transfer->capture.location && !drop_transfer->location_sent) {
            auto command = drag_command(DragAction::location, *drop_transfer->capture.location);
            drop_transfer->location_sent = true;
            drop_transfer->phase = DragAction::location;
            drop_transfer->ticket = session.submit(std::move(command));
        } else {
            auto command = drag_command(DragAction::drop, drop_transfer->capture.dropped);
            drop_transfer->phase = DragAction::drop;
            if (drop_transfer->capture.kind == DropPayloadKind::plain_text)
                drop_transfer->ticket = session.drop_text(*drop_transfer->approved_text, std::move(command));
            else {
                const auto source = *drop_transfer->source;
                drop_transfer->ticket = session.drop_document(source, std::move(command));
            }
        }
    }
    void complete_drop_transfer(const security::ActivityCompletion &reply) {
        if (!drop_transfer || !drop_transfer->ticket || reply.ticket != drop_transfer->ticket) return;
        drop_transfer->ticket = 0;
        if (drop_transfer->phase == DragAction::drop) {
            drop_transfer->dropped = true;
            drop_transfer->drop_result = reply.handled;
            return; // ENDED must follow the real DROP, carrying its actual result.
        }
        if (drop_transfer->phase == DragAction::ended) {
            finish_drop_transfer(drop_transfer->dropped && drop_transfer->drop_result && reply.handled);
            return;
        }
        if (drop_transfer->phase == DragAction::started) {
            // Even callbacks that all declined STARTED need their false ending.
            drop_transfer->started = true;
            if (!reply.handled) drop_transfer->cancel = true;
        }
        // A LOCATION outside interested targets does not reject a later real
        // DROP at another coordinate. Its actual callback decides the result.
    }
    bool soft_window_ready() const {
        if (!window || shutting_down || power_suspended || !IsWindowVisible(window) || IsIconic(window) ||
            GetFocus() != window || GetForegroundWindow() != window || session.state() != Lifecycle::resumed)
            return false;
        GUITHREADINFO input{sizeof(GUITHREADINFO)};
        return GetGUIThreadInfo(GetCurrentThreadId(), &input) &&
            !(input.flags & (GUI_INMENUMODE | GUI_POPUPMENUMODE | GUI_SYSTEMMENUMODE));
    }
    void clear_system_caret() noexcept {
        if (caret_created) (void)DestroyCaret();
        caret_created = false; caret_height = 0;
    }
    void system_caret(POINT origin, int height) noexcept {
        if (!soft_window_ready() || height <= 0) { clear_system_caret(); return; }
        if (!caret_created || caret_height != height) {
            clear_system_caret();
            caret_created = CreateCaret(window, nullptr, 1, height) != FALSE;
            if (caret_created) caret_height = height;
        }
        // Rendering owns the visible caret. Keep the real system caret hidden
        // while exposing its actual client geometry to Windows input services.
        if (caret_created && !SetCaretPos(origin.x, origin.y)) clear_system_caret();
    }
    bool update_presentation() {
        RECT clip = viewport;
        int pan = 0;
        const auto target = ime_target();
        if (input_pane && soft_window_ready() && !mouse_down && !touch_down) {
            if (const auto screen = input_pane->occlusion(); screen && !IsRectEmpty(&*screen)) {
                POINT corners[2]{{screen->left, screen->top}, {screen->right, screen->bottom}};
                if (ScreenToClient(window, &corners[0]) && ScreenToClient(window, &corners[1])) {
                    const RECT pane{corners[0].x, corners[0].y, corners[1].x, corners[1].y};
                    RECT overlap{};
                    if (IntersectRect(&overlap, &pane, &viewport)) {
                        // A floating pane may cover only part of the width. A
                        // contiguous vertical presentation region keeps every
                        // rendering, input and accessibility coordinate aligned.
                        if (overlap.top - viewport.top >= viewport.bottom - overlap.bottom)
                            clip.bottom = overlap.top;
                        else clip.top = overlap.bottom;
                        const auto found = session.views().find(target);
                        if (found != session.views().end() && layout_bounds.contains(target) &&
                            clip.bottom > clip.top && found->second.selection_end >= 0) {
                            auto bounds = rectangle(layout_bounds.at(target));
                            OffsetRect(&bounds, 0, presentation_pan); // Unpanned logical presentation.
                            const auto content = text_rectangle(found->second.kind, bounds);
                            const auto shape = shaped_text(target, std::max(1L, content.right - content.left));
                            const auto boxes = shape->rectangles(static_cast<std::uint32_t>(found->second.selection_end), 0);
                            if (!boxes.empty()) {
                                const auto top = content.top + static_cast<LONG>(std::floor(boxes.front().top));
                                const auto bottom = content.top + static_cast<LONG>(std::ceil(boxes.front().top + boxes.front().height));
                                if (bottom > clip.bottom) pan = bottom - clip.bottom;
                                if (top - pan < clip.top) pan = top - clip.top;
                            }
                        }
                    }
                }
            }
        }
        if (clip.left != presentation_clip.left || clip.top != presentation_clip.top ||
            clip.right != presentation_clip.right || clip.bottom != presentation_clip.bottom || pan != presentation_pan) {
            if (mouse_down || touch_down) return false; // Preserve the active gesture's transform.
            presentation_clip = clip; presentation_pan = pan;
            InvalidateRect(window, nullptr, FALSE);
            return true;
        }
        return false;
    }
    void submit_soft_input() {
        if (terminal_activation_mode || soft_claim || consuming_soft_input || configuration_ticket || placement_ticket ||
            text_publication_pending() || session.publication().exited || session.snapshot().soft_input_requests.empty()) return;
        const auto request = session.snapshot().soft_input_requests.front();
        if (request.revision <= soft_claimed_revision) return;
        security::ActivityCommand command;
        command.kind = security::ActivityCommandKind::claim_soft_input;
        command.view = request.view; command.soft_input_revision = request.revision;
        if (request.show && soft_window_ready() && !mouse_down && !touch_down && native_ime &&
            ime_target() == request.view && ime_generation != UINT64_MAX) {
            if (ime_token && ime_view != request.view) retire_ime();
            if (!ime_token && ime_next_token != UINT64_MAX) {
                ime_token = ++ime_next_token; ime_view = request.view;
            }
            command.ime_token = ime_token;
            command.expected_view_revision = session.metrics().view_revision;
            command.expected_text = session.views().at(request.view).text;
        }
        // Reserve and consume locally before submitting. Even an unavailable or
        // stale request is consumed by the worker once, without a native retry.
        soft_claim.emplace(SoftClaim{request, 0, ime_generation, command.ime_token, false, command.expected_view_revision});
        soft_claimed_revision = request.revision;
        try { soft_claim->ticket = session.submit(std::move(command)); }
        catch (...) { soft_claim.reset(); throw; }
    }
    bool consume_soft_input() {
        const auto observation = session.take_soft_input_observation();
        if (!observation) return false;
        consuming_soft_input = true;
        struct Reset { bool &flag; ~Reset() { flag = false; } } reset{consuming_soft_input};
        bool accepted = false;
        const auto ticket = session.soft_input_observation_ticket();
        const auto pane = input_pane; // Pin native lifetime across COM reentry.
        const auto &request = observation->request;
        const bool matching = soft_claim && !soft_claim->attempted && soft_claim->ticket == ticket &&
            soft_claim->request.revision == request.revision &&
            soft_claim->request.window_generation == request.window_generation &&
            soft_claim->request.view == request.view && soft_claim->request.show == request.show &&
            soft_claim->generation == ime_generation;
        if (soft_claim) soft_claim->attempted = true; // Before any native operation.
        try {
            if (matching && pane && soft_window_ready() && !configuration_ticket && !placement_ticket &&
                observation->lifecycle == Lifecycle::resumed && observation->window_focused &&
                !mouse_down && !touch_down) {
                if (!request.show) accepted = pane->request_hide() == PaneAttempt::accepted;
                else {
                    const auto &document = observation->document;
                    if (observation->rooted && document.object == request.view && document.kind == ViewKind::edit_text &&
                        document.enabled && document.focused && document.ime_token &&
                        document.ime_token == soft_claim->token && document.ime_token == ime_token &&
                        ime_view == request.view && ime_target() == request.view &&
                        observation->view_revision == soft_claim->baseline_revision &&
                        observation->view_revision == session.metrics().view_revision &&
                        layout_bounds.contains(request.view) &&
                        document.selection_end >= 0) {
                        const auto content = text_rectangle(document.kind, rectangle(layout_bounds.at(request.view)));
                        const TextLayout shape(document.text, static_cast<float>(std::max(1L, content.right - content.left)),
                                               16.0f * static_cast<float>(dpi) / 96.0f);
                        const auto boxes = shape.rectangles(static_cast<std::uint32_t>(document.selection_end), 0);
                        if (!boxes.empty()) {
                            const auto &box = boxes.front();
                            system_caret({content.left + static_cast<LONG>(std::lround(box.left)),
                                          content.top + static_cast<LONG>(std::floor(box.top))},
                                         std::max(1, static_cast<int>(std::ceil(box.height))));
                            if (caret_created && soft_window_ready() && soft_claim->generation == ime_generation)
                                accepted = pane->request_show() == PaneAttempt::accepted;
                            accepted = accepted && window && !shutting_down && soft_window_ready() &&
                                soft_claim && soft_claim->generation == ime_generation &&
                                soft_claim->token == ime_token;
                        }
                    }
                }
            }
        } catch (const std::exception &) { ime_error("AETHER_SOFT_INPUT_UNAVAILABLE"); }
        // Destruction cancels the exchange; it must never revive an aborted UI.
        // WM_CLOSE may have queued close behind this paused exchange. It still
        // needs its false receipt; actual destruction instead aborts the session.
        if (window) session.complete_soft_input_observation(request.revision, accepted && !shutting_down);
        return true;
    }
    void ime_error(const char *code) noexcept {
        report.ime_diagnostic = code;
        if (report.ime_rejected != UINT64_MAX) ++report.ime_rejected;
        OutputDebugStringA(code); // Fixed diagnostic only; no input text is logged.
    }
    void unknown_ime_conversion() noexcept {
        ime_conversion_unknown = true;
        if (ime_conversion_epoch != UINT64_MAX) ++ime_conversion_epoch;
        // Saturation keeps this context unknown until retirement; never wrap
        // an old successful acknowledgement into a current metadata fence.
    }
    std::size_t ime_pending() const noexcept {
        return static_cast<std::size_t>(std::count_if(ime_tickets.begin(), ime_tickets.end(),
                                                     [](const auto &entry) { return entry.has_value(); }));
    }
    void ime_submit(security::ActivityCommand command) {
        const auto slot = std::find_if(ime_tickets.begin(), ime_tickets.end(),
                                      [](const auto &entry) { return !entry; });
        if (slot == ime_tickets.end()) throw std::runtime_error("AETHER_IME_PENDING_LIMIT");
        // Reserve nonallocating tracking BEFORE submitting a non-replayable write.
        slot->emplace(ImeTicket{0, ime_generation, command.ime_token, ime_conversion_epoch,
                                command.ime_kind == ImeEditKind::conversion,
                                command.ime_conversion && command.ime_conversion->available});
        try { (*slot)->ticket = session.submit(std::move(command)); }
        catch (...) { slot->reset(); throw; }
        if (report.ime_submitted != UINT64_MAX) ++report.ime_submitted;
    }
    dex::ObjectId ime_target() const {
        if (!window || shutting_down || power_suspended || GetFocus() != window ||
            GetForegroundWindow() != window || session.state() != Lifecycle::resumed) return 0;
        GUITHREADINFO input{sizeof(GUITHREADINFO)};
        if (!GetGUIThreadInfo(GetCurrentThreadId(), &input) ||
            (input.flags & (GUI_INMENUMODE | GUI_POPUPMENUMODE | GUI_SYSTEMMENUMODE))) return 0;
        for (const auto &[id, node] : session.views()) {
            if (node.kind != ViewKind::edit_text || !node.focused || !node.enabled || !layout_bounds.contains(id)) continue;
            auto ancestor = id;
            for (std::size_t depth = 0; ancestor && depth <= session.views().size(); ++depth) {
                const auto found = session.views().find(ancestor);
                if (found == session.views().end() || !found->second.enabled) break;
                if (ancestor == session.content_view()) return id;
                ancestor = found->second.parent;
            }
        }
        return 0;
    }
    void retire_ime(bool lifecycle = false, bool cancel_native = true) noexcept {
        if (ime_retiring) return;
        ime_retiring = true;
        if (input_pane && (!window || shutting_down || power_suspended || GetFocus() != window ||
            GetForegroundWindow() != window || !IsWindowVisible(window) || IsIconic(window))) input_pane->abandon();
        clear_system_caret();
        if (native_key_generation != UINT64_MAX) ++native_key_generation;
        pending_keys.clear(); captured_key.reset();
        const auto old_token = ime_token;
        const auto old_view = ime_view;
        ime_token = 0; ime_view = 0; ime_composing = false;
        ime_conversion_unknown = false; ime_conversion_epoch = 0;
        ime_characters.clear(); ime_position_force = false;
        if (ime_generation != UINT64_MAX) ++ime_generation;
        try {
            // Submitted commits and their ticket accounting stay in the serial
            // worker FIFO. Only late local completion effects are retired.
            if (!lifecycle && old_token && old_view && !session.publication().exited) {
                security::ActivityCommand command;
                command.kind = security::ActivityCommandKind::ime_edit;
                command.ime_kind = ImeEditKind::finish;
                command.view = old_view; command.ime_token = old_token;
                ime_submit(std::move(command)); // One reserved cleanup slot, never replayed.
            }
        } catch (const std::exception &) { ime_error("AETHER_IME_RETIRE_UNAVAILABLE"); }
        try { if (cancel_native) if (const auto context = native_ime) context->cancel(); }
        catch (const std::exception &) { ime_error("AETHER_IME_NATIVE_CANCEL_UNAVAILABLE"); }
        ime_retiring = false;
    }
    bool ime_send(ImeEditKind kind, std::u16string text = {}, std::int32_t cursor = 0,
                  std::optional<ImeConversionTarget> conversion = {}) {
        if (conversion) unknown_ime_conversion();
        const auto target = ime_target();
        if (!native_ime || !target || ime_retiring) return false;
        if (ime_token && ime_view != target) {
            if (kind == ImeEditKind::conversion) return false;
            retire_ime();
            if (conversion) unknown_ime_conversion(); // The replacement binding owns a fresh fence.
        }
        if (ime_target() != target) return false;
        if (!ime_token && (kind == ImeEditKind::finish || kind == ImeEditKind::cancel ||
                           kind == ImeEditKind::cursor || kind == ImeEditKind::conversion))
            return false;
        const auto required = (ime_token ? 0u : 1u) + (kind == ImeEditKind::begin ? 0u : 1u);
        // Sixteen outstanding writes total, including a reserved retirement slot.
        if (ime_pending() + required > 15 || text.size() > editable_text_limit || ime_generation == UINT64_MAX) {
            ime_error("AETHER_IME_INPUT_LIMIT");
            if (kind != ImeEditKind::conversion) retire_ime();
            return false;
        }
        if (!ime_token) {
            if (configuration_ticket || placement_ticket) { ime_error("AETHER_IME_BASELINE_UNAVAILABLE"); return false; }
            if (ime_next_token == UINT64_MAX) { ime_error("AETHER_IME_TOKEN_LIMIT"); return false; }
            ime_token = ++ime_next_token; ime_view = target;
            security::ActivityCommand begin;
            begin.kind = security::ActivityCommandKind::ime_edit; begin.ime_kind = ImeEditKind::begin;
            begin.view = target; begin.ime_token = ime_token;
            begin.expected_view_revision = session.metrics().view_revision;
            begin.expected_text = session.views().at(target).text;
            ime_submit(std::move(begin));
        }
        if (kind == ImeEditKind::begin) return true;
        security::ActivityCommand command;
        command.kind = security::ActivityCommandKind::ime_edit; command.ime_kind = kind;
        command.view = ime_view; command.ime_token = ime_token;
        command.replacement_text = std::move(text); command.ime_cursor = cursor;
        command.ime_conversion = std::move(conversion);
        ime_submit(std::move(command));
        return true;
    }
    void ime_packet(LPARAM flags) {
        if (ime_retiring || !native_ime) return;
        try {
            const auto captured_target = ime_target();
            if (!captured_target) { ime_error("AETHER_IME_NO_ELIGIBLE_EDITOR"); retire_ime(); return; }
            const auto captured_generation = ime_generation;
            const auto context = native_ime; // Retain through reentrant native notifications/destruction.
            auto packet = context->read(flags);
            if (!window || ime_retiring) return;
            if (native_ime != context || ime_generation != captured_generation || ime_target() != captured_target) {
                ime_error("AETHER_IME_CAPTURE_STALE");
                return;
            }
            if (packet.cancel) {
                retire_native_keys();
                if (ime_token) (void)ime_send(ImeEditKind::cancel);
                retire_ime(true, false); // Already cancelled natively; no echo/replay.
                return;
            }
            if (packet.result || packet.composition) ime_characters.clear();
            std::optional<ImeConversionTarget> conversion;
            if (packet.conversion) {
                conversion = ImeConversionTarget{packet.conversion->available,
                                                  packet.conversion->start, packet.conversion->end};
                if (packet.composition && !packet.result) {
                    conversion->unchanged_prefix = packet.conversion->unchanged_prefix;
                    conversion->previous_composition_sha256 = std::move(packet.conversion->previous_composition_sha256);
                }
                if (!conversion->available) ime_error("AETHER_IME_CONVERSION_UNAVAILABLE");
            }
            if (packet.result) {
                ime_composing = false;
                const auto cursor = static_cast<std::int32_t>(packet.result->size());
                if (!ime_send(ImeEditKind::commit, std::move(*packet.result), cursor)) return;
            }
            if (packet.composition) {
                ime_composing = true;
                const auto cursor = packet.cursor.value_or(static_cast<std::int32_t>(packet.composition->size()));
                if (!ime_send(ImeEditKind::update, std::move(*packet.composition), cursor, std::move(conversion))) retire_ime();
            } else if (packet.cursor && !packet.result && ime_token) {
                if (!ime_send(ImeEditKind::cursor, {}, *packet.cursor)) retire_ime();
            }
            if (!packet.composition && packet.conversion && ime_token) {
                try {
                    if (!ime_send(ImeEditKind::conversion, std::move(packet.conversion->composition), 0, std::move(conversion)))
                        ime_error("AETHER_IME_CONVERSION_UNAVAILABLE");
                } catch (const std::exception &) {
                    // Optional metadata is never grounds to close the actual
                    // editor or retry already submitted text/cursor writes.
                    ime_error("AETHER_IME_CONVERSION_UNAVAILABLE");
                }
            }
            position_ime();
        } catch (const std::exception &) {
            ime_error("AETHER_IME_CAPTURE_UNSUPPORTED"); retire_ime();
        }
    }
    void position_ime(bool force = false) {
        if (terminal_activation_mode) return;
        if (force) ime_position_force = true;
        if (soft_claim) return; // Its actual observed caret belongs to the native attempt.
        clear_system_caret();
        if (text_publication_pending()) return;
        if (!native_ime || !ime_token || ime_retiring || configuration_ticket || placement_ticket) return;
        const auto found = session.views().find(ime_view);
        if (found == session.views().end() || ime_target() != ime_view) { retire_ime(); return; }
        const auto &node = found->second;
        if (node.ime_token != ime_token) {
            const bool pending = std::any_of(ime_tickets.begin(), ime_tickets.end(), [&](const auto &entry) {
                return entry && entry->generation == ime_generation && entry->token == ime_token;
            });
            if (!pending) { ime_error("AETHER_IME_BINDING_RETIRED"); retire_ime(); }
            return;
        }
        if (node.selection_end < 0 || !layout_bounds.contains(ime_view)) return;
        const auto content = text_rectangle(node.kind, rectangle(layout_bounds.at(ime_view)));
        const auto shape = shaped_text(ime_view, std::max(1L, content.right - content.left));
        const auto boxes = shape->rectangles(static_cast<std::uint32_t>(node.selection_end), 0);
        if (boxes.empty()) return;
        RECT clip = presentation_clip;
        auto ancestor = ime_view;
        for (std::size_t depth = 0; ancestor && depth <= session.views().size(); ++depth) {
            const auto current = session.views().find(ancestor);
            if (current == session.views().end() || !current->second.enabled || !layout_bounds.contains(ancestor)) return;
            RECT next{};
            const auto bounds = rectangle(layout_bounds.at(ancestor));
            if (!IntersectRect(&next, &clip, &bounds)) return;
            clip = next;
            if (ancestor == session.content_view()) break;
            ancestor = current->second.parent;
            if (!ancestor || depth == session.views().size()) return;
        }
        RECT clipped{};
        if (!IntersectRect(&clipped, &clip, &content)) return;
        const auto &box = boxes.front();
        const double x = static_cast<double>(content.left) + box.left;
        const double top = static_cast<double>(content.top) + box.top;
        const double bottom = top + box.height;
        if (x < clipped.left || x >= clipped.right || bottom <= clipped.top || top >= clipped.bottom) return;
        const auto caret_x = std::clamp(static_cast<LONG>(std::lround(x)), clipped.left, clipped.right - 1);
        const auto line_top = std::max(clipped.top, static_cast<LONG>(std::floor(top)));
        const auto line_bottom = std::min(clipped.bottom, static_cast<LONG>(std::ceil(bottom)));
        const POINT caret{caret_x, line_bottom};
        const RECT line{clipped.left, line_top, clipped.right, line_bottom};
        if (line.bottom <= line.top) return;
        system_caret({caret_x, line_top}, static_cast<int>(line_bottom - line_top));
        const auto forced = std::exchange(ime_position_force, false);
        try { const auto context = native_ime; context->position(caret, line, ime_candidate_mask, forced); }
        catch (const std::exception &) { ime_error("AETHER_IME_CANDIDATE_UNAVAILABLE"); }
    }
    static LPARAM character_signature(LPARAM value) noexcept {
        return value & ((LPARAM(0xff) << 16) | (LPARAM(1) << 24) | (LPARAM(1) << 29));
    }
    void translate_ime_key(const NativeKey &value, std::uint64_t ticket) {
        if (!native_ime || !value.ime || value.original.hwnd != window ||
            GetKeyboardLayout(GetCurrentThreadId()) != value.layout) return;
        if (value.editor != ime_target()) return;
        std::array<BYTE, 256> keyboard{};
        bool changed = !GetKeyboardState(keyboard.data());
        constexpr std::array modifiers{VK_SHIFT, VK_LSHIFT, VK_RSHIFT, VK_CONTROL, VK_LCONTROL, VK_RCONTROL,
                                       VK_MENU, VK_LMENU, VK_RMENU, VK_LWIN, VK_RWIN};
        constexpr std::array toggles{VK_CAPITAL, VK_NUMLOCK, VK_SCROLL, VK_KANA};
        for (const auto key : modifiers)
            changed = changed || ((keyboard[static_cast<std::size_t>(key)] ^ value.keyboard[static_cast<std::size_t>(key)]) & 0x80);
        for (const auto key : toggles)
            changed = changed || ((keyboard[static_cast<std::size_t>(key)] ^ value.keyboard[static_cast<std::size_t>(key)]) & 0x81);
        if (changed) { ime_error("AETHER_IME_KEYBOARD_STATE_CHANGED"); retire_ime(); return; }
        const bool credit = value.allow_character && !ime_composing && ime_target();
        if (credit) {
            if (ime_characters.size() >= 16) { ime_error("AETHER_IME_CHARACTER_LIMIT"); retire_ime(); return; }
            ime_characters.push_back({value.generation, ticket, value.lp, value.layout, {}});
        }
        // This is the original queued MSG, after its guest decision and under
        // its original still-current HKL. No reconstructed or synthetic key.
        if (!TranslateMessage(&value.original) && credit)
            std::erase_if(ime_characters, [&](const auto &entry) { return entry.ticket == ticket; });
    }
    void discard_character(LPARAM lp) noexcept {
        const auto signature = character_signature(lp);
        std::erase_if(ime_characters, [&](const auto &entry) {
            return entry.generation != native_key_generation || character_signature(entry.key) == signature;
        });
    }
    void ime_character(WPARAM wp, LPARAM lp) {
        if (!native_ime || ime_retiring || ime_composing || !ime_target()) { discard_character(lp); return; }
        const auto layout = GetKeyboardLayout(GetCurrentThreadId());
        std::erase_if(ime_characters, [&](const auto &entry) {
            return entry.generation != native_key_generation || entry.layout != layout;
        });
        const auto signature = character_signature(lp);
        const auto credit = std::find_if(ime_characters.begin(), ime_characters.end(),
            [&](const auto &entry) { return character_signature(entry.key) == signature; });
        if (credit == ime_characters.end()) return; // Uncredited native messages cannot insert text.
        try {
            if (wp > 0xffffu) { ime_error("AETHER_IME_CHARACTER_INVALID"); ime_characters.erase(credit); return; }
            const auto unit = static_cast<char16_t>(wp);
            if (unit >= 0xd800 && unit <= 0xdbff) {
                if (credit->high) { ime_error("AETHER_IME_CHARACTER_INVALID"); ime_characters.erase(credit); }
                else credit->high = unit;
                return;
            }
            std::u16string text;
            if (unit >= 0xdc00 && unit <= 0xdfff) {
                if (!credit->high) { ime_error("AETHER_IME_CHARACTER_INVALID"); ime_characters.erase(credit); return; }
                text.push_back(*credit->high); text.push_back(unit);
            } else {
                if (credit->high || ((unit < 0x20 || unit == 0x7f) && unit != u'\r' && unit != u'\n')) {
                    ime_error("AETHER_IME_CONTROL_UNSUPPORTED"); ime_characters.erase(credit); return;
                }
                text.push_back(unit == u'\r' ? u'\n' : unit); // Plain multiline editor Return.

            }
            const auto repeat = std::max(1u, static_cast<unsigned>(LOWORD(credit->key)));
            ime_characters.erase(credit); // Retire the credit before any guest/native reentry.
            if (repeat > editable_text_limit / text.size()) { ime_error("AETHER_IME_CHARACTER_LIMIT"); retire_ime(); return; }
            const auto value = text;
            text.reserve(value.size() * repeat);
            for (unsigned i = 1; i < repeat; ++i) text += value;
            const auto cursor = static_cast<std::int32_t>(text.size());
            if (!ime_send(ImeEditKind::commit, std::move(text), cursor)) {
                ime_error("AETHER_IME_CHARACTER_REJECTED"); retire_ime();
            }
        } catch (const std::exception &) { ime_error("AETHER_IME_CHARACTER_UNAVAILABLE"); retire_ime(); }
    }
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
    CapturedKey capture_key(const MSG &message) {
        NativeKeyMapper::Request request;
        check_win(GetKeyboardState(request.keyboard.data()) != FALSE, "Capture keyboard state");
        request.layout = GetKeyboardLayout(GetCurrentThreadId());
        check_win(request.layout != nullptr, "Capture keyboard layout");
        check_win(message.wParam <= 255, "Capture keyboard virtual key");
        request.virtual_key = static_cast<UINT>(message.wParam);
        // Always ask for the make-key mapping, including for ACTION_UP getters.
        request.scan = static_cast<UINT>((message.lParam >> 16) & 0xff);
        const auto down = [&](int key) { return (request.keyboard[static_cast<std::size_t>(key)] & 0x80) != 0; };
        request.meta = android_modifiers(down(VK_SHIFT), down(VK_MENU), down(VK_CONTROL), down(VK_LWIN) || down(VK_RWIN)) |
            ((request.keyboard[VK_CAPITAL] & 1) ? 0x100000u : 0u) |
            ((request.keyboard[VK_NUMLOCK] & 1) ? 0x200000u : 0u) |
            ((request.keyboard[VK_SCROLL] & 1) ? 0x400000u : 0u);
        auto normalized = request.virtual_key;
        if (normalized == VK_SHIFT) normalized = MapVirtualKeyExW(request.scan, MAPVK_VSC_TO_VK_EX, request.layout);
        if (normalized == VK_CONTROL) normalized = (message.lParam & (LPARAM(1) << 24)) ? VK_RCONTROL : VK_LCONTROL;
        if (normalized == VK_MENU) normalized = (message.lParam & (LPARAM(1) << 24)) ? VK_RMENU : VK_LMENU;
        const auto mapped = key_mapper.map(request);
        const auto keycode = normalized == VK_RETURN && (message.lParam & (LPARAM(1) << 24))
                                 ? 160u : android_keycode(normalized);
        KeyInput input{message.message == WM_KEYUP || message.message == WM_SYSKEYUP,
                       keycode, request.meta, 0, mapped.status, mapped.unicode};
        check_win(valid_key_input(input), "Captured key mapping exceeds the supported profile");
        return {message.message, message.wParam, message.lParam, input, native_key_generation, message, request.layout, request.keyboard};
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
        text_layouts.clear();
        dpi = value;
        observed_revision = ~std::uint64_t{0};
    }
    int px(float logical) const {
        return static_cast<int>(std::lround(logical * static_cast<float>(dpi) / 96.0f));
    }
    RECT rectangle(const ViewBounds &r) const {
        return {viewport.left + px(r.x), viewport.top + px(r.y) - presentation_pan,
                viewport.left + px(r.x + r.width), viewport.top + px(r.y + r.height) - presentation_pan};
    }
    bool in_viewport(int x, int y) const noexcept {
        return x >= presentation_clip.left && x < presentation_clip.right &&
            y >= presentation_clip.top && y < presentation_clip.bottom;
    }
    PointerInput viewport_pointer(PointerAction action, std::uint32_t id, std::uint32_t source, int x, int y) const {
        return logical_pointer(action, id, source, x - viewport.left, y - viewport.top + presentation_pan, dpi);
    }
    std::shared_ptr<const TextLayout> shaped_text(dex::ObjectId id, int width_pixels) {
        const auto &text = session.views().at(id).text;
        const auto width_value = static_cast<float>(std::max(1, width_pixels));
        const auto font_value = 16.0f * static_cast<float>(dpi) / 96.0f;
        auto &cached = text_layouts[id];
        if (!cached || cached->text() != text || cached->width() != width_value || cached->font_size() != font_value)
            cached = std::make_shared<TextLayout>(text, width_value, font_value);
        return cached;
    }
    RECT text_rectangle(ViewKind kind, RECT bounds) const {
        if (kind == ViewKind::checkbox) {
            bounds.left += px(36);
            InflateRect(&bounds, -px(8), -px(8));
        } else if (kind == ViewKind::button || kind == ViewKind::edit_text) {
            InflateRect(&bounds, -px(16), -px(8));
        }
        return bounds;
    }
    float text_height(dex::ObjectId id, int width_pixels) {
        return std::max(28.0f, shaped_text(id, width_pixels)->height() * 96.0f / static_cast<float>(dpi));
    }
    float arrange(dex::ObjectId id, float x, float y, float width, std::vector<ViewPlacement> &placements) {
        const auto &view = session.views().at(id);
        width = std::max(width, 0.0f);
        if (view.kind == ViewKind::scroll_view) {
            if (id != session.content_view()) fail("Nested ScrollView layout is unsupported");
            const auto height = static_cast<float>(viewport.bottom - viewport.top) * 96.0f / static_cast<float>(dpi);
            if (!view.children.empty()) (void)arrange(view.children.front(), x, y, width, placements);
            placements.push_back({id, {x, y, width, height}});
            return height;
        }
        if (view.kind != ViewKind::linear_layout) {
            const auto physical = text_rectangle(view.kind, rectangle({x, y, width, 0}));
            const auto measured = text_height(id, std::max(1L, physical.right - physical.left));
            const auto height = (view.kind == ViewKind::button || view.kind == ViewKind::checkbox || view.kind == ViewKind::edit_text)
                                    ? std::max(48.0f, measured + 16) : measured;
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
    bool text_publication_pending() const noexcept {
        return consuming_streamed_text_edit || streamed_text_edit ||
            session.publication().text_edit_observation_revision < streamed_text_edit_floor;
    }
    void fill_accessibility_text(AccessibilityNode &node, const android::ViewState &view, std::uint64_t id,
                                 std::optional<std::uint64_t> source_revision = {}) {
        node.value = view.text;
        node.selection_start = view.selection_start;
        node.selection_end = view.selection_end;
        node.composing_start = view.composing_start;
        node.composing_end = view.composing_end;
        node.conversion_start = view.conversion_start;
        node.conversion_end = view.conversion_end;
        node.conversion_available = view.conversion_available;
        if (view.composing_start >= 0 && ime_conversion_unknown && ime_token &&
            ime_view == id && view.ime_token == ime_token) {
            node.conversion_available = false;
            node.conversion_start = node.conversion_end = -1;
        }
        node.composition_event_revision = view.composition_event_revision;
        node.ime_token = view.ime_token;
        node.caret_pos = view.selection_end;
        node.text_event_revision = view.text_event_revision;
        node.selection_event_revision = view.selection_event_revision;
        node.text_mutation_base_revision = view.text_mutation_base_revision;
        for (const auto &mutation : view.text_mutations)
            node.text_mutations.push_back({mutation.revision, mutation.start, mutation.removed,
                mutation.inserted, mutation.before_length});
        node.text_buffer_revision = view.text_buffer_revision;
        node.text_edit_event_revision = view.text_edit_event_revision;
        node.source_view_revision = source_revision ? *source_revision : session.metrics().view_revision;
        node.text_scale = static_cast<float>(dpi) / 96.0f;
        node.text_can_scroll = !source_revision && session.content_view() &&
            session.views().at(session.content_view()).kind == ViewKind::scroll_view &&
            session.views().at(session.content_view()).scroll_range_y > 0;
    }
    void advance_accessibility_text(std::vector<security::ActivityCompletion> &replies) {
        if (!accessibility) return;
        std::vector<AccessibilityTextMutationRecord> mutations;
        std::vector<AccessibilityTextMutationGap> gaps;
        for (auto &reply : replies) {
            for (const auto &record : reply.text_mutations) {
                const auto &mutation = record.mutation;
                mutations.push_back({record.view, record.buffer_revision,
                    {mutation.revision, mutation.start, mutation.removed, mutation.inserted, mutation.before_length}});
            }
            for (const auto &gap : reply.text_mutation_gaps)
                gaps.push_back({gap.view, gap.buffer_revision, gap.through_revision});
            reply.text_mutations.clear();
            reply.text_mutation_gaps.clear();
        }
        // Only the current rooted tree supplies document identities. Detached
        // managed Views cannot keep an old exposed range alive.
        std::vector<AccessibilityNode> documents;
        std::vector<dex::ObjectId> pending;
        if (session.content_view()) pending.push_back(session.content_view());
        while (!pending.empty()) {
            const auto id = pending.back(); pending.pop_back();
            const auto &view = session.views().at(id);
            if (view.kind == ViewKind::edit_text) {
                AccessibilityNode node;
                node.id = id;
                node.kind = AccessibilityKind::edit_text;
                node.name = view.content_description;
                fill_accessibility_text(node, view, id);
                documents.push_back(std::move(node));
            }
            pending.insert(pending.end(), view.children.begin(), view.children.end());
        }
        // Content delivery precedes acknowledgement processing and geometry
        // suspension. The API keeps old shaping unavailable until full publish.
        accessibility->advance_text_documents(std::move(documents), std::move(mutations), std::move(gaps));
    }
    void publish_accessibility() {
        if (!accessibility || !window || terminal_activation_mode)
            return;
        if (text_publication_pending() || placement_ticket || configuration_ticket) {
            accessibility->suspend();
            return;
        }
        const auto publication = accessibility_state_generation;
        const auto nonvirtual_subtree = [&](std::uint64_t root, std::uint64_t proof) {
            std::vector<dex::ObjectId> pending{root};
            std::size_t visited = 0;
            while (!pending.empty()) {
                const auto id = pending.back(); pending.pop_back();
                const auto found = session.views().find(id);
                if (++visited > 256 || found == session.views().end() ||
                    found->second.accessibility_metadata_revision != proof ||
                    found->second.accessibility_node_provider_present) return false;
                pending.insert(pending.end(), found->second.children.begin(), found->second.children.end());
            }
            return proof != 0;
        };
        AccessibilitySnapshot snapshot;
        snapshot.name = u"Android application";
        if (!report.display_name.empty()) {
            const auto name = utf16(report.display_name);
            snapshot.name.assign(name.begin(), name.end());
        }
        RECT client{};
        POINT origin{};
        check_win(GetClientRect(window, &client), "Accessibility client bounds");
        check_win(ClientToScreen(window, &origin), "Accessibility screen origin");
        snapshot.bounds = client;
        OffsetRect(&snapshot.bounds, origin.x, origin.y);
        snapshot.active = !shutting_down && !power_suspended && !configuration_ticket && !placement_ticket &&
                          !mouse_down && !touch_down && IsWindowVisible(window) && !IsIconic(window) &&
                          session.state() == Lifecycle::resumed;
        snapshot.foreground = GetForegroundWindow() == window;
        if (!configuration_ticket && !placement_ticket && session.content_view() && layout_bounds.contains(session.content_view())) {
            snapshot.content = session.content_view();
            const auto append = [&](auto &&self, dex::ObjectId id, bool enabled, RECT clip) -> void {
                const auto &view = session.views().at(id);
                AccessibilityNode node;
                node.id = id;
                node.source_view_revision = session.metrics().view_revision;
                node.parent = view.parent;
                node.children.assign(view.children.begin(), view.children.end());
                node.name = view.kind == ViewKind::edit_text ? view.content_description
                    : view.content_description.empty() ? view.text : view.content_description;
                if (view.kind == ViewKind::edit_text) fill_accessibility_text(node, view, id);
                node.kind = view.kind == ViewKind::checkbox ? AccessibilityKind::checkbox
                          : view.kind == ViewKind::edit_text ? AccessibilityKind::edit_text
                          : view.kind == ViewKind::scroll_view ? AccessibilityKind::scroll_view
                          : view.kind == ViewKind::button ? AccessibilityKind::button
                          : view.kind == ViewKind::linear_layout ? AccessibilityKind::container
                          : AccessibilityKind::text;
                node.enabled = enabled && view.enabled;
                node.toggleable = view.kind == ViewKind::checkbox;
                node.checked = view.checked;
                node.scrollable = view.kind == ViewKind::scroll_view;
                node.scroll_y = view.scroll_y;
                node.scroll_range_y = view.scroll_range_y;
                node.scroll_viewport_y = view.scroll_viewport_y;
                if (view.accessibility_metadata_revision && view.accessibility_collection) {
                    const auto &collection = *view.accessibility_collection;
                    if (!collection.hierarchical && collection.row_count >= 0 && collection.row_count <= 256 &&
                        collection.column_count >= 0 && collection.column_count <= 256 &&
                        collection.selection_mode >= 0 && collection.selection_mode <= 2 &&
                        std::int64_t(collection.row_count) * collection.column_count <= 256)
                        node.grid = AccessibilityGrid{collection.row_count, collection.column_count,
                            collection.item_count, collection.important_item_count,
                            nonvirtual_subtree(id, view.accessibility_metadata_revision),
                            collection.selection_mode, view.accessibility_metadata_revision,
                            view.accessibility_selection_required};
                }
                if (view.accessibility_metadata_revision && view.accessibility_collection_item &&
                    view.accessibility_collection_owner) {
                    const auto &item = *view.accessibility_collection_item;
                    if (item.row_index >= 0 && item.row_index <= 256 && item.column_index >= 0 &&
                        item.column_index <= 256 && item.row_span > 0 && item.row_span <= 256 &&
                        item.column_span > 0 && item.column_span <= 256)
                        node.grid_item = AccessibilityGridItem{view.accessibility_collection_owner,
                            item.row_index, item.column_index, item.row_span, item.column_span,
                            item.selected, view.accessibility_actions};
                }
                node.invokable = view.clickable && !node.toggleable;
                // This is the current framework's actual Tab-order rule, not a
                // claim that all Android clickable views are generally focusable.
                node.focusable = view.focusable;
                node.focused = view.focused && GetFocus() == window;
                const auto bounds = rectangle(layout_bounds.at(id));
                const bool visible = IntersectRect(&node.bounds, &bounds, &clip) != FALSE;
                const auto children_clip = node.bounds;
                node.offscreen = !visible || !IsWindowVisible(window) || IsIconic(window);
                OffsetRect(&node.bounds, origin.x, origin.y);
                if (view.kind == ViewKind::edit_text) {
                    auto content = text_rectangle(view.kind, bounds);
                    node.text_layout = shaped_text(id, std::max(1L, content.right - content.left));
                    node.text_origin = {content.left + origin.x, content.top + origin.y};
                    node.view_origin = {bounds.left + origin.x, bounds.top + origin.y};
                    OffsetRect(&content, origin.x, origin.y);
                    if (!IntersectRect(&node.text_clip, &content, &node.bounds)) SetRectEmpty(&node.text_clip);
                }
                snapshot.nodes.push_back(std::move(node));
                for (const auto child : view.children)
                    self(self, child, enabled && view.enabled, children_clip);
            };
            append(append, session.content_view(), true, presentation_clip);
            // Detached view parents are guest metadata. The exposed content is
            // always the one fragment root child selected by the Activity.
            snapshot.nodes.front().parent = 0;
        }
        publish_text_edits(&snapshot);
        // Any nested state adoption requires its own full publication, even
        // when that batch contains no Invoke ACK. An older outer callback's
        // return cannot mark the newer state as published.
        if (accessibility_state_generation == publication)
            published_accessibility_state_generation = publication;
        deliver_invocations();
    }
    void deliver_invocations() {
        if (delivering_invocations || !accessibility || !window || shutting_down ||
            text_publication_pending() || configuration_ticket || placement_ticket ||
            published_accessibility_state_generation != accessibility_state_generation ||
            accessibility->text_edit_delivery_active()) return;
        delivering_invocations = true;
        struct Reset { bool &flag; ~Reset() { flag = false; } } reset{delivering_invocations};
        while (window && !shutting_down) {
            auto selected = pending_invocations.end();
            for (auto it = pending_invocations.begin(); it != pending_invocations.end(); ++it)
                if (it->origin && it->ready && it->publication <= published_accessibility_state_generation &&
                    (selected == pending_invocations.end() || it->revision < selected->revision)) selected = it;
            if (selected == pending_invocations.end()) break;
            auto origin = std::move(selected->origin);
            *selected = {}; // Consume before COM can pump a nested completion.
            const auto result = accessibility->complete_invoke(origin, true);
            if (FAILED(result)) OutputDebugStringW(L"AETHER_UIA_INVOKED_EVENT_UNAVAILABLE\n");
            // Reentry may suspend publication or destroy the owned HWND. Never
            // deliver the next historical receipt against unsettled new state.
            if (!window || shutting_down || text_publication_pending() || configuration_ticket ||
                placement_ticket || published_accessibility_state_generation != accessibility_state_generation ||
                accessibility->text_edit_delivery_active()) break;
        }
    }
    void publish_text_edits(AccessibilitySnapshot *snapshot = nullptr) {
        if (!accessibility) return;
        std::vector<AccessibilityTextEditEvent> text_edits;
        text_edits.reserve(pending_text_edits.size());
        while (!pending_text_edits.empty()) {
            text_edits.push_back(std::move(pending_text_edits.front()));
            pending_text_edits.pop_front();
        }
        pending_text_edit_units = 0;
        std::sort(text_edits.begin(), text_edits.end(), [](const auto &left, const auto &right) {
            return left.revision < right.revision;
        });
        std::vector<AccessibilityTextEditGap> gaps;
        gaps.reserve(pending_text_edit_gaps.size());
        for (const auto &[id, gap] : pending_text_edit_gaps) {
            (void)id;
            gaps.push_back(gap);
        }
        pending_text_edit_gaps.clear();
        const auto delivered = snapshot
            ? accessibility->publish(std::move(*snapshot), std::move(text_edits), std::move(gaps))
            : accessibility->deliver_text_edits(std::move(text_edits), std::move(gaps));
        const auto add = [](std::uint64_t &value, std::uint64_t increment) {
            value += (std::min)(increment, UINT64_MAX - value);
        };
        add(report.text_edit_attempted, delivered.attempted);
        add(report.text_edit_failed, delivered.failed);
        if (delivered.retired) {
            add(report.text_edit_gaps, delivered.retired);
            report.text_edit_diagnostic = "AETHER_TEXT_EDIT_HISTORY_GAP";
            OutputDebugStringA("AETHER_TEXT_EDIT_HISTORY_GAP");
        }
        if (delivered.failed) {
            report.text_edit_diagnostic = "AETHER_TEXT_EDIT_DELIVERY_FAILED";
            OutputDebugStringA("AETHER_TEXT_EDIT_DELIVERY_FAILED");
        }
        complete_streamed_text_edit();
        if (deferred_text_completion && !accessibility->text_edit_delivery_active()) {
            if (window) check_win(PostMessageW(window, completion_message, 0, 0), "Post deferred text completion");
            deferred_text_completion = false;
        }
    }
    void complete_streamed_text_edit() {
        if (!streamed_text_edit || !window || !accessibility || !accessibility->text_edit_delivery_idle()) return;
        session.complete_text_edit_observation(streamed_text_edit->event.revision);
        streamed_text_edit.reset();
    }
    bool consume_streamed_text_edit() {
        if (consuming_streamed_text_edit || (accessibility && accessibility->text_edit_delivery_active())) {
            deferred_text_completion = true;
            return true;
        }
        if (streamed_text_edit) {
            complete_streamed_text_edit();
            return true; // Never adopt an older full snapshot in this receipt turn.
        }
        const auto observation = session.take_text_edit_observation();
        if (!observation) return false;
        consuming_streamed_text_edit = true;
        struct ResetStream { bool &flag; ~ResetStream() { flag = false; } } reset{consuming_streamed_text_edit};
        streamed_text_edit = observation;
        streamed_text_edit_floor = (std::max)(streamed_text_edit_floor, observation->event.revision);
        if (!accessibility || !window) fail("Text edit observation has no live UI consumer");
        const auto command_ticket = session.text_edit_observation_ticket();
        const auto &observed = observation->document;
        if (observation->event.kind == TextEditEventKind::conversion_target_changed &&
            observed.conversion_available && observed.object == ime_view &&
            ime_token && observed.ime_token == ime_token && ime_conversion_epoch != UINT64_MAX) {
            const auto matching = std::find_if(ime_tickets.begin(), ime_tickets.end(), [&](const auto &entry) {
                return entry && entry->ticket == command_ticket && entry->known_metadata &&
                    entry->generation == ime_generation && entry->token == ime_token &&
                    entry->conversion_epoch == ime_conversion_epoch;
            });
            // This actual metadata event belongs to the newest native capture.
            // An older/idle stream cannot clear a newer native unknown fence.
            if (matching != ime_tickets.end()) ime_conversion_unknown = false;
        }
        AccessibilityNode document;
        document.id = observation->document.object;
        document.kind = AccessibilityKind::edit_text;
        fill_accessibility_text(document, observation->document, document.id, observation->view_revision);
        accessibility->advance_text_document(std::move(document), observation->rooted);
        const auto &event = observation->event;
        const auto kind = event.kind == TextEditEventKind::composition ? AccessibilityTextEditKind::composition
            : event.kind == TextEditEventKind::composition_finalized ? AccessibilityTextEditKind::composition_finalized
            : AccessibilityTextEditKind::conversion_target_changed;
        while (!pending_text_edits.empty() &&
               (pending_text_edits.size() >= 256 || event.text.size() > 65536 - pending_text_edit_units)) {
            const auto retired = std::move(pending_text_edits.front());
            pending_text_edits.pop_front();
            pending_text_edit_units -= retired.text.size();
            text_edit_gap(retired.view, retired.buffer_revision, retired.revision);
        }
        pending_text_edit_units += event.text.size();
        pending_text_edits.push_back({observation->document.object, event.buffer_revision, event.revision, kind, event.text});
        publish_text_edits();
        // A reentrant call may have enqueued behind an existing UIA drain.
        // Its outer publish_text_edits call completes this receipt only after
        // that drain returns; UIA queries themselves never wait on the guest.
        return true;
    }
    void text_edit_gap(std::uint64_t view_id, std::uint64_t buffer_revision, std::uint64_t dropped_revision) {
        if (report.text_edit_gaps != UINT64_MAX) ++report.text_edit_gaps;
        report.text_edit_diagnostic = "AETHER_TEXT_EDIT_HISTORY_GAP";
        OutputDebugStringA("AETHER_TEXT_EDIT_HISTORY_GAP");
        const auto found = session.views().find(view_id);
        if (!dropped_revision || !buffer_revision || found == session.views().end() ||
            found->second.kind != ViewKind::edit_text || found->second.text_buffer_revision < buffer_revision) return;
        auto &gap = pending_text_edit_gaps[view_id]; // At most the current 256 Views.
        gap.view = view_id;
        gap.buffer_revision = found->second.text_buffer_revision;
        gap.dropped_revision = (std::max)(gap.dropped_revision, dropped_revision);
        // A missing later operation does not invalidate earlier captured
        // payloads. Retention evicts exact records at the bounded queue below;
        // this watermark reports loss and prevents replay only after delivery.
    }
    void hold_text_edits(security::ActivityCompletion &reply) {
        // Never attach historical payloads to ordinary current-state snapshots.
        // Consume completion data once; historical delivery does not wait for geometry.
        std::erase_if(pending_text_edit_gaps, [&](const auto &entry) {
            const auto found = session.views().find(entry.first);
            return found == session.views().end() || found->second.kind != ViewKind::edit_text;
        });
        for (const auto &gap : reply.text_edit_gaps)
            text_edit_gap(gap.view, gap.buffer_revision, gap.dropped_revision);
        for (auto &record : reply.text_edit_events) {
            const auto found = session.views().find(record.view);
            if (found == session.views().end() || found->second.kind != ViewKind::edit_text ||
                !record.buffer_revision || found->second.text_buffer_revision < record.buffer_revision) {
                text_edit_gap(record.view, record.buffer_revision, record.event.revision);
                continue;
            }
            while (!pending_text_edits.empty() &&
                   (pending_text_edits.size() >= 256 || record.event.text.size() > 65536 - pending_text_edit_units)) {
                const auto retired = std::move(pending_text_edits.front());
                pending_text_edits.pop_front();
                pending_text_edit_units -= retired.text.size();
                text_edit_gap(retired.view, retired.buffer_revision, retired.revision);
            }
            pending_text_edit_units += record.event.text.size();
            const auto kind = record.event.kind == TextEditEventKind::composition
                ? AccessibilityTextEditKind::composition
                : record.event.kind == TextEditEventKind::composition_finalized
                ? AccessibilityTextEditKind::composition_finalized
                : AccessibilityTextEditKind::conversion_target_changed;
            pending_text_edits.push_back({record.view, record.buffer_revision, record.event.revision,
                kind, std::move(record.event.text)});
        }
    }
    void request_accessibility_metadata(bool explicit_demand = false) {
        if (explicit_demand) {
            accessibility_metadata_enabled = true;
            accessibility_metadata_pending = true;
            accessibility_metadata_failed = false;
        }
        if (!accessibility_metadata_enabled || accessibility_metadata_ticket || terminal_activation_mode ||
            shutting_down || !window || configuration_ticket || placement_ticket || session.read_pending() ||
            mouse_down || touch_down || !session.content_view() || session.publication().exited) return;
        const auto invalidation = session.snapshot().accessibility_invalidation_revision;
        if (accessibility_metadata_failed && invalidation == failed_metadata_invalidation) return;
        const auto source_root = session.content_view();
        const auto source_revision = session.metrics().view_revision;
        const auto prepared_root = session.views().find(source_root);
        if (!accessibility_metadata_pending &&
            session.snapshot().accessibility_metadata_status == android::AccessibilityMetadataStatus::ready &&
            prepared_root != session.views().end() && prepared_root->second.accessibility_metadata_revision &&
            prepared_root->second.accessibility_metadata_revision == session.snapshot().accessibility_metadata_attempt) {
            // Compound selection already prepared this exact current pure-snapshot
            // cache. Adopt its key instead of querying callbacks again on the timer.
            requested_metadata_root = source_root;
            requested_metadata_view_revision = source_revision;
            requested_metadata_invalidation = invalidation;
            return;
        }
        if (!accessibility_metadata_pending && requested_metadata_root == source_root &&
            requested_metadata_view_revision == source_revision && requested_metadata_invalidation == invalidation)
            return; // Unchanged periodic reads never execute guest metadata callbacks.
        security::ActivityCommand command;
        command.kind = security::ActivityCommandKind::prepare_accessibility_metadata;
        command.view = session.content_view();
        command.expected_view_revision = session.metrics().view_revision;
        accessibility_metadata_ticket = session.submit(std::move(command));
        requested_metadata_root = source_root;
        requested_metadata_view_revision = source_revision;
        requested_metadata_invalidation = invalidation;
        accessibility_metadata_pending = false;
    }
    void perform_accessibility_action() {
        if (!accessibility || terminal_activation_mode)
            return;
        const auto requested = accessibility->next_action();
        if (!requested || shutting_down || power_suspended || configuration_ticket || placement_ticket || mouse_down || touch_down ||
            session.state() != Lifecycle::resumed)
            return;
        const auto id = static_cast<dex::ObjectId>(requested->view);
        const auto selected = session.views().find(id);
        const bool scrolling = requested->kind == AccessibilityActionKind::scroll ||
                               requested->kind == AccessibilityActionKind::set_scroll_percent;
        const bool revealing = requested->kind == AccessibilityActionKind::reveal_text_range;
        const bool selecting = requested->kind == AccessibilityActionKind::set_selection;
        const bool collection_selecting = requested->kind == AccessibilityActionKind::collection_selection;
        const bool editing = requested->kind == AccessibilityActionKind::replace_text || selecting || revealing;
        if (selected == session.views().end() ||
            (scrolling ? selected->second.kind != ViewKind::scroll_view || !selected->second.scroll_range_y
             : editing ? selected->second.kind != ViewKind::edit_text
             : collection_selecting ? !selected->second.accessibility_collection_item ||
                 selected->second.accessibility_collection_owner != requested->collection_owner
             : requested->kind == AccessibilityActionKind::focus ? !selected->second.focusable
                       : !selected->second.clickable) ||
            !layout_bounds.contains(id))
            return;
        if (requested->kind == AccessibilityActionKind::toggle && selected->second.kind != ViewKind::checkbox)
            return;
        RECT bounds = presentation_clip;
        auto ancestor = id;
        // Admit only a currently exposed on-screen control, including every
        // ancestor's enabled state. Execution below uses its semantic identity.
        for (std::size_t depth = 0; ancestor && depth <= session.views().size(); ++depth) {
            const auto view = session.views().find(ancestor);
            if (view == session.views().end() || !view->second.enabled || !layout_bounds.contains(ancestor))
                return;
            const auto rectangle_for_view = rectangle(layout_bounds.at(ancestor));
            RECT clipped{};
            if (!revealing) {
                if (!IntersectRect(&clipped, &bounds, &rectangle_for_view)) return;
                bounds = clipped;
            }
            if (ancestor == session.content_view()) break;
            ancestor = view->second.parent;
            if (!ancestor || depth == session.views().size()) return;
        }
        security::ActivityCommand command;
        if (requested->kind == AccessibilityActionKind::focus) {
            // Accessibility may move focus within the foreground app. It never
            // activates another top-level window or steals foreground ownership.
            if (GetForegroundWindow() != window)
                return;
            GUITHREADINFO input_state{sizeof(GUITHREADINFO)};
            if (!GetGUIThreadInfo(GetCurrentThreadId(), &input_state) ||
                (input_state.flags & (GUI_INMENUMODE | GUI_POPUPMENUMODE | GUI_SYSTEMMENUMODE)))
                return; // Preserve an open native menu/confirmation focus owner.
            if (GetFocus() != window) {
                SetFocus(window);
                if (GetFocus() != window)
                    return;
            }
            retire_native_keys(); // Retire delayed old-focus native defaults without replay.
            command.kind = security::ActivityCommandKind::focus;
        } else if (collection_selecting) {
            if (GetForegroundWindow() != window ||
                session.metrics().view_revision != requested->expected_view_revision ||
                !requested->expected_metadata_revision ||
                selected->second.accessibility_metadata_revision != requested->expected_metadata_revision)
                return;
            const auto owner = session.views().find(requested->collection_owner);
            if (owner == session.views().end() ||
                owner->second.accessibility_metadata_revision != requested->expected_metadata_revision ||
                !owner->second.accessibility_collection) return;
            GUITHREADINFO input_state{sizeof(GUITHREADINFO)};
            if (!GetGUIThreadInfo(GetCurrentThreadId(), &input_state) ||
                (input_state.flags & (GUI_INMENUMODE | GUI_POPUPMENUMODE | GUI_SYSTEMMENUMODE))) return;
            command.kind = security::ActivityCommandKind::collection_selection;
            command.collection_owner = requested->collection_owner;
            command.expected_metadata_revision = requested->expected_metadata_revision;
            command.expected_view_revision = requested->expected_view_revision;
            switch (requested->collection_selection_operation) {
            case AccessibilityCollectionSelectionOperation::replace:
                command.collection_selection_operation = android::CollectionSelectionOperation::replace; break;
            case AccessibilityCollectionSelectionOperation::add:
                command.collection_selection_operation = android::CollectionSelectionOperation::add; break;
            case AccessibilityCollectionSelectionOperation::remove:
                command.collection_selection_operation = android::CollectionSelectionOperation::remove; break;
            default: return;
            }
        } else if (revealing) {
            if (selected->second.text != requested->expected_text ||
                session.metrics().view_revision != requested->expected_view_revision) return;
            GUITHREADINFO input_state{sizeof(GUITHREADINFO)};
            if (!GetGUIThreadInfo(GetCurrentThreadId(), &input_state) ||
                (input_state.flags & (GUI_INMENUMODE | GUI_POPUPMENUMODE | GUI_SYSTEMMENUMODE))) return;
            command.kind = security::ActivityCommandKind::reveal_text_range;
            command.expected_text = requested->expected_text;
            command.expected_view_revision = requested->expected_view_revision;
            command.range_top = requested->range_top;
            command.range_bottom = requested->range_bottom;
            command.align_top = requested->align_top;
        } else if (selecting) {
            if (GetForegroundWindow() != window || selected->second.text != requested->expected_text ||
                !requested->expected_buffer_revision ||
                selected->second.text_buffer_revision != requested->expected_buffer_revision ||
                selected->second.text_event_revision != requested->expected_text_revision)
                return;
            GUITHREADINFO input_state{sizeof(GUITHREADINFO)};
            if (!GetGUIThreadInfo(GetCurrentThreadId(), &input_state) ||
                (input_state.flags & (GUI_INMENUMODE | GUI_POPUPMENUMODE | GUI_SYSTEMMENUMODE)))
                return; // Selection must not disturb a native menu or confirmation.
            command.kind = security::ActivityCommandKind::set_selection;
            command.selection_start = requested->caret_offset;
            command.selection_end = requested->selection_end;
            switch (requested->selection_operation) {
            case AccessibilitySelectionOperation::replace: command.selection_operation = android::SelectionOperation::replace; break;
            case AccessibilitySelectionOperation::add: command.selection_operation = android::SelectionOperation::add; break;
            case AccessibilitySelectionOperation::remove: command.selection_operation = android::SelectionOperation::remove; break;
            default: return;
            }
            command.expected_text = requested->expected_text;
            command.expected_buffer_revision = requested->expected_buffer_revision;
            command.expected_text_revision = requested->expected_text_revision;
        } else if (editing) {
            command.kind = security::ActivityCommandKind::replace_text;
            command.replacement_text = requested->replacement_text;
        } else if (requested->kind == AccessibilityActionKind::scroll) {
            command.kind = security::ActivityCommandKind::scroll;
            command.scroll_amount = requested->scroll_amount;
        } else if (requested->kind == AccessibilityActionKind::set_scroll_percent) {
            command.kind = security::ActivityCommandKind::set_scroll_percent;
            command.scroll_percent = requested->scroll_percent;
        } else if (requested->kind == AccessibilityActionKind::toggle) {
            command.kind = security::ActivityCommandKind::toggle;
        } else if (requested->kind == AccessibilityActionKind::invoke) {
            command.kind = security::ActivityCommandKind::invoke;
        } else {
            return; // Unimplemented semantic actions must never become clicks.
        }
        command.view = id;
        // Semantic actions enter the guest's existing click/focus implementations.
        // No coordinate taps, synthetic keys or pointer-state changes occur.
        if (requested->kind == AccessibilityActionKind::invoke) {
            if (!requested->invocation) return;
            const auto slot = std::find_if(pending_invocations.begin(), pending_invocations.end(),
                [](const auto &entry) { return !entry.origin; });
            if (slot == pending_invocations.end()) return; // Bounded admission; never retry a mutation.
            slot->origin = requested->invocation;
            slot->view = requested->view;
            try { slot->ticket = session.submit(std::move(command)); }
            catch (...) { *slot = {}; throw; }
        } else {
            (void)session.submit(std::move(command));
        }
    }
    void synchronize() {
        if (shutting_down || terminal_activation_mode || synchronizing || text_publication_pending())
            return;
        synchronizing = true;
        struct Reset { bool &flag; ~Reset() { flag = false; } } reset{synchronizing};
        RECT client{};
        check_win(GetClientRect(window, &client), "GetClientRect");
        const int w = client.right, h = client.bottom;
        if (w <= 0 || h <= 0 || IsIconic(window))
        {
            publish_accessibility();
            return;
        }
        const bool resized = buffer.width != w || buffer.height != h;
        buffer.resize(w, h);
        const auto orientation = session.snapshot().requested_orientation;
        RECT next{0, 0, w, h};
        if (orientation != -1) {
            // Virtual-display policy: portrait 2:3, landscape 3:2. Windows stays resizable.
            const int numerator = orientation == 1 ? 2 : 3, denominator = orientation == 1 ? 3 : 2;
            int vw = w, vh = h;
            if (std::int64_t(w) * denominator > std::int64_t(h) * numerator)
                vw = (std::max)(1, h * numerator / denominator);
            else
                vh = (std::max)(1, w * denominator / numerator);
            next = {(w - vw) / 2, (h - vh) / 2, (w - vw) / 2 + vw, (h - vh) / 2 + vh};
        }
        const bool moved = next.left != viewport.left || next.top != viewport.top ||
                           next.right != viewport.right || next.bottom != viewport.bottom;
        if (moved || orientation != observed_orientation) {
            if (orientation != observed_orientation)
                retire_native_keys();
            cancel_pointer();
            if (GetCapture() == window)
                ReleaseCapture();
            viewport = next;
            presentation_clip = viewport;
            presentation_pan = 0;
            observed_orientation = orientation;
        }
        // Configuration may recreate the Activity and invalidate every old view ID.
        // Wait for one acknowledged write before sending placements or accepting input.
        const auto logical_size = [&](int pixels) {
            return static_cast<std::uint32_t>((std::max)(1, MulDiv(pixels, 96, static_cast<int>(dpi))));
        };
        DisplayConfiguration display;
        display.screen_width_dp = logical_size(viewport.right - viewport.left);
        display.screen_height_dp = logical_size(viewport.bottom - viewport.top);
        display.smallest_screen_width_dp = (std::min)(display.screen_width_dp, display.screen_height_dp);
        display.density_dpi = static_cast<std::uint32_t>(MulDiv(static_cast<int>(dpi), 160, 96));
        if (configuration_ticket || placement_ticket)
        {
            publish_accessibility();
            return;
        }
        if (display != session.snapshot().configuration) {
            if (++unsettled_configurations > 64)
                fail("Activity display configuration did not settle after 64 transitions");
            cancel_pointer();
            if (GetCapture() == window)
                ReleaseCapture();
            retire_native_keys();
            layout_bounds.clear();
            natural_layout_bounds.clear();
            observed_revision = ~std::uint64_t{0};
            retire_ime(true);
            cancel_drop_transfer();
            pending_configuration = display;
            configuration_ticket = session.configure(display);
            publish_accessibility();
            return;
        }
        unsettled_configurations = 0;
        if (!session.content_view())
        {
            publish_accessibility();
            return;
        }
        if (resized || moved || observed_revision != session.metrics().view_revision) {
            // Defer geometry writes while a live pointer gesture owns its
            // positions. Automatic reads continue without dropping its release.
            if (mouse_down || touch_down) { publish_accessibility(); return; }
            std::erase_if(text_layouts, [&](const auto &entry) { return !session.views().contains(entry.first); });
            const float width = static_cast<float>(viewport.right - viewport.left) * 96.0f / static_cast<float>(dpi);
            const float height = static_cast<float>(viewport.bottom - viewport.top) * 96.0f / static_cast<float>(dpi);
            std::vector<ViewPlacement> placements;
            arrange(session.content_view(), 0, 0, width, placements);
            for (auto &p : placements)
                if (p.view == session.content_view())
                    p.bounds = {0, 0, width, height};
            std::map<dex::ObjectId, ViewBounds> desired;
            for (const auto &placement : placements)
                desired.emplace(placement.view, placement.bounds);
            if (desired != natural_layout_bounds) {
                security::ActivityCommand command;
                command.kind = security::ActivityCommandKind::place;
                command.placements = std::move(placements);
                placement_ticket = session.submit(std::move(command));
                natural_layout_bounds = std::move(desired);
            }
            observed_revision = session.metrics().view_revision;
            ++report.layouts;
            InvalidateRect(window, nullptr, FALSE);
        }
        publish_accessibility();
    }
    void draw_node(dex::ObjectId id, bool enabled = true) {
        const auto &view = session.views().at(id);
        auto r = rectangle(layout_bounds.at(id));
        DcState state(buffer.dc);
        IntersectClipRect(buffer.dc, r.left, r.top, r.right, r.bottom);
        enabled = enabled && view.enabled;
        if (view.kind == ViewKind::linear_layout || view.kind == ViewKind::scroll_view) {
            for (auto child : view.children)
                draw_node(child, enabled);
            return;
        }
        SetBkMode(buffer.dc, TRANSPARENT);
        COLORREF text_background = RGB(247, 249, 252);
        if (view.kind == ViewKind::checkbox) {
            auto box = r;
            const auto size = px(20);
            box.left += px(8);
            box.top += ((r.bottom - r.top) - size) / 2;
            box.right = box.left + size;
            box.bottom = box.top + size;
            check_win(DrawFrameControl(buffer.dc, &box, DFC_BUTTON,
                DFCS_BUTTONCHECK | (view.checked ? DFCS_CHECKED : 0) |
                (!enabled ? DFCS_INACTIVE : 0) | (view.pressed ? DFCS_PUSHED : 0)), "Draw checked control");
            if (view.focused) {
                auto focus = r;
                InflateRect(&focus, -px(3), -px(3));
                DrawFocusRect(buffer.dc, &focus);
            }
            SetTextColor(buffer.dc, enabled ? RGB(24, 36, 52) : RGB(115, 121, 130));
        } else if (view.kind == ViewKind::button) {
            SetDCBrushColor(buffer.dc, !enabled       ? RGB(180, 187, 199)
                                       : view.pressed ? RGB(29, 63, 144)
                                                      : RGB(37, 99, 205));
            FillRect(buffer.dc, &r, static_cast<HBRUSH>(GetStockObject(DC_BRUSH)));
            text_background = GetDCBrushColor(buffer.dc);
            if (view.focused) {
                auto focus = r;
                InflateRect(&focus, -px(3), -px(3));
                SetTextColor(buffer.dc, RGB(255, 255, 255));
                DrawFocusRect(buffer.dc, &focus);
            }
            SetTextColor(buffer.dc, RGB(255, 255, 255));
        } else if (view.kind == ViewKind::edit_text) {
            SetDCBrushColor(buffer.dc, enabled ? RGB(255, 255, 255) : RGB(230, 232, 236));
            FillRect(buffer.dc, &r, static_cast<HBRUSH>(GetStockObject(DC_BRUSH)));
            text_background = GetDCBrushColor(buffer.dc);
            DrawEdge(buffer.dc, &r, EDGE_SUNKEN, BF_RECT);
            if (view.focused) {
                auto focus = r;
                InflateRect(&focus, -px(3), -px(3));
                DrawFocusRect(buffer.dc, &focus);
            }
            SetTextColor(buffer.dc, enabled ? RGB(24, 36, 52) : RGB(115, 121, 130));
        } else
            SetTextColor(buffer.dc, enabled ? RGB(24, 36, 52) : RGB(115, 121, 130));
        r = text_rectangle(view.kind, r);
        RECT inherited_clip{};
        if (GetClipBox(buffer.dc, &inherited_clip) == ERROR)
            fail("Read shaped text clipping region");
        RECT text_clip{};
        if (IntersectRect(&text_clip, &r, &inherited_clip)) {
            const auto layout = shaped_text(id, std::max(1L, r.right - r.left));
            layout->draw(buffer.dc, {r.left, r.top}, text_clip, GetTextColor(buffer.dc), text_background,
                         view.kind == ViewKind::edit_text ? view.selection_start : -1,
                         view.kind == ViewKind::edit_text ? view.selection_end : -1,
                         enabled && view.kind == ViewKind::edit_text && view.focused && GetFocus() == window);
            if (view.kind == ViewKind::edit_text && view.composing_start >= 0 && view.composing_end > view.composing_start) {
                DcState underline(buffer.dc);
                IntersectClipRect(buffer.dc, text_clip.left, text_clip.top, text_clip.right, text_clip.bottom);
                SelectObject(buffer.dc, GetStockObject(DC_PEN));
                SetDCPenColor(buffer.dc, GetTextColor(buffer.dc));
                const auto boxes = layout->rectangles(static_cast<std::uint32_t>(view.composing_start),
                    static_cast<std::uint32_t>(view.composing_end - view.composing_start));
                for (const auto &box : boxes) {
                    if (box.width <= 0 || box.height <= 0) continue;
                    const auto left = std::max(text_clip.left, static_cast<LONG>(std::floor(r.left + box.left)));
                    const auto right = std::min(text_clip.right, static_cast<LONG>(std::ceil(r.left + box.left + box.width)));
                    const auto y = static_cast<LONG>(std::ceil(r.top + box.top + box.height)) - 1;
                    if (right <= left || y < text_clip.top || y >= text_clip.bottom) continue;
                    check_win(MoveToEx(buffer.dc, left, y, nullptr), "Move composition underline");
                    check_win(LineTo(buffer.dc, right, y), "Draw composition underline");
                }
            }
        }
    }
    void render() {
        if (text_publication_pending()) return;
        synchronize();
        if (!buffer.dc)
            return;
        RECT r{0, 0, buffer.width, buffer.height};
        SetDCBrushColor(buffer.dc, RGB(247, 249, 252));
        FillRect(buffer.dc, &r, static_cast<HBRUSH>(GetStockObject(DC_BRUSH)));
        if (!session.content_view() || configuration_ticket || placement_ticket || !layout_bounds.contains(session.content_view()))
            return;
        DcState presentation(buffer.dc);
        IntersectClipRect(buffer.dc, presentation_clip.left, presentation_clip.top,
                          presentation_clip.right, presentation_clip.bottom);
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
        if (!consuming_terminal_activations) (void)consume_terminal_activations();
        if (terminal_activation_mode) {
            if (window) check_win(DestroyWindow(window), "Destroy terminal window");
            return;
        }
        if (!shutting_down) {
            session.retire_clipboard_window();
            cancel_drop_transfer();
            if (file_drop) file_drop->retire();
            if (input_pane) input_pane->abandon();
            retire_ime(true);
            retire_native_keys();
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
            auto parent = developer_output_root;
            if (parent.empty()) {
                std::array<wchar_t, 32768> module{};
                const auto count = GetModuleFileNameW(nullptr, module.data(), static_cast<DWORD>(module.size()));
                if (!count || count >= module.size()) fail("Cannot resolve evidence output directory");
                parent = std::filesystem::path(std::wstring(module.data(), count)).parent_path();
            }
            const auto capture = parent / L"window-capture.png";
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
    void retire_and_deliver_terminal_invocations(std::vector<PendingInvocation> deliveries) {
        terminal_activation_mode = true; // Latch before any native callback can reenter.
        const bool previous_consuming = consuming_terminal_activations;
        consuming_terminal_activations = true;
        struct Restore { bool &flag; bool previous; ~Restore() { flag = previous; } }
            restore{consuming_terminal_activations, previous_consuming};
        if (window) KillTimer(window, read_timer);
        session.retire_clipboard_window();
        std::sort(deliveries.begin(), deliveries.end(), [](const auto &left, const auto &right) {
            return left.revision < right.revision;
        });
        std::uint64_t previous = 0;
        for (const auto &entry : deliveries) {
            if (!entry.revision || entry.revision <= previous) fail("Terminal activation order is invalid");
            previous = entry.revision;
        }
        if (accessibility && window) accessibility->retire_for_terminal();
        for (auto &entry : deliveries) {
            auto origin = std::move(entry.origin); // Consume before native reentry.
            if (!origin || !window || !accessibility) continue; // Explicit lifetime retirement.
            const auto result = accessibility->complete_invoke(origin, true);
            if (FAILED(result)) OutputDebugStringW(L"AETHER_UIA_TERMINAL_INVOKED_EVENT_UNAVAILABLE\n");
        }
    }
    std::vector<PendingInvocation> take_ready_invocations() {
        std::vector<PendingInvocation> ready;
        ready.reserve(android::view_activation_limit);
        for (auto &entry : pending_invocations)
            if (entry.origin && entry.ready) {
                ready.push_back(std::move(entry));
                entry = {};
            }
        return ready;
    }
    bool consume_terminal_activations() {
        if (consuming_terminal_activations) return true;
        if (accessibility && accessibility->text_edit_delivery_active()) return false;
        const auto custody = session.take_terminal_activations();
        if (!custody) return false;
        consuming_terminal_activations = true;
        struct Reset { bool &flag; ~Reset() { flag = false; } } reset{consuming_terminal_activations};
        bool receipt_attempted = false;
        try {
            auto deliveries = take_ready_invocations();
            for (const auto &record : custody->records) {
                std::shared_ptr<AccessibilityInvocation> origin;
                for (auto &entry : pending_invocations)
                    if (entry.origin && !entry.ready && record.ticket && entry.ticket == record.ticket &&
                        entry.view == record.activation.view) {
                        origin = std::move(entry.origin);
                        entry = {};
                        break;
                    }
                if (!origin && accessibility && window)
                    origin = accessibility->capture_invocation(record.activation.view);
                if (!origin) continue; // Never invent a provider for a never-exposed control.
                if (deliveries.size() == android::view_activation_limit)
                    fail("Terminal native activation custody quota exhausted");
                PendingInvocation delivery;
                delivery.origin = std::move(origin);
                delivery.revision = record.activation.revision;
                delivery.view = record.activation.view;
                deliveries.push_back(std::move(delivery));
            }
            pending_invocations = {}; // Unfinished requests are not activation facts.
            retire_and_deliver_terminal_invocations(std::move(deliveries));
            receipt_attempted = true; // Never repeat a receipt after a partial native failure.
            session.complete_terminal_activations(custody->through_revision);
        } catch (...) {
            if (!receipt_attempted) {
                receipt_attempted = true;
                session.complete_terminal_activations(custody->through_revision);
            }
            throw;
        }
        return true; // Sender can now produce its actual exit/error record.
    }
    void completed() {
        if (consuming_terminal_activations) return;
        if (consume_terminal_activations()) return;
        if (consuming_soft_input) return;
        if (consume_streamed_text_edit()) return;
        if (consume_soft_input()) return;
        auto replies = session.consume();
        if (terminal_activation_mode) {
            // Stored terminal failures are surfaced by consume(). A genuine
            // final exit publication must also be allowed to close this HWND.
            if (window && session.publication().exited) check_win(DestroyWindow(window), "Destroy terminal window");
            return;
        }
        if (accessibility_state_generation == UINT64_MAX) fail("Accessibility state identity exhausted");
        ++accessibility_state_generation;
        // Capture every actual activation before a newer publication can retire
        // its exposed identity. ACK success/metrics are no longer event sources.
        // consume() still exposes the latest state, not historical snapshots.
        for (const auto &reply : replies) {
            std::shared_ptr<AccessibilityInvocation> requested_origin;
            std::uint64_t requested_view = 0;
            for (auto &entry : pending_invocations)
                if (entry.origin && !entry.ready && entry.ticket == reply.ticket) {
                    requested_origin = std::move(entry.origin);
                    requested_view = entry.view;
                    entry = {};
                    break;
                }
            for (const auto &activation : reply.view_activations) {
                auto origin = activation.view == requested_view && requested_origin
                    ? std::move(requested_origin)
                    : accessibility ? accessibility->capture_invocation(activation.view) : nullptr;
                if (!origin) continue; // Never introduce a provider for an unexposed guest control.
                const auto slot = std::find_if(pending_invocations.begin(), pending_invocations.end(),
                    [](const auto &entry) { return !entry.origin; });
                if (slot == pending_invocations.end()) fail("Native activation custody quota exhausted");
                slot->origin = std::move(origin);
                slot->ticket = reply.ticket;
                slot->view = activation.view;
                slot->revision = activation.revision;
                slot->publication = accessibility_state_generation;
                slot->ready = true;
            }
        }
        if (!text_publication_pending()) advance_accessibility_text(replies);
        // Hold the entire historical batch before any acknowledgement can
        // enter a native callback. Reentrant publication then sees old records
        // before newer completions, preserving the real global event order.
        for (auto &reply : replies) hold_text_edits(reply);
        for (auto &reply : replies) {
            if (reply.kind == security::ActivityCommandKind::prepare_accessibility_metadata &&
                reply.ticket == accessibility_metadata_ticket) {
                accessibility_metadata_ticket = 0;
                if (reply.accessibility_metadata_attempt <= completed_metadata_attempt ||
                    reply.accessibility_metadata_status == android::AccessibilityMetadataStatus::none ||
                    reply.handled != (reply.accessibility_metadata_status == android::AccessibilityMetadataStatus::ready))
                    fail("Accessibility preparation completion has no matching result witness");
                completed_metadata_attempt = reply.accessibility_metadata_attempt;
                // A stale expected key was rejected before callbacks and may
                // retry on a newly observed key. Actual callback mutation keeps
                // its backoff until an independent demand or invalidation.
                accessibility_metadata_failed =
                    reply.accessibility_metadata_status == android::AccessibilityMetadataStatus::mutated;
                failed_metadata_invalidation = reply.accessibility_invalidation_revision;
            } else if (reply.kind == security::ActivityCommandKind::collection_selection) {
                // A compound action prepares metadata explicitly after each real
                // callback. Its failed round must not rearm itself through this ACK.
                // Rejection before preparation can legitimately retain the old attempt.
                if (reply.accessibility_metadata_attempt > completed_metadata_attempt) {
                    if (reply.accessibility_metadata_status == android::AccessibilityMetadataStatus::none)
                        fail("Collection selection completion has no preparation witness");
                    completed_metadata_attempt = reply.accessibility_metadata_attempt;
                    accessibility_metadata_failed =
                        reply.accessibility_metadata_status == android::AccessibilityMetadataStatus::mutated;
                    failed_metadata_invalidation = reply.accessibility_invalidation_revision;
                }
            } else if (reply.kind != security::ActivityCommandKind::refresh &&
                       reply.kind != security::ActivityCommandKind::place &&
                       reply.kind != security::ActivityCommandKind::prepare_accessibility_metadata) {
                // Independent input/lifecycle work may make a failed callback
                // query stable. Timer/placement/preparation ACKs cannot rearm it.
                if (accessibility_metadata_enabled && accessibility_metadata_failed)
                    accessibility_metadata_pending = true;
                accessibility_metadata_failed = false;
            }
            complete_drop_transfer(reply);
            if (terminal_activation_mode || !window) return;
            if (soft_claim && reply.ticket == soft_claim->ticket) {
                // Native keyboard acceptance is independent from the real
                // InputConnection binding. position_ime validates its final
                // actual token; a declined pane must not finish composition.
                soft_claim.reset();
            }
            if (reply.kind == security::ActivityCommandKind::configure && reply.ticket == configuration_ticket) {
                if (!pending_configuration || session.snapshot().configuration != *pending_configuration)
                    fail("Activity did not acknowledge the selected display configuration");
                configuration_ticket = 0;
                pending_configuration.reset();
                layout_bounds.clear();
                natural_layout_bounds.clear();
                observed_revision = ~std::uint64_t{0};
            }
            if (reply.kind == security::ActivityCommandKind::place && reply.ticket == placement_ticket) {
                placement_ticket = 0;
                observed_revision = ~std::uint64_t{0};
            }
            if (reply.kind == security::ActivityCommandKind::refresh && !reply.read_unavailable)
                last_read_ticket = reply.ticket;
            const auto ime = std::find_if(ime_tickets.begin(), ime_tickets.end(),
                [&](const auto &entry) { return entry && entry->ticket == reply.ticket; });
            if (ime != ime_tickets.end()) {
                const auto value = **ime;
                ime->reset();
                if (report.ime_completed != UINT64_MAX) ++report.ime_completed;
                if (reply.handled && value.known_metadata && value.generation == ime_generation &&
                    value.token == ime_token && value.conversion_epoch == ime_conversion_epoch &&
                    ime_conversion_epoch != UINT64_MAX) {
                    const auto found = session.views().find(ime_view);
                    if (found != session.views().end() && found->second.ime_token == ime_token &&
                        found->second.conversion_available)
                        ime_conversion_unknown = false;
                }
                if (!reply.handled && value.generation == ime_generation && value.token == ime_token) {
                    if (value.metadata_only) {
                        if (value.conversion_epoch == ime_conversion_epoch) unknown_ime_conversion();
                        ime_error("AETHER_IME_CONVERSION_UNAVAILABLE");
                    }
                    else { ime_error("AETHER_IME_GUEST_DECLINED"); retire_ime(); }
                }
            }
            const auto key = pending_keys.find(reply.ticket);
            if (key != pending_keys.end()) {
                const auto value = key->second;
                pending_keys.erase(key);
                if (!reply.handled && value.generation == native_key_generation &&
                    !shutting_down && !terminal_activation_mode && !power_suspended && window &&
                    IsWindowVisible(window) && !IsIconic(window) &&
                    GetForegroundWindow() == window && GetFocus() == window) {
                    if (value.ime) translate_ime_key(value, reply.ticket);
                    if (window && value.generation == native_key_generation)
                        DefWindowProcW(window, value.message, value.wp, value.lp);
                }
            }
        }
        // Bookkeeping precedes external UIA callbacks. Current semantic
        // content is already available even while placement/configuration waits.
        if (!window || terminal_activation_mode) return; // Native callbacks may retire it reentrantly.
        publish_text_edits();
        if (!window || terminal_activation_mode) return; // UIA can pump terminal custody.
        if (session.publication().exited) {
            const auto &live = session.publication().last_live;
            if (live)
                for (const auto &[id, view] : live->views) {
                    (void)id;
                    if (view.id == 102)
                        report.result_text = view.text;
                }
            // Final historical facts do not wait for geometry or a guest state
            // that can no longer arrive. Retire dynamic values before delivery.
            auto deliveries = take_ready_invocations();
            pending_invocations = {};
            retire_and_deliver_terminal_invocations(std::move(deliveries));
            if (!window) return;
            check_win(DestroyWindow(window), "DestroyWindow");
            return;
        }
        if (text_publication_pending()) return;
        if (!configuration_ticket && !placement_ticket) {
            // Published effective rectangles are the worker's authoritative
            // hit-test geometry, including current ScrollView translation.
            layout_bounds.clear();
            std::vector<dex::ObjectId> pending;
            if (session.content_view()) pending.push_back(session.content_view());
            while (!pending.empty()) {
                const auto id = pending.back(); pending.pop_back();
                const auto &node = session.views().at(id);
                layout_bounds.emplace(id, node.bounds);
                pending.insert(pending.end(), node.children.begin(), node.children.end());
            }
        }
        synchronize();
        if (terminal_activation_mode || !window) return;
        if (update_presentation()) publish_accessibility();
        position_ime();
        submit_soft_input();
        progress_drop_transfer();
        if (accessibility_metadata_pending) request_accessibility_metadata();
        exercise();
    }
    LRESULT message(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
        if (terminal_activation_mode && msg != WM_DESTROY && msg != WM_NCDESTROY && msg != WM_CLOSE &&
            msg != completion_message && msg != WM_GETOBJECT && msg != WM_PAINT)
            return DefWindowProcW(hwnd, msg, wp, lp);
        if (shutting_down && msg != WM_DESTROY && msg != WM_NCDESTROY && msg != completion_message &&
            msg != WM_PAINT)
            return DefWindowProcW(hwnd, msg, wp, lp);
        switch (msg) {
        case WM_CREATE:
            session.bind_clipboard_window(hwnd);
            try { native_ime = std::make_shared<NativeIme>(hwnd); }
            catch (const std::exception &) { ime_error("AETHER_IME_CONTEXT_UNAVAILABLE"); }
            try { input_pane = std::make_shared<InputPane>(hwnd, input_pane_message); }
            catch (const std::exception &) { ime_error("AETHER_SOFT_INPUT_UNAVAILABLE"); }
            if (!report.installed_id.empty()) {
                try {
                    file_drop = std::make_unique<FileDrop>(hwnd, FileDropCallbacks{
                        [this](POINT point) { return native_drop_begin(point); },
                        [this](std::uint64_t generation, POINT point) { return native_drop_over(generation, point); },
                        [this](FileDropCapture capture) { return native_drop_accept(std::move(capture)); },
                        [this](std::uint64_t generation) { if (native_drop && native_drop->generation == generation) native_drop.reset(); }});
                } catch (const std::exception &) { drop_diagnostic("AETHER_DROP_NATIVE_UNAVAILABLE"); }
            }
            accessibility = std::make_unique<WindowAccessibility>(hwnd, accessibility_action_message);
            set_dpi(GetDpiForWindow(hwnd));
            report.initial_dpi = dpi;
            power_notification = RegisterSuspendResumeNotification(hwnd, DEVICE_NOTIFY_WINDOW_HANDLE);
            check_win(power_notification != nullptr, "RegisterSuspendResumeNotification");
            check_win(SetTimer(hwnd, read_timer, 1000, nullptr) != 0, "SetTimer");
            return 0;
        case WM_IME_SETCONTEXT:
            if (native_ime) lp &= ~static_cast<LPARAM>(ISC_SHOWUICOMPOSITIONWINDOW);
            return DefWindowProcW(hwnd, msg, wp, lp);
        case WM_IME_STARTCOMPOSITION:
            if (native_ime) native_ime->reset_composition_evidence();
            if (ime_retiring) return 0;
            retire_native_keys();
            ime_composing = true;
            try {
                if (!ime_send(ImeEditKind::begin)) { ime_error("AETHER_IME_BEGIN_UNAVAILABLE"); retire_ime(); }
                else position_ime(true);
            } catch (const std::exception &) { ime_error("AETHER_IME_BEGIN_UNAVAILABLE"); retire_ime(); }
            return 0;
        case WM_IME_COMPOSITION:
            ime_packet(lp);
            return 0;
        case WM_IME_ENDCOMPOSITION:
            if (native_ime) native_ime->reset_composition_evidence();
            if (ime_retiring) return 0;
            retire_native_keys();
            ime_composing = false;
            ime_characters.clear();
            try { if (ime_token && !ime_send(ImeEditKind::finish)) retire_ime(); }
            catch (const std::exception &) { ime_error("AETHER_IME_END_UNAVAILABLE"); retire_ime(); }
            return 0;
        case WM_IME_NOTIFY:
            if (wp == IMN_SETCANDIDATEPOS) return 0; // Native helper already gates synchronous reentry.
            if (wp == IMN_OPENCANDIDATE || wp == IMN_CHANGECANDIDATE || wp == IMN_CLOSECANDIDATE) {
                const auto mask = static_cast<std::uintptr_t>(lp);
                if (mask & ~std::uintptr_t{0x0f}) ime_error("AETHER_IME_CANDIDATE_INDEX_UNSUPPORTED");
                else if (wp == IMN_CLOSECANDIDATE) ime_candidate_mask &= ~static_cast<unsigned>(mask);
                else { ime_candidate_mask = static_cast<unsigned>(mask); position_ime(true); }
            }
            return DefWindowProcW(hwnd, msg, wp, lp);
        case WM_INPUTLANGCHANGE:
            retire_native_keys();
            retire_ime();
            return DefWindowProcW(hwnd, msg, wp, lp);
        case WM_GETOBJECT:
            if (static_cast<LONG>(lp) == UiaRootObjectId && accessibility) {
                if (!terminal_activation_mode) request_accessibility_metadata(true);
                return accessibility->object(wp, lp);
            }
            return DefWindowProcW(hwnd, msg, wp, lp);
        case accessibility_action_message:
            perform_accessibility_action();
            return 0;
        case WM_POWERBROADCAST:
            if (wp == PBT_APMSUSPEND) {
                if (!power_suspended) {
                    power_suspended = true;
                    session.retire_clipboard_window();
                    cancel_drop_transfer();
                    if (input_pane) input_pane->abandon();
                    retire_ime(true);
                    retire_native_keys(); // Never apply a delayed pre-suspend native default after wake.
                    cancel_pointer();
                    if (GetCapture() == hwnd)
                        ReleaseCapture();
                    session.signal(WindowSignal::suspend);
                    publish_accessibility();
                }
                return TRUE; // Queue lifecycle work; never block Windows on the worker pipe.
            }
            if (wp == PBT_APMRESUMEAUTOMATIC)
                return TRUE; // An automatic wake does not establish that a user is present.
            if (wp == PBT_APMRESUMESUSPEND) {
                if (power_suspended) {
                    // Reconcile actual host state before reopening the lifecycle gate.
                    session.signal(IsIconic(hwnd) || !IsWindowVisible(hwnd) ? WindowSignal::minimize : WindowSignal::restore);
                    session.signal(GetForegroundWindow() == hwnd ? WindowSignal::activate : WindowSignal::deactivate);
                    session.signal(GetFocus() == hwnd ? WindowSignal::focus_gained : WindowSignal::focus_lost);
                    session.signal(WindowSignal::resume);
                    power_suspended = false;
                    if (GetForegroundWindow() == hwnd && GetFocus() == hwnd && IsWindowVisible(hwnd) && !IsIconic(hwnd))
                        session.bind_clipboard_window(hwnd);
                    synchronize();
                }
                return TRUE;
            }
            return DefWindowProcW(hwnd, msg, wp, lp);
        case WM_GETMINMAXINFO: {
            auto &limits = *reinterpret_cast<MINMAXINFO *>(lp);
            limits.ptMinTrackSize = {px(240), px(220)};
            return 0;
        }
        case file_drop_message:
            open_drop_review();
            return 0;
        case input_pane_message:
            (void)update_presentation();
            publish_accessibility();
            position_ime(true);
            return 0;
        case WM_MOVE:
            if (input_pane) input_pane->refresh();
            (void)update_presentation();
            publish_accessibility();
            position_ime(true);
            return 0;
        case WM_SIZE:
            ++report.resizes;
            if (wp == SIZE_MINIMIZED) {
                session.retire_clipboard_window();
                cancel_drop_transfer();
                if (input_pane) input_pane->abandon();
                retire_ime(true);
                retire_native_keys(); // Retire native defaults from the previous visible/focused state.
                cancel_pointer();
            }
            session.signal(wp == SIZE_MINIMIZED ? WindowSignal::minimize : WindowSignal::restore);
            if (wp != SIZE_MINIMIZED)
                synchronize();
            return 0;
        case WM_SHOWWINDOW:
            if (!wp) {
                session.retire_clipboard_window();
                cancel_drop_transfer();
                if (input_pane) input_pane->abandon();
                retire_ime(true);
                retire_native_keys();
            }
            if (!report.selftest) {
                if (!wp)
                    cancel_pointer();
                session.signal(wp ? WindowSignal::restore : WindowSignal::minimize);
                synchronize();
            }
            return 0;
        case WM_DPICHANGED: {
            if (input_pane) input_pane->refresh();
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
            if (LOWORD(wp) == WA_INACTIVE) {
                session.retire_clipboard_window();
                if (drop_transfer && (drop_transfer->started || drop_transfer->ticket)) drop_transfer->cancel = true;
                if (input_pane) input_pane->abandon();
                retire_ime(true);
                retire_native_keys();
                cancel_pointer();
            }
            if (LOWORD(wp) != WA_INACTIVE && !power_suspended) session.bind_clipboard_window(hwnd);
            session.signal(LOWORD(wp) == WA_INACTIVE ? WindowSignal::deactivate : WindowSignal::activate);
            synchronize();
            return 0;
        case WM_SETFOCUS:
            if (!power_suspended) session.bind_clipboard_window(hwnd);
            if (input_pane) input_pane->refresh(); // Recover observation for this actual foreground tenure.
            session.signal(WindowSignal::focus_gained);
            (void)update_presentation();
            publish_accessibility();
            return 0;
        case WM_KILLFOCUS:
            session.retire_clipboard_window();
            if (drop_transfer && (drop_transfer->started || drop_transfer->ticket)) drop_transfer->cancel = true;
            if (input_pane) input_pane->abandon();
            retire_ime(true);
            retire_native_keys();
            cancel_pointer();
            session.signal(WindowSignal::focus_lost);
            synchronize();
            return 0;
        case WM_LBUTTONDOWN:
        case WM_LBUTTONUP:
        case WM_MOUSEMOVE: {
            if (power_suspended || configuration_ticket || placement_ticket)
                return 0;
            // Suppress touch-promoted mouse messages; the pointer path already delivered them.
            if ((static_cast<ULONG_PTR>(GetMessageExtraInfo()) & 0xffffff00u) == 0xff515700u)
                return 0;
            if (touch_down || (msg != WM_LBUTTONDOWN && !mouse_down) ||
                (msg == WM_LBUTTONDOWN && !in_viewport(GET_X_LPARAM(lp), GET_Y_LPARAM(lp))))
                return 0;
            if (msg != WM_LBUTTONDOWN && !in_viewport(GET_X_LPARAM(lp), GET_Y_LPARAM(lp))) {
                cancel_pointer();
                if (GetCapture() == hwnd)
                    ReleaseCapture();
                synchronize();
                return 0;
            }
            if (msg == WM_LBUTTONDOWN) {
                retire_ime();
                retire_native_keys();
                mouse_down = true;
                SetFocus(hwnd);
                SetCapture(hwnd);
            }
            const auto action = msg == WM_LBUTTONDOWN ? PointerAction::down
                                : msg == WM_LBUTTONUP ? PointerAction::up
                                                      : PointerAction::move;
            (void)session.pointer(
                viewport_pointer(action, 0, 0x2002, GET_X_LPARAM(lp), GET_Y_LPARAM(lp)));
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
            if (power_suspended || configuration_ticket || placement_ticket)
                return 0;
            POINTER_INFO pointer{};
            check_win(GetPointerInfo(GET_POINTERID_WPARAM(wp), &pointer), "GetPointerInfo");
            if (pointer.pointerType != PT_TOUCH || !(pointer.pointerFlags & POINTER_FLAG_PRIMARY))
                return 0;
            if (pointer.pointerFlags & POINTER_FLAG_CANCELED) {
                cancel_pointer();
                synchronize();
                return 0;
            }
            POINT point = pointer.ptPixelLocation;
            check_win(ScreenToClient(hwnd, &point), "ScreenToClient");
            if (msg == WM_POINTERDOWN && !in_viewport(point.x, point.y))
                return 0;
            if (msg == WM_POINTERDOWN) {
                retire_ime();
                retire_native_keys();
                touch_id = pointer.pointerId;
                touch_down = true;
                SetFocus(hwnd);
            }
            if (!touch_down || touch_id != pointer.pointerId)
                return 0;
            if (!in_viewport(point.x, point.y)) {
                cancel_pointer();
                synchronize();
                return 0;
            }
            const auto action = msg == WM_POINTERDOWN ? PointerAction::down
                                : msg == WM_POINTERUP ? PointerAction::up
                                                      : PointerAction::move;
            (void)session.pointer(viewport_pointer(action, touch_id, 0x1002, point.x, point.y));
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
            const auto queued = std::exchange(captured_key, std::nullopt);
            const bool up = msg == WM_KEYUP || msg == WM_SYSKEYUP;
            // A key held before placement still receives its release; only
            // new key-down actions wait for authoritative geometry.
            if (power_suspended || configuration_ticket || (placement_ticket && !up))
                return 0;
            // Focus loss cancels guest input without pausing a still-active
            // Activity. A queued key-down must not edit that unfocused app.
            // Keep releases flowing so a previously delivered down can retire.
            const bool native_eligible = !shutting_down && IsWindowVisible(hwnd) && !IsIconic(hwnd) &&
                                         GetForegroundWindow() == hwnd && GetFocus() == hwnd;
            if (!up && !native_eligible)
                return 0;
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
                                                     GetKeyState(VK_LWIN) < 0 || GetKeyState(VK_RWIN) < 0) |
                ((GetKeyState(VK_CAPITAL) & 1) ? 0x100000u : 0u) |
                ((GetKeyState(VK_NUMLOCK) & 1) ? 0x200000u : 0u) |
                ((GetKeyState(VK_SCROLL) & 1) ? 0x400000u : 0u);
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
            const auto keycode = normalized == VK_RETURN && (lp & (LPARAM(1) << 24))
                                     ? 160u : android_keycode(normalized);
            KeyInput input{up, keycode, modifiers, repeat};
            auto generation = native_key_generation;
            if (queued && queued->message == msg && queued->wp == wp && queued->lp == lp) {
                input = queued->input;
                input.repeat = repeat;
                generation = queued->generation;
            }
            NativeKey native{msg, wp, lp, generation};
            if (queued && queued->message == msg && queued->wp == wp && queued->lp == lp) {
                native.original = queued->original;
                native.layout = queued->layout;
                native.keyboard = queued->keyboard;
                native.ime = native.layout && ImmIsIME(native.layout);
                native.allow_character = !up && msg == WM_KEYDOWN &&
                    !(input.meta & ~(key_lock_meta_mask | 1u)); // Shift/locks only; no shortcut text credits.
                native.editor = ime_target();
            }
            const auto ticket = session.key(input);
            if (native_eligible) pending_keys.emplace(ticket, std::move(native));
            return 0; // The completion applies an unhandled native default exactly once.
        }
        case WM_CHAR:
            ime_character(wp, lp); // Only bounded credits from guest-declined original IME keys may insert.
            return 0;
        case WM_SYSCHAR:
        case WM_DEADCHAR:
        case WM_SYSDEADCHAR:
            discard_character(lp);
            return 0;
        case WM_IME_CHAR:
            // GCS_RESULTSTR is the sole native composition result route. Never
            // let DefWindowProc convert this second path to duplicate WM_CHAR.
            ime_characters.clear();
            return 0;
        case WM_UNICHAR:
            return FALSE; // No independent Unicode-message insertion endpoint is advertised.
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
            if (!window || shutting_down || terminal_activation_mode)
                return 0;
            if (input_pane) input_pane->refresh(); // Passive recovery; no keyboard write.
            if (update_presentation()) publish_accessibility();
            position_ime();
            if (!window || shutting_down || terminal_activation_mode) return 0;
            ++report.timer_reads;
            request_accessibility_metadata(); // One coalesced explicit callback phase, not a snapshot side effect.
            if (!accessibility_metadata_ticket)
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
            pending_invocations = {};
            session.retire_clipboard_window();
            if (file_drop) file_drop->retire();
            file_drop.reset();
            cancel_drop_transfer();
            drop_review.reset();
            text_drop_review.reset();
            drop_transfer.reset();
            retire_ime(true);
            input_pane.reset();
            native_ime.reset(); // Active native calls retain their own shared owner through reentry.
            if (accessibility)
                accessibility->disconnect();
            if (power_notification) {
                UnregisterSuspendResumeNotification(power_notification);
                power_notification = nullptr;
            }
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
                   const std::shared_ptr<const apk::Artwork> &presentation,
                   const std::filesystem::path &developer_output_root)
        : session(session), report(report), developer_output_root(developer_output_root) {
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
            session.retire_clipboard_window();
            DestroyWindow(window);
        }
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
                                          CW_USEDEFAULT, session.snapshot().requested_orientation == 1 ? 380 : 560,
                                            session.snapshot().requested_orientation == 1 ? 560 : 380,
                                            nullptr, nullptr, instance, this);
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
            if (drop_review && drop_review->translate(msg)) continue;
            if (text_drop_review && text_drop_review->translate(msg)) continue;
            std::optional<CapturedKey> key;
            const bool owned_key = window && msg.hwnd == window &&
                (msg.message == WM_KEYDOWN || msg.message == WM_KEYUP ||
                 msg.message == WM_SYSKEYDOWN || msg.message == WM_SYSKEYUP);
            if (owned_key)
                key = capture_key(msg); // Raw same-event mapping; no eager native character/default route.
            else
                TranslateMessage(&msg); // Preserve normal translation for other native windows.
            captured_key = std::move(key); // Only the exact queued dispatch may use this Unicode snapshot.
            DispatchMessageW(&msg);
            captured_key.reset();
        }
        if (failure)
            std::rethrow_exception(failure);
    }
};
} // namespace

namespace {
WindowReport run_window(security::ActivityDispatcher &session, bool selftest, std::string installed_id = {},
                        std::shared_ptr<const apk::Artwork> presentation = {},
                        security::InstalledRelaunch relaunch = {},
                        const std::filesystem::path &developer_output_root = {}) {
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
        ActivityWindow window(session, report, presentation, developer_output_root);
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
WindowReport run_fixture_window(const std::filesystem::path &path, bool selftest,
                                const std::filesystem::path &developer_output_root) {
    security::ActivityDispatcher session(path, selftest ? security::ActivityMode::read_recovery_probe
                                                        : security::ActivityMode::normal, developer_output_root);
    return run_window(session, selftest, {}, {}, {}, developer_output_root);
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
InstalledCloseResult request_installed_window_close(
    std::string_view app_id, const std::filesystem::path &expected_launcher,
    const security::InstalledRelaunch &expected_relaunch) noexcept {
    InstalledCloseSearch search;
    try {
        if (!security::valid_installed_id(app_id) || !expected_relaunch.unavailable_reason.empty() ||
            expected_relaunch.command.empty() || expected_relaunch.display_name.empty() ||
            expected_relaunch.icon_resource.empty()) {
            search.error(ERROR_INVALID_PARAMETER);
            return search.result;
        }
        search.images[0] = close_image_path(expected_launcher);
        const std::filesystem::path launcher(search.images[0]);
        if (search.images[0].empty() || !same_path(launcher.filename().native(), L"aether-shell.exe")) {
            search.error(ERROR_INVALID_PARAMETER);
            return search.result;
        }
        search.images[1] = close_image_path(launcher.parent_path() / L"aether.exe");
        search.application_id = utf16("Aether.App." + std::string(app_id));
        search.relaunch = {utf16(expected_relaunch.command), utf16(expected_relaunch.display_name),
                           utf16(expected_relaunch.icon_resource)};
        for (const auto &value : search.relaunch)
            if (value.size() >= 32768 || value.find(L'\0') != std::wstring::npos) {
                search.error(ERROR_INVALID_PARAMETER);
                return search.result;
            }
        CloseComScope com;
        if (FAILED(com.initialized) && com.initialized != RPC_E_CHANGED_MODE) {
            search.error(static_cast<DWORD>(com.initialized));
            return search.result;
        }
        SetLastError(ERROR_SUCCESS);
        const auto enumerated = EnumWindows(InstalledCloseSearch::enumerate, reinterpret_cast<LPARAM>(&search));
        if (!enumerated)
            search.error(GetLastError());
        if (search.result.matched > 1)
            search.error(ERROR_DUP_NAME);
        if (search.result.error) {
            search.result.status = InstalledCloseStatus::partial_failure;
            return search.result;
        }
        if (!search.result.matched) {
            search.result.status = InstalledCloseStatus::no_eligible_window;
            return search.result;
        }
        DWORD current_pid = 0;
        const auto window = search.candidate;
        if (!InstalledCloseSearch::activity_class(window) ||
            !GetWindowThreadProcessId(window, &current_pid) || current_pid != search.process_id ||
            !search.image(search.process.get()) || !search.live(search.process.get()) ||
            !search.identity(window)) {
            search.error(ERROR_INVALID_WINDOW_HANDLE);
            search.result.status = InstalledCloseStatus::partial_failure;
            return search.result;
        }
        // Property reads can outlast the first HWND check. Recheck ownership and
        // the held process immediately before the sole asynchronous close post.
        current_pid = 0;
        if (!InstalledCloseSearch::activity_class(window) ||
            !GetWindowThreadProcessId(window, &current_pid) || current_pid != search.process_id ||
            !search.live(search.process.get())) {
            search.error(ERROR_INVALID_WINDOW_HANDLE);
            search.result.status = InstalledCloseStatus::partial_failure;
            return search.result;
        }
        if (!PostMessageW(window, WM_CLOSE, 0, 0)) {
            search.error(GetLastError());
            search.result.status = InstalledCloseStatus::partial_failure;
            return search.result;
        }
        search.result.requested = 1;
        search.result.status = InstalledCloseStatus::requested;
        return search.result;
    } catch (const std::bad_alloc &) {
        search.error(ERROR_NOT_ENOUGH_MEMORY);
    } catch (...) {
        search.error(ERROR_GEN_FAILURE);
    }
    return search.result;
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
           "\"renderer\":\"Win32-GDI-DirectWrite-Direct2D\",\"gpuGlesImplemented\":false,\"touchHardwareTested\":false,\"passed\":"
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
        << "},\"ime\":{\"submitted\":" << ime_submitted << ",\"completed\":" << ime_completed
        << ",\"rejected\":" << ime_rejected << ",\"diagnostic\":" << json_quote(ime_diagnostic)
        << ",\"profile\":\"bounded-IMM32-plain-editor\""
        << "},\"textEdit\":{\"attempted\":" << text_edit_attempted << ",\"failed\":" << text_edit_failed
        << ",\"historyGaps\":" << text_edit_gaps << ",\"diagnostic\":" << json_quote(text_edit_diagnostic)
        << ",\"profile\":\"bounded-actual-operation-history\""
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
    if (!ime_diagnostic.empty()) out << "Native IME: " << ime_diagnostic << '\n';
    if (!text_edit_diagnostic.empty()) out << "TextEdit: " << text_edit_diagnostic << '\n';
    if (verbose || !passed())
        for (const auto &check : checks)
            out << (check.passed ? "  PASS " : "  FAIL ") << check.name << '\n';
    return out.str();
}
} // namespace aether::host
