#include "aether/host/windows/file_drop.hpp"
#include "aether/common/text.hpp"
#include <ole2.h>
#include <shellapi.h>
#include <shlobj_core.h>
#include <algorithm>
#include <atomic>
#include <limits>
#include <stdexcept>
#include <utility>
#include <vector>

namespace aether::host {
namespace {
constexpr FORMATETC drop_format{CF_HDROP, nullptr, DVASPECT_CONTENT, -1, TYMED_HGLOBAL};
constexpr FORMATETC text_drop_format{CF_UNICODETEXT, nullptr, DVASPECT_CONTENT, -1, TYMED_HGLOBAL};
std::u16string extract_text(IDataObject *data) {
    STGMEDIUM medium{};
    auto format = text_drop_format;
    if (!data || data->GetData(&format, &medium) != S_OK)
        throw std::runtime_error("AETHER_DROP_TEXT_FORMAT_UNAVAILABLE");
    struct Release { STGMEDIUM &value; ~Release() { ReleaseStgMedium(&value); } } release{medium};
    if (medium.tymed != TYMED_HGLOBAL || !medium.hGlobal)
        throw std::runtime_error("AETHER_DROP_TEXT_FORMAT_UNSUPPORTED");
    const auto bytes = GlobalSize(medium.hGlobal);
    if (bytes < sizeof(wchar_t) || bytes > 65536)
        throw std::runtime_error("AETHER_DROP_TEXT_FORMAT_LIMIT");
    const auto memory = static_cast<const wchar_t *>(GlobalLock(medium.hGlobal));
    if (!memory) throw std::runtime_error("AETHER_DROP_TEXT_FORMAT_UNAVAILABLE");
    struct Unlock { HGLOBAL value; ~Unlock() { GlobalUnlock(value); } } unlock{medium.hGlobal};
    const auto available = std::min<std::size_t>(bytes / sizeof(wchar_t), drop_text_limit + 1);
    std::size_t length = 0;
    while (length < available && memory[length]) ++length;
    if (length == available || length > drop_text_limit)
        throw std::runtime_error("AETHER_DROP_TEXT_FORMAT_LIMIT");
    std::u16string result(memory, memory + length);
    if (!valid_drop_text(result)) throw std::runtime_error("AETHER_DROP_TEXT_INVALID");
    // Keep exact selected code units, including CR/LF and an empty payload.
    // Allocation padding after the required terminator is not selected text.
    return result;
}
std::filesystem::path extract_file(IDataObject *data) {
    STGMEDIUM medium{};
    auto format = drop_format;
    if (!data || FAILED(data->GetData(&format, &medium)))
        throw std::runtime_error("AETHER_DROP_FORMAT_UNAVAILABLE");
    struct Release { STGMEDIUM &value; ~Release() { ReleaseStgMedium(&value); } } release{medium};
    if (medium.tymed != TYMED_HGLOBAL || !medium.hGlobal)
        throw std::runtime_error("AETHER_DROP_FORMAT_UNSUPPORTED");
    const auto bytes = GlobalSize(medium.hGlobal);
    if (bytes < sizeof(DROPFILES) + 2 * sizeof(wchar_t) || bytes > 65536)
        throw std::runtime_error("AETHER_DROP_FORMAT_LIMIT");
    const auto memory = static_cast<const unsigned char *>(GlobalLock(medium.hGlobal));
    if (!memory) throw std::runtime_error("AETHER_DROP_FORMAT_UNAVAILABLE");
    struct Unlock { HGLOBAL value; ~Unlock() { GlobalUnlock(value); } } unlock{medium.hGlobal};
    const auto header = reinterpret_cast<const DROPFILES *>(memory);
    if (!header->fWide || header->pFiles < sizeof(DROPFILES) || header->pFiles >= bytes ||
        header->pFiles % alignof(wchar_t))
        throw std::runtime_error("AETHER_DROP_FORMAT_UNSUPPORTED");
    const auto names = reinterpret_cast<const wchar_t *>(memory + header->pFiles);
    const auto count = (bytes - header->pFiles) / sizeof(wchar_t);
    std::size_t length = 0;
    while (length < count && names[length]) ++length;
    if (!length || length >= MAX_PATH || length + 1 >= count || names[length + 1])
        throw std::runtime_error("AETHER_DROP_SINGLE_FILE_REQUIRED");
    // The actual double-NUL list ends here. GlobalSize may include allocator
    // padding; those unspecified bytes are not additional file names.
    return std::filesystem::path(std::wstring(names, length));
}
bool copy_effect(DWORD allowed, DWORD keys) noexcept {
    // Copy is the only offered operation. Never claim move/link or cause source
    // deletion, including an explicit Shift or Ctrl+Shift operation.
    return (allowed & DROPEFFECT_COPY) && !(keys & (MK_SHIFT | MK_RBUTTON));
}
} // namespace
struct FileDrop::Impl final : IDropTarget {
    std::atomic<ULONG> references{1};
    const HWND window;
    const DWORD owner = GetCurrentThreadId();
    FileDropCallbacks callbacks;
    HRESULT initialized = E_FAIL;
    bool registered = false, live = true, calling = false;
    std::uint64_t generation = 0;
    DropPayloadKind selected_kind = DropPayloadKind::file;
    POINT entered{};
    std::optional<POINT> location;
    explicit Impl(HWND value, FileDropCallbacks functions) : window(value), callbacks(std::move(functions)) {}
    ~Impl() { if (SUCCEEDED(initialized)) OleUninitialize(); }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void **output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        if (iid != IID_IUnknown && iid != IID_IDropTarget) return E_NOINTERFACE;
        *output = static_cast<IDropTarget *>(this); AddRef(); return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return references.fetch_add(1, std::memory_order_relaxed) + 1; }
    ULONG STDMETHODCALLTYPE Release() override {
        const auto remaining = references.fetch_sub(1, std::memory_order_acq_rel) - 1;
        // The shared owner supplies the initial reference; native registration
        // and in-flight calls retain separate references until their return.
        if (!remaining) delete this;
        return remaining;
    }
    bool ready() const noexcept {
        DWORD process = 0;
        return live && GetCurrentThreadId() == owner && IsWindow(window) &&
            GetWindowThreadProcessId(window, &process) == owner && process == GetCurrentProcessId();
    }
    void clear() noexcept {
        const auto old = std::exchange(generation, 0);
        location.reset();
        if (old) try { const auto cancel = callbacks.cancel; if (cancel) cancel(old); } catch (...) {}
    }
    struct Call {
        Impl &value;
        explicit Call(Impl &state) : value(state) { value.AddRef(); value.calling = true; }
        ~Call() { value.calling = false; value.Release(); }
    };
    HRESULT STDMETHODCALLTYPE DragEnter(IDataObject *data, DWORD keys, POINTL point, DWORD *effect) override {
        if (!effect) return E_INVALIDARG;
        const auto allowed = std::exchange(*effect, DROPEFFECT_NONE);
        if (!ready() || calling) return S_OK;
        Call call(*this);
        clear();
        if (!data || !copy_effect(allowed, keys)) return S_OK;
        // Freeze one representation for this native session. A file offer wins
        // over a text representation of its path; failure never changes kind.
        auto file_format = drop_format, text_format = text_drop_format;
        if (data->QueryGetData(&file_format) == S_OK) selected_kind = DropPayloadKind::file;
        else if (data->QueryGetData(&text_format) == S_OK) selected_kind = DropPayloadKind::plain_text;
        else return S_OK;
        try {
            entered = {point.x, point.y};
            const auto begin = callbacks.begin;
            generation = begin ? begin(entered) : 0;
            if (ready() && generation) *effect = DROPEFFECT_COPY;
        } catch (...) { clear(); }
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE DragOver(DWORD keys, POINTL point, DWORD *effect) override {
        if (!effect) return E_INVALIDARG;
        const auto allowed = std::exchange(*effect, DROPEFFECT_NONE);
        if (!ready() || calling || !generation) return S_OK;
        Call call(*this);
        try {
            const POINT current{point.x, point.y};
            const auto over = callbacks.over;
            if (copy_effect(allowed, keys) && over && over(generation, current)) {
                location = current;
                if (ready()) *effect = DROPEFFECT_COPY;
            }
        } catch (...) { clear(); }
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE DragLeave() override {
        if (ready() && !calling) { Call call(*this); clear(); }
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Drop(IDataObject *data, DWORD keys, POINTL point, DWORD *effect) override {
        if (!effect) return E_INVALIDARG;
        const auto allowed = std::exchange(*effect, DROPEFFECT_NONE);
        if (!ready() || calling || !generation) return S_OK;
        Call call(*this);
        const auto old = generation;
        try {
            const POINT dropped{point.x, point.y};
            const auto over = callbacks.over;
            if (copy_effect(allowed, keys) && over && over(old, dropped)) {
                // No source extraction takes place before this actual Drop.
                FileDropCapture capture{old, {}, entered, dropped, location, selected_kind, {}};
                if (selected_kind == DropPayloadKind::file) capture.file = extract_file(data);
                else capture.text = extract_text(data);
                generation = 0; location.reset(); // Consume before the host callback.
                const auto accept = callbacks.accept;
                if (ready() && accept && accept(std::move(capture)) && ready())
                    *effect = DROPEFFECT_COPY;
            }
        } catch (...) {}
        clear();
        return S_OK;
    }
    void retire() noexcept {
        if (!live) return;
        live = false;
        clear();
        callbacks = {};
        if (std::exchange(registered, false)) (void)RevokeDragDrop(window);
    }
};
FileDrop::FileDrop(HWND window, FileDropCallbacks callbacks) {
    auto raw = new Impl(window, std::move(callbacks));
    impl_ = std::shared_ptr<Impl>(raw, [](Impl *value) { value->Release(); });
    raw->initialized = OleInitialize(nullptr);
    if (FAILED(raw->initialized)) throw std::runtime_error("AETHER_DROP_APARTMENT_UNAVAILABLE");
    const auto status = RegisterDragDrop(window, raw);
    if (FAILED(status)) throw std::runtime_error("AETHER_DROP_REGISTRATION_UNAVAILABLE");
    raw->registered = true;
}
FileDrop::~FileDrop() noexcept { retire(); }
void FileDrop::retire() noexcept { if (impl_) impl_->retire(); }

namespace {
class TypedDocument final : public DocumentService {
    const PreparedDocumentSource original_;
    const DocumentInfo info_;
  public:
    TypedDocument(PreparedDocumentSource original, std::string mime)
        : original_(std::move(original)), info_([&] { auto info = original_.info; info.mime_type = std::move(mime); return info; }()) {}
    FileResult describe(std::string_view uri, DocumentInfo &output) noexcept override {
        DocumentInfo actual;
        const auto result = original_.service->describe(uri, actual);
        if (result.error != FileError::none) return result;
        if (actual != original_.info) return {-1, FileError::denied};
        try { output = info_; return {0, FileError::none}; } catch (...) { return {-1, FileError::io}; }
    }
    FileResult open_document(std::string_view uri) noexcept override {
        DocumentInfo checked;
        const auto result = describe(uri, checked);
        return result.error == FileError::none ? original_.service->open_document(uri) : result;
    }
    FileResult read_document(int descriptor, std::span<std::uint8_t> bytes) noexcept override {
        return original_.service->read_document(descriptor, bytes);
    }
    FileResult close_document(int descriptor) noexcept override { return original_.service->close_document(descriptor); }
    void revoke_documents() noexcept override { original_.service->revoke_documents(); }
};
constexpr wchar_t review_class[] = L"Aether.FileDropReview.v1";
std::wstring safe_text(std::wstring_view value) {
    constexpr wchar_t digits[] = L"0123456789ABCDEF";
    std::wstring result;
    for (std::size_t at = 0; at < value.size(); ++at) {
        const auto unit = value[at];
        if (unit >= 0xd800 && unit <= 0xdbff && at + 1 < value.size() &&
            value[at + 1] >= 0xdc00 && value[at + 1] <= 0xdfff) {
            result.push_back(unit); result.push_back(value[++at]); continue;
        }
        if (unit < 32 || (unit >= 0x7f && unit <= 0x9f) || unit == 0x061c || unit == 0x200e || unit == 0x200f ||
            (unit >= 0x2028 && unit <= 0x202e) || (unit >= 0x2066 && unit <= 0x2069) ||
            (unit >= 0xd800 && unit <= 0xdfff) || unit == L'\\') {
            result += L"\\u";
            for (int shift = 12; shift >= 0; shift -= 4) result.push_back(digits[(unit >> shift) & 15]);
        } else result.push_back(unit);
    }
    return result;
}
std::wstring safe_text(std::string_view text) { return safe_text(utf16(text)); }
} // namespace
struct FileDropReview::Impl : std::enable_shared_from_this<FileDropReview::Impl> {
    const HWND owner;
    const DWORD owner_thread = GetCurrentThreadId(), owner_process = GetCurrentProcessId();
    HWND window = nullptr, mime = nullptr, status = nullptr, approve = nullptr;
    PreparedDocumentSource source;
    std::optional<PreparedDocumentSource> result;
    bool available = false, closed = false;
    explicit Impl(HWND parent, std::wstring recipient, const std::filesystem::path &path)
        : owner(parent), source(prepare_document_source(path, "application/octet-stream")) {
        struct Construction {
            Impl &self; bool ready = false;
            ~Construction() { if (!ready) self.close(false); }
        } construction{*this};
        WNDCLASSW type{}; type.lpfnWndProc = procedure; type.hInstance = GetModuleHandleW(nullptr);
        type.lpszClassName = review_class; type.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        if (!RegisterClassW(&type) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS)
            throw std::runtime_error("AETHER_DROP_REVIEW_UNAVAILABLE");
        const auto dpi = GetDpiForWindow(owner);
        window = CreateWindowExW(WS_EX_DLGMODALFRAME, review_class, L"Share dropped document read-only",
            WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, CW_USEDEFAULT, CW_USEDEFAULT,
            MulDiv(580, static_cast<int>(dpi), 96), MulDiv(300, static_cast<int>(dpi), 96),
            owner, nullptr, type.hInstance, this);
        if (!window) throw std::runtime_error("AETHER_DROP_REVIEW_UNAVAILABLE");
        const auto label = L"Recipient: " + safe_text(recipient) + L"\r\nDocument: " + safe_text(source.info.display_name) +
            L"\r\nSize: " + std::to_wstring(source.info.size) + L" bytes\r\nAllow this receiving screen to request read access to only this document.";
        control(L"EDIT", label.c_str(), 12, 12, 548, 90, 11, ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL);
        control(L"STATIC", L"MIME type (review or edit the generic default):", 12, 105, 548, 22, 0);
        mime = control(L"EDIT", L"application/octet-stream", 12, 130, 548, 27, 10, WS_BORDER | ES_AUTOHSCROLL);
        SendMessageW(mime, EM_SETLIMITTEXT, 255, 0);
        status = control(L"STATIC", L"Checking the held document...", 12, 166, 548, 30, 0);
        approve = control(L"BUTTON", L"Allow read request", 295, 208, 145, 30, IDOK, BS_DEFPUSHBUTTON);
        control(L"BUTTON", L"Cancel", 450, 208, 110, 30, IDCANCEL);
        refresh();
        if (!SetTimer(window, 1, 1000, nullptr)) throw std::runtime_error("AETHER_DROP_REVIEW_UNAVAILABLE");
        ShowWindow(window, SW_SHOWNORMAL);
        SetFocus(mime);
        construction.ready = true;
    }
    ~Impl() { close(false); }
    HWND control(const wchar_t *type, const wchar_t *caption, int x, int y, int width, int height, int id, DWORD style = 0) {
        const auto dpi = GetDpiForWindow(window);
        const auto scale = [dpi](int value) { return MulDiv(value, static_cast<int>(dpi), 96); };
        auto child = CreateWindowExW(0, type, caption, WS_CHILD | WS_VISIBLE | (id ? WS_TABSTOP : 0) | style,
            scale(x), scale(y), scale(width), scale(height), window,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), GetModuleHandleW(nullptr), nullptr);
        if (!child) throw std::runtime_error("AETHER_DROP_REVIEW_UNAVAILABLE");
        SendMessageW(child, WM_SETFONT, reinterpret_cast<WPARAM>(GetStockObject(DEFAULT_GUI_FONT)), FALSE);
        return child;
    }
    std::string current_mime() const {
        wchar_t value[256]{};
        const auto length = GetWindowTextW(mime, value, static_cast<int>(std::size(value)));
        if (length <= 0) return {};
        return utf8(std::wstring_view(value, static_cast<std::size_t>(length)));
    }
    void refresh() noexcept {
        if (closed || !window || !mime) return;
        try {
            DocumentInfo actual;
            available = source.service && source.service->describe(source.info.uri, actual).error == FileError::none && actual == source.info;
            const auto valid = valid_document_mime(current_mime());
            EnableWindow(approve, available && valid);
            SetWindowTextW(status, !available ? L"Held document unavailable. Checking again automatically; your MIME edit is kept." :
                !valid ? L"Enter one canonical lowercase MIME type such as text/plain." : L"Ready. The app must request access; release or closing this Activity ends that permission.");
        } catch (...) { available = false; EnableWindow(approve, FALSE); }
    }
    void close(bool restore) noexcept {
        if (closed) return;
        closed = true;
        if (window) { KillTimer(window, 1); DestroyWindow(window); window = nullptr; }
        DWORD process = 0;
        if (restore && IsWindow(owner) && GetWindowThreadProcessId(owner, &process) == owner_thread && process == owner_process) {
            SetForegroundWindow(owner); SetFocus(owner);
        }
    }
    void accept() {
        refresh();
        const auto type = current_mime();
        if (!available || !valid_document_mime(type)) return;
        auto service = std::make_shared<TypedDocument>(source, type);
        auto info = source.info; info.mime_type = type;
        DocumentInfo actual;
        if (service->describe(info.uri, actual).error != FileError::none || actual != info) return;
        result.emplace(PreparedDocumentSource{std::move(info), std::move(service)});
        close(true);
    }
    static LRESULT CALLBACK procedure(HWND hwnd, UINT message, WPARAM wp, LPARAM lp) noexcept {
        auto self = reinterpret_cast<Impl *>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        if (message == WM_NCCREATE) {
            self = static_cast<Impl *>(reinterpret_cast<CREATESTRUCTW *>(lp)->lpCreateParams);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
        }
        if (!self) return DefWindowProcW(hwnd, message, wp, lp);
        // Once constructed, pin the callback state across native close/focus
        // reentry even if the parent consumes and deletes its review wrapper.
        const auto pin = self->weak_from_this().lock();
        try {
            if (message == WM_TIMER) { self->refresh(); return 0; }
            if (message == WM_COMMAND) {
                if (LOWORD(wp) == IDOK) { self->accept(); return 0; }
                if (LOWORD(wp) == IDCANCEL) { self->close(true); return 0; }
                if (LOWORD(wp) == 10 && HIWORD(wp) == EN_CHANGE) { self->refresh(); return 0; }
            }
            if (message == WM_CLOSE) { self->close(true); return 0; }
            if (message == WM_NCDESTROY) {
                self->closed = true; self->window = nullptr;
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            }
        } catch (...) { self->close(true); }
        return DefWindowProcW(hwnd, message, wp, lp);
    }
};
FileDropReview::FileDropReview(HWND owner, std::wstring recipient, const std::filesystem::path &path)
    : impl_(std::make_shared<Impl>(owner, std::move(recipient), path)) {}
FileDropReview::~FileDropReview() noexcept = default;
bool FileDropReview::closed() const noexcept { return impl_->closed; }
bool FileDropReview::translate(MSG &message) noexcept {
    const auto state = impl_;
    return state->window && IsDialogMessageW(state->window, &message);
}
std::optional<PreparedDocumentSource> FileDropReview::take() { return std::exchange(impl_->result, {}); }
void FileDropReview::cancel() noexcept { const auto state = impl_; state->result.reset(); state->close(false); }

struct TextDropReview::Impl : std::enable_shared_from_this<TextDropReview::Impl> {
    const HWND owner;
    const DWORD owner_thread = GetCurrentThreadId(), owner_process = GetCurrentProcessId();
    const std::u16string text;
    HWND window = nullptr;
    std::optional<std::u16string> result;
    bool closed = false;
    Impl(HWND parent, std::wstring recipient, std::u16string selected)
        : owner(parent), text(std::move(selected)) {
        if (!valid_drop_text(text)) throw std::runtime_error("AETHER_DROP_TEXT_INVALID");
        struct Construction {
            Impl &self; bool ready = false;
            ~Construction() { if (!ready) self.close(false); }
        } construction{*this};
        constexpr wchar_t class_name[] = L"Aether.TextDropReview.v1";
        WNDCLASSW type{}; type.lpfnWndProc = procedure; type.hInstance = GetModuleHandleW(nullptr);
        type.lpszClassName = class_name; type.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        if (!RegisterClassW(&type) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS)
            throw std::runtime_error("AETHER_DROP_TEXT_REVIEW_UNAVAILABLE");
        const auto dpi = GetDpiForWindow(owner);
        window = CreateWindowExW(WS_EX_DLGMODALFRAME, class_name, L"Share dropped plain text",
            WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, CW_USEDEFAULT, CW_USEDEFAULT,
            MulDiv(620, static_cast<int>(dpi), 96), MulDiv(430, static_cast<int>(dpi), 96),
            owner, nullptr, type.hInstance, this);
        if (!window) throw std::runtime_error("AETHER_DROP_TEXT_REVIEW_UNAVAILABLE");
        const auto label = L"Recipient: " + safe_text(recipient) +
            L"\r\nPlain text (text/plain). Only the selected text shown below will be sent.";
        control(L"EDIT", label.c_str(), 12, 12, 588, 65, 10, ES_MULTILINE | ES_READONLY | WS_VSCROLL);
        control(L"STATIC", L"Exact selection preview (controls and directional formatting are escaped):", 12, 84, 588, 26, 0);
        const auto preview = safe_text(std::wstring(text.begin(), text.end()));
        control(L"EDIT", preview.c_str(), 12, 112, 588, 185, 11,
            ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL);
        control(L"STATIC", L"The app can retain a copy after delivery. Cancelling before sharing sends no text. Clipboard access is not granted.",
            12, 305, 588, 42, 0);
        control(L"BUTTON", L"Share selected text", 325, 354, 155, 30, IDOK, BS_DEFPUSHBUTTON);
        control(L"BUTTON", L"Cancel", 490, 354, 110, 30, IDCANCEL);
        ShowWindow(window, SW_SHOWNORMAL);
        SetFocus(GetDlgItem(window, 11));
        construction.ready = true;
    }
    ~Impl() { close(false); }
    HWND control(const wchar_t *type, const wchar_t *caption, int x, int y, int width, int height, int id, DWORD style = 0) {
        const auto dpi = GetDpiForWindow(window);
        const auto scale = [dpi](int value) { return MulDiv(value, static_cast<int>(dpi), 96); };
        const auto child = CreateWindowExW(0, type, caption, WS_CHILD | WS_VISIBLE | (id ? WS_TABSTOP : 0) | style,
            scale(x), scale(y), scale(width), scale(height), window,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), GetModuleHandleW(nullptr), nullptr);
        if (!child) throw std::runtime_error("AETHER_DROP_TEXT_REVIEW_UNAVAILABLE");
        SendMessageW(child, WM_SETFONT, reinterpret_cast<WPARAM>(GetStockObject(DEFAULT_GUI_FONT)), FALSE);
        return child;
    }
    void close(bool restore) noexcept {
        if (closed) return;
        closed = true;
        if (window) { DestroyWindow(window); window = nullptr; }
        DWORD process = 0;
        if (restore && IsWindow(owner) && GetWindowThreadProcessId(owner, &process) == owner_thread && process == owner_process) {
            SetForegroundWindow(owner); SetFocus(owner);
        }
    }
    void accept() {
        if (!valid_drop_text(text)) return;
        result = text;
        close(true);
    }
    static LRESULT CALLBACK procedure(HWND hwnd, UINT message, WPARAM wp, LPARAM lp) noexcept {
        auto self = reinterpret_cast<Impl *>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        if (message == WM_NCCREATE) {
            self = static_cast<Impl *>(reinterpret_cast<CREATESTRUCTW *>(lp)->lpCreateParams);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
        }
        if (!self) return DefWindowProcW(hwnd, message, wp, lp);
        const auto pin = self->weak_from_this().lock();
        try {
            if (message == WM_COMMAND) {
                if (LOWORD(wp) == IDOK) { self->accept(); return 0; }
                if (LOWORD(wp) == IDCANCEL) { self->close(true); return 0; }
            }
            if (message == WM_CLOSE) { self->close(true); return 0; }
            if (message == WM_NCDESTROY) {
                self->closed = true; self->window = nullptr;
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            }
        } catch (...) { self->close(true); }
        return DefWindowProcW(hwnd, message, wp, lp);
    }
};
TextDropReview::TextDropReview(HWND owner, std::wstring recipient, std::u16string text)
    : impl_(std::make_shared<Impl>(owner, std::move(recipient), std::move(text))) {}
TextDropReview::~TextDropReview() noexcept = default;
bool TextDropReview::closed() const noexcept { return impl_->closed; }
bool TextDropReview::translate(MSG &message) noexcept {
    const auto state = impl_;
    return state->window && IsDialogMessageW(state->window, &message);
}
std::optional<std::u16string> TextDropReview::take() { return std::exchange(impl_->result, {}); }
void TextDropReview::cancel() noexcept { const auto state = impl_; state->result.reset(); state->close(false); }
} // namespace aether::host
