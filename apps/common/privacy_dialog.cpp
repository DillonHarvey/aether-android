#include "privacy_dialog.hpp"
#include "aether/common/text.hpp"
#include "aether/install/privacy.hpp"
#include "aether/install/store.hpp"
#include "dialog_style.hpp"
#include "privacy_ids.h"

namespace aether::install {
namespace {
struct Guide {
    std::wstring text;
    int dpi = 96;
    HFONT normal = nullptr, heading = nullptr, small = nullptr;
    HBRUSH brush = CreateSolidBrush(dialog_style::background);
    bool closed = false, initialized = false;
    ~Guide() {
        for (const auto font : {normal, heading, small})
            if (font)
                DeleteObject(font);
        DeleteObject(brush);
    }
    void layout(HWND window) {
        dpi = static_cast<int>(GetDpiForWindow(window));
        normal = dialog_style::font(15, FW_NORMAL, dpi);
        heading = dialog_style::font(27, FW_SEMIBOLD, dpi);
        small = dialog_style::font(13, FW_NORMAL, dpi);
        const auto place = [&](int id, int x, int y, int width, int height, HFONT font) {
            const auto child = GetDlgItem(window, id);
            SendMessageW(child, WM_SETFONT, reinterpret_cast<WPARAM>(font), FALSE);
            MoveWindow(child, dialog_style::px(x, dpi), dialog_style::px(y, dpi),
                       dialog_style::px(width, dpi), dialog_style::px(height, dpi), FALSE);
        };
        place(IDC_PRIVACY_LABEL, 32, 22, 512, 22, small);
        place(IDC_PRIVACY_HEADING, 32, 64, 576, 42, heading);
        place(dialog_style::close_id, 584, 12, 40, 40, normal);
        place(IDC_PRIVACY_TEXT, 32, 126, 576, 402, normal);
        place(IDCANCEL, 496, 550, 112, 42, normal);
        // EDITTEXT otherwise supplies a sunken system border unlike the installer.
        const auto edit = GetDlgItem(window, IDC_PRIVACY_TEXT);
        SetWindowLongPtrW(edit, GWL_STYLE, GetWindowLongPtrW(edit, GWL_STYLE) & ~WS_BORDER);
        SetWindowLongPtrW(edit, GWL_EXSTYLE, GetWindowLongPtrW(edit, GWL_EXSTYLE) & ~WS_EX_CLIENTEDGE);
        SetWindowPos(edit, nullptr, 0, 0, 0, 0,
                     SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
    }
    static INT_PTR CALLBACK callback(HWND window, UINT message, WPARAM first, LPARAM second) {
        auto *self = reinterpret_cast<Guide *>(GetWindowLongPtrW(window, DWLP_USER));
        if (message == WM_INITDIALOG) {
            self = reinterpret_cast<Guide *>(second);
            SetWindowLongPtrW(window, DWLP_USER, reinterpret_cast<LONG_PTR>(self));
            // RC's CAPTION directive adds WS_CAPTION to the compiled template.
            SetWindowTextW(window, L"Aether - Privacy and permissions");
            self->layout(window);
            SendDlgItemMessageW(window, IDC_PRIVACY_TEXT, EM_SETLIMITTEXT, 32767, 0);
            self->initialized = SetDlgItemTextW(window, IDC_PRIVACY_TEXT, self->text.c_str()) != FALSE;
            return TRUE;
        }
        if (!self)
            return FALSE;
        if (message == WM_NCHITTEST) {
            SetWindowLongPtrW(window, DWLP_MSGRESULT,
                              dialog_style::header_hit_test(window, second, self->dpi));
            return TRUE;
        }
        if (message == WM_ERASEBKGND) {
            RECT rect{};
            GetClientRect(window, &rect);
            FillRect(reinterpret_cast<HDC>(first), &rect, self->brush);
            return TRUE;
        }
        if (message == WM_CTLCOLORDLG || message == WM_CTLCOLORSTATIC || message == WM_CTLCOLOREDIT) {
            SetTextColor(reinterpret_cast<HDC>(first),
                         GetDlgCtrlID(reinterpret_cast<HWND>(second)) == IDC_PRIVACY_LABEL
                             ? dialog_style::muted : dialog_style::ink);
            SetBkColor(reinterpret_cast<HDC>(first), dialog_style::background);
            return reinterpret_cast<INT_PTR>(self->brush);
        }
        if (message == WM_DRAWITEM) {
            dialog_style::draw_button(*reinterpret_cast<DRAWITEMSTRUCT *>(second), self->normal,
                                      self->dpi, first == IDCANCEL);
            return TRUE;
        }
        if (message == WM_CLOSE || (message == WM_COMMAND &&
            (LOWORD(first) == IDCANCEL || LOWORD(first) == dialog_style::close_id))) {
            DestroyWindow(window);
            return TRUE;
        }
        if (message == WM_DESTROY) {
            self->closed = true; // Do not post WM_QUIT to the owner's message loop.
            // A synchronous accessibility/button invocation may destroy us while
            // GetMessage is dispatching a sent message. Wake its queued-message wait.
            PostThreadMessageW(GetCurrentThreadId(), WM_NULL, 0, 0);
            return TRUE;
        }
        return FALSE;
    }
};
} // namespace
void show_privacy_dialog(HWND owner) {
    const auto previous_dpi = SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    struct DpiRestore {
        DPI_AWARENESS_CONTEXT previous;
        ~DpiRestore() { if (previous) SetThreadDpiAwarenessContext(previous); }
    } dpi_restore{previous_dpi};
    Guide guide;
    for (const auto c : utf16(privacy_text())) {
        if (c == L'\n')
            guide.text += L'\r';
        guide.text += c;
    }
    const auto focus = GetFocus();
    const bool enabled = owner && IsWindowEnabled(owner);
    const bool visible = owner && IsWindowVisible(owner);
    STARTUPINFOW startup{sizeof(startup)};
    GetStartupInfoW(&startup);
    const bool minimized =
        owner ? IsIconic(owner) != FALSE
              : (startup.dwFlags & STARTF_USESHOWWINDOW) && startup.wShowWindow == SW_SHOWMINNOACTIVE;
    RECT bounds{};
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &bounds, 0);
    if (owner && !minimized)
        GetWindowRect(owner, &bounds);
    if (enabled)
        EnableWindow(owner, FALSE);
    struct Restore {
        HWND owner, focus;
        bool enabled, visible, minimized;
        ~Restore() {
            if (IsWindow(owner)) {
                if (enabled)
                    EnableWindow(owner, TRUE);
                if (visible)
                    ShowWindow(owner, minimized ? SW_SHOWMINNOACTIVE : SW_SHOWNORMAL);
                if (enabled && visible && !minimized) {
                    SetActiveWindow(owner);
                    if (IsWindow(focus))
                        SetFocus(focus);
                }
            }
        }
    } restore{owner, focus, enabled, visible, minimized};
    const auto window = CreateDialogParamW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(IDD_PRIVACY), owner,
                                           Guide::callback, reinterpret_cast<LPARAM>(&guide));
    if (!window)
        throw InstallError("AETHER_PRIVACY_DIALOG", "Windows could not open privacy and permissions");
    struct Close {
        HWND window;
        ~Close() {
            if (IsWindow(window))
                DestroyWindow(window);
        }
    } close{window};
    if (!guide.initialized)
        throw InstallError("AETHER_PRIVACY_DIALOG", "Windows could not display the privacy guide");
    const auto width = dialog_style::px(640, guide.dpi), height = dialog_style::px(616, guide.dpi);
    SetWindowPos(window, nullptr, bounds.left + (bounds.right - bounds.left - width) / 2,
                 bounds.top + (bounds.bottom - bounds.top - height) / 2, width, height,
                 SWP_NOZORDER | SWP_NOACTIVATE);
    if (!owner) {
        SetDlgItemTextW(window, dialog_style::close_id, L"Close privacy guide");
        SetDlgItemTextW(window, IDCANCEL, L"Close");
    }
    if (visible)
        ShowWindow(owner, SW_HIDE);
    ShowWindow(window, minimized ? SW_SHOWMINNOACTIVE : SW_SHOWNORMAL);
    MSG message{};
    while (!guide.closed) {
        const auto result = GetMessageW(&message, nullptr, 0, 0);
        if (result <= 0) {
            if (result == 0)
                PostQuitMessage(static_cast<int>(message.wParam));
            throw InstallError("AETHER_PRIVACY_DIALOG", "The privacy guide message loop ended unexpectedly");
        }
        if (!IsDialogMessageW(window, &message)) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
}
} // namespace aether::install
