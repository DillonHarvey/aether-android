#include "privacy_dialog.hpp"
#include "aether/common/text.hpp"
#include "aether/install/privacy.hpp"
#include "aether/install/store.hpp"
#include "privacy_ids.h"

namespace aether::install {
namespace {
struct Guide {
    std::wstring text;
    bool closed = false, initialized = false;
    static INT_PTR CALLBACK callback(HWND window, UINT message, WPARAM first, LPARAM second) {
        auto *self = reinterpret_cast<Guide *>(GetWindowLongPtrW(window, DWLP_USER));
        if (message == WM_INITDIALOG) {
            self = reinterpret_cast<Guide *>(second);
            SetWindowLongPtrW(window, DWLP_USER, reinterpret_cast<LONG_PTR>(self));
            SendDlgItemMessageW(window, IDC_PRIVACY_TEXT, EM_SETLIMITTEXT, 32767, 0);
            self->initialized = SetDlgItemTextW(window, IDC_PRIVACY_TEXT, self->text.c_str()) != FALSE;
            return TRUE;
        }
        if (!self)
            return FALSE;
        if (message == WM_CLOSE || (message == WM_COMMAND && LOWORD(first) == IDCANCEL)) {
            DestroyWindow(window);
            return TRUE;
        }
        if (message == WM_DESTROY) {
            self->closed = true; // Do not post WM_QUIT to the owner's message loop.
            return TRUE;
        }
        return FALSE;
    }
};
} // namespace
void show_privacy_dialog(HWND owner) {
    Guide guide;
    for (const auto c : utf16(privacy_text())) {
        if (c == L'\n')
            guide.text += L'\r';
        guide.text += c;
    }
    const auto focus = GetFocus();
    const bool enabled = owner && IsWindowEnabled(owner);
    if (enabled)
        EnableWindow(owner, FALSE);
    struct Restore {
        HWND owner, focus;
        bool enabled;
        ~Restore() {
            if (enabled && IsWindow(owner)) {
                EnableWindow(owner, TRUE);
                if (!IsIconic(owner) && GetActiveWindow() == owner && IsWindow(focus))
                    SetFocus(focus);
            }
        }
    } restore{owner, focus, enabled};
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
    STARTUPINFOW startup{sizeof(startup)};
    GetStartupInfoW(&startup);
    const bool minimized =
        owner ? IsIconic(owner) != FALSE
              : (startup.dwFlags & STARTF_USESHOWWINDOW) && startup.wShowWindow == SW_SHOWMINNOACTIVE;
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
