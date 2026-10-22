#include "install_dialog.hpp"
#include "aether/apk/artwork.hpp"
#include "aether/common/text.hpp"
#include "aether/install/store.hpp"
#include "aether/security/metadata_process.hpp"
#include "dialog_style.hpp"
#include "privacy_dialog.hpp"
#include <Windows.h>
#include <algorithm>
#include <atomic>
#include <commctrl.h>
#include <future>
#include <iostream>

namespace aether::install {
namespace {
constexpr int action_id = 100, permissions_id = 102, private_files_id = 201, wall_clock_id = 202, privacy_id = 220;
using namespace dialog_style;
std::wstring display(std::string_view text, std::string_view fallback = "Android app") {
    return utf16(apk::clean_display_name(text, fallback));
}
std::string error_code(const std::exception &error) {
    if (const auto *value = dynamic_cast<const InstallError *>(&error))
        return value->code;
    if (const auto *value = dynamic_cast<const apk::InspectError *>(&error))
        return value->diagnostic.code;
    return "AETHER_SHELL_FAILED";
}
struct Icon {
    HICON value = nullptr;
    Icon(const apk::IconBitmap &bitmap, int size) {
        const auto bytes = apk::icon_file(bitmap, 2);
        const auto number = [&](std::size_t offset) {
            return DWORD(bytes.at(offset)) | (DWORD(bytes.at(offset + 1)) << 8) |
                   (DWORD(bytes.at(offset + 2)) << 16) | (DWORD(bytes.at(offset + 3)) << 24);
        };
        const auto index = std::size_t(6 + 6 * 16); // Canonical 256 px DIB; never an untrusted image decoder.
        const auto length = number(index + 8), offset = number(index + 12);
        if (offset <= bytes.size() && length <= bytes.size() - offset)
            value = CreateIconFromResourceEx(const_cast<BYTE *>(bytes.data()) + offset, length, TRUE,
                                             0x00030000, size, size, 0);
        if (!value)
            throw InstallError("AETHER_SHELL_ICON", "Windows could not create the application icon");
    }
    ~Icon() {
        if (value)
            DestroyIcon(value);
    }
};
struct Observation {
    std::shared_ptr<const apk::PackagePreview> package;
    std::optional<shell::IconDigest> identity;
    std::optional<InstalledApp> current;
    std::string code, message;
    bool available = false;
};
struct Outcome {
    std::optional<InstalledApp> app;
    std::string hash, code, message;
};
struct Installer {
    std::filesystem::path source, root;
    std::string uninstall_id;
    HWND keep_check = nullptr;
    bool uninstalling = false, keep_data = true;
    HWND window = nullptr, permission_window = nullptr;
    HWND picture = nullptr, title = nullptr, subtitle = nullptr, status = nullptr, progress = nullptr;
    HWND action = nullptr, cancel = nullptr, permissions = nullptr, close = nullptr;
    HWND wall_clock_check = nullptr, files_check = nullptr, declarations = nullptr, permission_app = nullptr;
    HFONT normal = nullptr, heading = nullptr, small = nullptr;
    HBRUSH brush = CreateSolidBrush(background);
    int dpi = 96;
    std::unique_ptr<Icon> icon;
    std::shared_ptr<const apk::PackagePreview> cached;
    std::optional<shell::IconDigest> cached_identity;
    std::future<Observation> read;
    std::future<Outcome> write;
    Observation shown;
    Outcome outcome;
    std::atomic<InstallStage> stage{InstallStage::verifying};
    std::uint32_t grants = security::installed_clock;
    bool visible = false, busy = false, finished = false, cancelled = true, was_failed = false;
    bool permission_minimized = false;
    unsigned reads = 0, extractions = 0, failures = 0, recoveries = 0, attempts = 0;
    ULONGLONG started = GetTickCount64(), last_read = 0, ready_ms = 0, install_ms = 0, commit_started = 0;
    std::optional<InstalledApp> selected_current;

    Installer(std::filesystem::path input, std::filesystem::path store, std::string identity = {})
        : source(std::move(input)), root(std::move(store)), uninstall_id(std::move(identity)),
          uninstalling(!uninstall_id.empty()) {}
    ~Installer() {
        if (IsWindow(permission_window))
            DestroyWindow(permission_window);
        if (IsWindow(window))
            DestroyWindow(window);
        if (read.valid())
            read.wait();
        if (write.valid())
            write.wait();
        for (const auto font : {normal, heading, small})
            if (font)
                DeleteObject(font);
        DeleteObject(brush);
    }
    int px(int value) const { return MulDiv(value, dpi, 96); }
    HWND control(HWND parent, const wchar_t *kind, const wchar_t *text, DWORD style, int x, int y, int width,
                 int height, int id = 0, HFONT font = nullptr) {
        auto result =
            CreateWindowExW(0, kind, text, WS_CHILD | WS_VISIBLE | style, px(x), px(y), px(width), px(height),
                            parent, reinterpret_cast<HMENU>(INT_PTR(id)), GetModuleHandleW(nullptr), nullptr);
        if (!result)
            throw InstallError("AETHER_SHELL_DIALOG", "Cannot create an installer control");
        SendMessageW(result, WM_SETFONT, reinterpret_cast<WPARAM>(font ? font : normal), FALSE);
        return result;
    }
    HWND make_window(const wchar_t *caption, int width, int height, HWND parent = nullptr) {
        RECT bounds{0, 0, px(width), px(height)};
        const DWORD style = WS_POPUP | WS_MINIMIZEBOX;
        const auto w = bounds.right - bounds.left, h = bounds.bottom - bounds.top;
        RECT screen{};
        SystemParametersInfoW(SPI_GETWORKAREA, 0, &screen, 0);
        if (parent)
            GetWindowRect(parent, &screen);
        return CreateWindowExW(WS_EX_CONTROLPARENT | WS_EX_APPWINDOW, L"Aether.Installation", caption, style,
                               screen.left + (screen.right - screen.left - w) / 2,
                               screen.top + (screen.bottom - screen.top - h) / 2, w, h, parent, nullptr,
                               GetModuleHandleW(nullptr), this);
    }
    void create() {
        dpi = static_cast<int>(GetDpiForSystem());
        normal = dialog_style::font(15, FW_NORMAL, dpi);
        heading = dialog_style::font(27, FW_SEMIBOLD, dpi);
        small = dialog_style::font(13, FW_NORMAL, dpi);
        WNDCLASSW cls{};
        cls.lpfnWndProc = procedure;
        cls.hInstance = GetModuleHandleW(nullptr);
        cls.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        cls.lpszClassName = L"Aether.Installation";
        if (!RegisterClassW(&cls) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS)
            throw InstallError("AETHER_SHELL_DIALOG", "Cannot register the installer window");
        window = make_window(uninstalling ? L"Aether - App uninstaller" : L"Aether - App installer", 640, 344);
        if (!window)
            throw InstallError("AETHER_SHELL_DIALOG", "Cannot create the installer window");
        control(window, L"STATIC", uninstalling ? L"AETHER  /  APP UNINSTALLER" : L"AETHER  /  APP INSTALLER", 0, 36, 22, 520, 22, 0, small);
        close = control(window, L"BUTTON", uninstalling ? L"Close uninstaller" : L"Close installer", BS_OWNERDRAW | WS_TABSTOP,
                        584, 12, 40, 40, close_id);
        picture = control(window, L"STATIC", L"App icon", SS_ICON | SS_CENTERIMAGE, 36, 77, 88, 88);
        title = control(window, L"STATIC", L"", SS_NOPREFIX, 148, 72, 456, 76, 0, heading);
        subtitle = control(window, L"STATIC", L"", SS_NOPREFIX, 148, 155, 456, 26, 0, small);
        status = control(window, L"STATIC", L"", SS_NOPREFIX, 36, 208, 568, 42, 0, small);
        progress = control(window, PROGRESS_CLASSW, uninstalling ? L"Uninstallation progress" : L"Installation progress", PBS_MARQUEE, 160, 228, 320, 7);
        ShowWindow(progress, SW_HIDE);
        permissions = control(window, L"BUTTON", L"Permissions", BS_OWNERDRAW | WS_TABSTOP, 24, 280, 128, 42,
                              permissions_id);
        cancel =
            control(window, L"BUTTON", L"Cancel", BS_OWNERDRAW | WS_TABSTOP, 372, 280, 104, 42, IDCANCEL);
        action =
            control(window, L"BUTTON", L"Install", BS_OWNERDRAW | WS_TABSTOP, 488, 280, 116, 42, action_id);
        if (uninstalling) {
            ShowWindow(permissions, SW_HIDE);
            keep_check = control(window, L"BUTTON", L"Keep private data and diagnostic history",
                                 BS_AUTOCHECKBOX | WS_TABSTOP, 36, 254, 568, 24);
            SendMessageW(keep_check, BM_SETCHECK, BST_CHECKED, 0);
            set_text(action, L"Uninstall");
        }
        EnableWindow(action, FALSE);
        SetTimer(window, 1, 50, nullptr);
        tick(); // Remain hidden until the complete first metadata observation is applied.
    }
    Observation observe() {
        Observation result;
        try {
            if (uninstalling) {
                PackageStore store(root);
                result.current = store.info(uninstall_id);
                const auto state = result.current->state;
                result.available = state == State::installed || state == State::data_retained;
                // Artwork is optional for removal. Decode package resources only in
                // the existing isolated metadata worker; damaged/missing artwork
                // must never prevent the user from removing an app.
                if (state == State::installed && !cached) {
                    try {
                        shell::IconSource input(package_path(*result.current, root), true);
                        std::wstring executable(32768, L'\0');
                        const auto count = GetModuleFileNameW(nullptr, executable.data(), DWORD(executable.size()));
                        if (count && count < executable.size()) {
                            executable.resize(count);
                            security::MetadataProcess worker(std::filesystem::path(executable).parent_path() /
                                                             L"runtime" / L"aether_icon_worker.exe");
                            auto metadata = worker.inspect(input);
                            cached = std::make_shared<const apk::PackagePreview>(std::move(metadata.preview));
                        }
                    } catch (const std::exception &) {
                        // Keep the standard Aether fallback for unavailable artwork.
                    }
                }
                result.package = cached;
                if (!result.available)
                    result.message = "This app is unavailable or needs explicit repair before uninstalling.";
                return result;
            }
            shell::IconSource input(source, true);
            if (!cached || cached_identity != input.identity()) {
                std::wstring executable(32768, L'\0');
                auto count = GetModuleFileNameW(nullptr, executable.data(), DWORD(executable.size()));
                if (!count || count >= executable.size())
                    throw InstallError("AETHER_SHELL_PATH", "Cannot locate the metadata worker");
                executable.resize(count);
                security::MetadataProcess worker(std::filesystem::path(executable).parent_path() /
                                                 L"runtime" / L"aether_icon_worker.exe");
                ++extractions;
                auto metadata = worker.inspect(input);
                if (metadata.preview.package_name.empty())
                    throw InstallError(metadata.preview.code, metadata.preview.reason);
                cached = std::make_shared<const apk::PackagePreview>(std::move(metadata.preview));
                cached_identity = input.identity();
            }
            result.package = cached;
            result.identity = input.identity();
            if (cached->format != apk::PreviewFormat::apk && cached->format != apk::PreviewFormat::xapk)
                throw InstallError("AETHER_INSTALL_FORMAT_UNSUPPORTED",
                                   "This package format supports preview only.");
            PackageStore store(root);
            for (const auto &app : store.list())
                if (app.package_id == cached->package_name && app.state != State::removed) {
                    result.current = app;
                    if (app.state != State::installed || app.shell == ShellState::pending)
                        throw InstallError("AETHER_UPDATE_STATE",
                                           "Finish the existing installation or repair before updating.");
                    if (!cached->version_code || *cached->version_code <= app.version_code)
                        throw InstallError(
                            "AETHER_UPDATE_VERSION",
                            "This version is already installed, or is older than the installed app.");
                    break;
                }
            result.available = true;
        } catch (const std::exception &error) {
            result.code = error_code(error);
            result.message = error.what();
        }
        return result;
    }
    void set_text(HWND control, const std::wstring &text) {
        const auto length = GetWindowTextLengthW(control);
        std::wstring previous(std::size_t(length) + 1, L'\0');
        GetWindowTextW(control, previous.data(), length + 1);
        previous.resize(length);
        if (previous != text)
            SetWindowTextW(control, text.c_str());
    }
    void permission_text() {
        if (!permission_window || !shown.package)
            return;
        set_text(permission_app, display(shown.package->presentation.label));
        std::wstring text;
        for (const auto &name : shown.package->declared_permissions)
            text += display(name, "Unnamed permission") + L"\r\n";
        if (text.empty())
            text = L"No Android permissions declared.";
        // Preserve selection and scrolling during automatic reads.
        DWORD start = 0, end = 0;
        SendMessageW(declarations, EM_GETSEL, reinterpret_cast<WPARAM>(&start),
                     reinterpret_cast<LPARAM>(&end));
        const auto line = SendMessageW(declarations, EM_GETFIRSTVISIBLELINE, 0, 0);
        set_text(declarations, text);
        SendMessageW(declarations, EM_SETSEL, start, end);
        const auto next = SendMessageW(declarations, EM_GETFIRSTVISIBLELINE, 0, 0);
        SendMessageW(declarations, EM_LINESCROLL, 0, line - next);
    }
    void apply(Observation value) {
        if (!value.code.empty())
            ++failures;
        else if (was_failed)
            ++recoveries;
        was_failed = !value.code.empty();
        if (value.package && value.package != shown.package) {
            auto next = std::make_unique<Icon>(value.package->presentation.bitmap, px(88));
            SendMessageW(picture, STM_SETICON, reinterpret_cast<WPARAM>(next->value), 0);
            SendMessageW(window, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(next->value));
            if (permission_window)
                SendMessageW(permission_window, WM_SETICON, ICON_SMALL,
                             reinterpret_cast<LPARAM>(next->value));
            icon = std::move(next);
            set_text(title, display(value.package->presentation.label));
            set_text(subtitle, L"Version " + display(value.package->version_name, "not declared"));
            if (!ready_ms)
                ready_ms = GetTickCount64() - started;
        }
        if (uninstalling && value.current) {
            if (!icon) {
                icon = std::make_unique<Icon>(apk::fallback_icon(), px(88));
                SendMessageW(picture, STM_SETICON, reinterpret_cast<WPARAM>(icon->value), 0);
            }
            set_text(title, display(value.current->display_name, value.current->package_id));
            set_text(subtitle, L"Version " + display(value.current->version_name, "not declared"));
        }
        if (!uninstalling && !value.package && !shown.package) {
            icon = std::make_unique<Icon>(apk::fallback_icon(), px(88));
            SendMessageW(picture, STM_SETICON, reinterpret_cast<WPARAM>(icon->value), 0);
            set_text(title, L"Package unavailable");
        }
        set_text(action, uninstalling ? L"Uninstall" : value.current ? L"Update" : L"Install");
        set_text(status, value.available
                             ? (uninstalling ? L"Remove this app. Other apps and Aether will stay installed."
                                : value.current ? L"Update this app. Your data and permissions will be kept."
                                              : L"Install this app on your PC.")
                             : display(value.message, "Checking again automatically."));
        EnableWindow(action, value.available);
        EnableWindow(permissions, value.package != nullptr);
        shown = std::move(value);
        permission_text();
        if (!visible) {
            visible = true;
            STARTUPINFOW startup{};
            startup.cb = sizeof(startup);
            GetStartupInfoW(&startup);
            const auto show =
                (startup.dwFlags & STARTF_USESHOWWINDOW) && startup.wShowWindow == SW_SHOWMINNOACTIVE
                    ? SW_SHOWMINNOACTIVE
                    : SW_SHOWNORMAL;
            ShowWindow(window, show);
            if (show == SW_SHOWNORMAL)
                SetFocus(uninstalling ? cancel : action);
        }
    }
    void show_permissions() {
        if (permission_window || !shown.package || busy || finished)
            return;
        permission_window = make_window(L"Aether - Permissions", 600, 640, window);
        if (!permission_window)
            throw InstallError("AETHER_SHELL_DIALOG", "Cannot open permissions");
        SendMessageW(permission_window, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(icon->value));
        control(permission_window, L"STATIC", L"Permissions", 0, 32, 26, 480, 38, 0, heading);
        control(permission_window, L"BUTTON", L"Back", BS_OWNERDRAW | WS_TABSTOP,
                544, 12, 40, 40, close_id);
        permission_app =
            control(permission_window, L"STATIC", display(shown.package->presentation.label).c_str(),
                    SS_NOPREFIX, 32, 70, 536, 25, 0, small);
        const auto choices = shown.current ? shown.current->permissions : grants;
        auto clock = control(permission_window, L"BUTTON", L"Basic time access", BS_AUTOCHECKBOX, 32, 120,
                             520, 26, 200);
        SendMessageW(clock, BM_SETCHECK, choices & security::installed_clock ? BST_CHECKED : BST_UNCHECKED,
                     0);
        EnableWindow(clock, FALSE);
        control(permission_window, L"STATIC", L"Required to run the app. No personal information is shared.",
                0, 57, 152, 510, 24, 0, small);
        files_check = control(permission_window, L"BUTTON", L"Private app files",
                              BS_AUTOCHECKBOX | WS_TABSTOP, 32, 194, 520, 26, private_files_id);
        SendMessageW(files_check, BM_SETCHECK,
                     choices & security::installed_files ? BST_CHECKED : BST_UNCHECKED, 0);
        EnableWindow(files_check, !shown.current);
        control(permission_window, L"STATIC",
                L"Only this app's private storage. Your other files stay private.", 0, 57, 226, 510, 24, 0,
                small);
        wall_clock_check = control(permission_window, L"BUTTON", L"Wall-clock date and time",
                                   BS_AUTOCHECKBOX | WS_TABSTOP, 32, 264, 520, 26, wall_clock_id);
        SendMessageW(wall_clock_check, BM_SETCHECK,
                     choices & security::installed_wall_clock ? BST_CHECKED : BST_UNCHECKED, 0);
        EnableWindow(wall_clock_check, !shown.current);
        control(permission_window, L"STATIC", L"Current calendar date and time. Optional; denied unless selected.",
                0, 57, 296, 510, 24, 0, small);
        control(permission_window, L"STATIC",
                shown.package->format == apk::PreviewFormat::xapk ? L"BASE APK DECLARATIONS"
                                                                  : L"REQUESTED BY THE APP",
                0, 32, 352, 536, 22, 0, small);
        control(permission_window, L"STATIC", L"Android declarations do not grant Windows access.", 0, 32,
                377, 536, 23, 0, small);
        declarations = control(permission_window, L"EDIT", L"",
                               ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL | WS_TABSTOP, 32, 414,
                               536, 112, 230, small);
        control(permission_window, L"STATIC",
                shown.current ? L"Existing choices are preserved. Edit them in App settings."
                              : L"Other device and personal-data access stays blocked.",
                0, 32, 538, 536, 22, 0, small);
        control(permission_window, L"BUTTON", L"Privacy", BS_OWNERDRAW | WS_TABSTOP, 20, 580, 100, 40,
                privacy_id);
        auto done = control(permission_window, L"BUTTON", L"Done", BS_OWNERDRAW | WS_TABSTOP, 456, 580, 112,
                            40, IDOK);
        permission_text();
        permission_minimized = IsIconic(window) != FALSE;
        EnableWindow(window, FALSE);
        ShowWindow(window, SW_HIDE);
        ShowWindow(permission_window, permission_minimized ? SW_SHOWMINNOACTIVE : SW_SHOWNORMAL);
        if (!permission_minimized)
            SetFocus(shown.current ? done : files_check);
    }
    void close_permissions() {
        if (!permission_window)
            return;
        if (!shown.current) {
            grants = security::installed_clock;
            if (SendMessageW(files_check, BM_GETCHECK, 0, 0) == BST_CHECKED)
                grants |= security::installed_files;
            if (SendMessageW(wall_clock_check, BM_GETCHECK, 0, 0) == BST_CHECKED)
                grants |= security::installed_wall_clock;
        }
        auto previous = permission_window;
        permission_window = nullptr;
        EnableWindow(window, TRUE);
        DestroyWindow(previous);
        ShowWindow(window, permission_minimized ? SW_SHOWMINNOACTIVE : SW_SHOWNORMAL);
        if (!permission_minimized) {
            SetActiveWindow(window);
            SetFocus(permissions);
        }
    }
    void start_install() {
        if (busy || finished || !shown.available || (!uninstalling && !shown.identity))
            return;
        busy = true;
        cancelled = false;
        ++attempts;
        selected_current = shown.current;
        const auto expected_identity = shown.identity.value_or(shell::IconDigest{});
        if (uninstalling) {
            keep_data = SendMessageW(keep_check, BM_GETCHECK, 0, 0) == BST_CHECKED;
            ShowWindow(keep_check, SW_HIDE);
        }
        const auto permissions_value = shown.current ? shown.current->permissions : grants;
        commit_started = GetTickCount64();
        for (const auto item : {permissions, cancel, action, subtitle})
            ShowWindow(item, SW_HIDE);
        EnableWindow(close, FALSE);
        MoveWindow(picture, px(276), px(58), px(88), px(88), TRUE);
        SetWindowLongPtrW(title, GWL_STYLE, GetWindowLongPtrW(title, GWL_STYLE) | SS_CENTER);
        MoveWindow(title, px(36), px(160), px(568), px(40), TRUE);
        SetWindowLongPtrW(status, GWL_STYLE, GetWindowLongPtrW(status, GWL_STYLE) | SS_CENTER);
        MoveWindow(status, px(36), px(244), px(568), px(30), TRUE);
        set_text(title, uninstalling ? L"Uninstalling app" : selected_current ? L"Updating app" : L"Installing app");
        set_text(status, uninstalling ? L"Removing app files and Windows entries" : L"Checking package integrity");
        ShowWindow(progress, SW_SHOW);
        SendMessageW(progress, PBM_SETMARQUEE, TRUE, 20);
        // Freeze the displayed source identity and update target. No timer result
        // may silently change what the user just selected; one write attempt only.
        write = std::async(std::launch::async, [this, expected_identity, permissions_value] {
            Outcome result;
            try {
                if (read.valid())
                    read.wait();
                if (uninstalling) {
                    PackageStore store(root, PackageStore::Access::write);
                    result.app = store.uninstall(uninstall_id, keep_data);
                    return result;
                }
                shell::IconSource input(source, true);
                if (input.identity() != expected_identity)
                    throw InstallError("AETHER_INSTALL_SOURCE_CHANGED",
                                       "The selected package changed. Open it again to review the new app.");
                auto prepared = PreparedInstall::read(source);
                result.hash = prepared.preview().inspection.sha256;
                if (!input.unchanged())
                    throw InstallError("AETHER_INSTALL_SOURCE_CHANGED",
                                       "The selected package changed while being read.");
                result.app = prepared.commit(root, permissions_value, selected_current,
                                             [this](InstallStage value) { stage.store(value); });
            } catch (const std::exception &error) {
                result.code = error_code(error);
                result.message = error.what();
            }
            return result;
        });
    }
    void complete(Outcome value) {
        outcome = std::move(value);
        busy = false;
        finished = true;
        install_ms = GetTickCount64() - commit_started;
        SendMessageW(progress, PBM_SETMARQUEE, FALSE, 0);
        ShowWindow(progress, SW_HIDE);
        set_text(title, uninstalling ? (outcome.app ? L"App uninstalled" : L"Couldn't uninstall app")
                                    : outcome.app ? (selected_current ? L"App updated" : L"App installed")
                                                  : L"Couldn't install app");
        MoveWindow(status, px(36), px(212), px(568), px(62), TRUE);
        set_text(status, outcome.app && uninstalling
                             ? (keep_data ? L"App removed. Private data and diagnostic history were kept."
                                          : L"App, private data and diagnostic history removed.")
                             : outcome.app ? L"All files are saved and Windows registration is complete."
                                     : display(outcome.message, uninstalling ? "Uninstallation failed."
                                                                           : "Installation failed."));
        set_text(action, L"Close");
        ShowWindow(action, SW_SHOW);
        EnableWindow(action, TRUE);
        EnableWindow(close, TRUE);
        SetFocus(action);
    }
    void tick() {
        if (busy) {
            const wchar_t *label = L"Checking package integrity";
            switch (stage.load()) {
            case InstallStage::writing:
                label = L"Saving application files";
                break;
            case InstallStage::registering:
                label = L"Adding the app to Windows";
                break;
            case InstallStage::finishing:
            case InstallStage::complete:
                label = L"Finishing installation";
                break;
            default:
                break;
            }
            set_text(status, uninstalling ? L"Removing app files and Windows entries" : label);
            if (!write.valid() || write.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
                return;
            complete(write.get());
            return;
        }
        if (finished)
            return;
        if (read.valid()) {
            if (read.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
                return;
            apply(read.get());
        }
        const auto now = GetTickCount64();
        if (!reads || now - last_read >= 1000) {
            last_read = now;
            ++reads;
            read = std::async(std::launch::async, [this] { return observe(); });
        }
    }
    static LRESULT CALLBACK procedure(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam) {
        auto *self = reinterpret_cast<Installer *>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        if (message == WM_NCCREATE) {
            self = static_cast<Installer *>(reinterpret_cast<CREATESTRUCTW *>(lparam)->lpCreateParams);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
        }
        if (!self)
            return DefWindowProcW(hwnd, message, wparam, lparam);
        try {
            switch (message) {
            case WM_NCHITTEST:
                return header_hit_test(hwnd, lparam, self->dpi);
            case WM_ERASEBKGND: {
                RECT rect{};
                GetClientRect(hwnd, &rect);
                FillRect(reinterpret_cast<HDC>(wparam), &rect, self->brush);
                return 1;
            }
            case WM_CTLCOLORSTATIC:
            case WM_CTLCOLOREDIT:
            case WM_CTLCOLORBTN:
                SetTextColor(reinterpret_cast<HDC>(wparam),
                             reinterpret_cast<HWND>(lparam) == self->title ? ink : muted);
                SetBkColor(reinterpret_cast<HDC>(wparam), background);
                return reinterpret_cast<LRESULT>(self->brush);
            case WM_DRAWITEM:
                dialog_style::draw_button(*reinterpret_cast<DRAWITEMSTRUCT *>(lparam), self->normal,
                                          self->dpi, wparam == action_id || wparam == IDOK);
                return TRUE;
            case WM_TIMER:
                if (hwnd == self->window)
                    self->tick();
                return 0;
            case WM_COMMAND:
                if (hwnd == self->permission_window) {
                    if (LOWORD(wparam) == IDOK || LOWORD(wparam) == IDCANCEL || LOWORD(wparam) == close_id)
                        self->close_permissions();
                    else if (LOWORD(wparam) == privacy_id)
                        show_privacy_dialog(hwnd);
                } else if (LOWORD(wparam) == action_id || LOWORD(wparam) == IDOK) {
                    if (self->finished)
                        DestroyWindow(hwnd);
                    else
                        self->start_install();
                } else if (LOWORD(wparam) == permissions_id)
                    self->show_permissions();
                else if ((LOWORD(wparam) == IDCANCEL || LOWORD(wparam) == close_id) && !self->busy)
                    DestroyWindow(hwnd);
                return 0;
            case WM_CLOSE:
                if (hwnd == self->permission_window)
                    self->close_permissions();
                else if (!self->busy)
                    DestroyWindow(hwnd);
                return 0;
            case WM_DESTROY:
                if (hwnd == self->window)
                    PostQuitMessage(0);
                return 0;
            }
        } catch (const std::exception &error) {
            // Exceptions never cross the Win32 callback boundary or trigger a retry of a write.
            if (self->busy && !self->write.valid()) {
                self->complete({{}, {}, error_code(error), error.what()});
                return 0;
            }
            self->shown.available = false;
            EnableWindow(self->action, FALSE);
            self->set_text(self->status, display(error.what(), "Installer unavailable."));
            if (!self->visible) {
                self->visible = true;
                ShowWindow(self->window, SW_SHOWNORMAL);
            }
        }
        return DefWindowProcW(hwnd, message, wparam, lparam);
    }
    int run(bool json) {
        const auto previous_dpi = SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        create();
        MSG message{};
        while (GetMessageW(&message, nullptr, 0, 0) > 0) {
            const auto active = permission_window ? permission_window : window;
            if (!IsDialogMessageW(active, &message)) {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
        if (read.valid())
            read.get();
        if (previous_dpi)
            SetThreadDpiAwarenessContext(previous_dpi);
        if (json) {
            std::cout << "{\"schemaVersion\":1,\"operation\":"
                      << json_quote(uninstalling ? "uninstall" : selected_current ? "update" : "install")
                      << ",\"cancelled\":" << (cancelled ? "true" : "false")
                      << ",\"writeAttempts\":" << attempts
                      << ",\"fullInspections\":0,\"metadataReads\":" << reads
                      << ",\"metadataExtractions\":" << extractions << ",\"metadataReadyMs\":" << ready_ms
                      << ",\"installMs\":" << install_ms << ",\"previewReads\":" << reads
                      << ",\"previewReadFailures\":" << failures
                      << ",\"previewReadRecoveries\":" << recoveries << ",\"previewReadConcurrencyLimit\":1"
                      << ",\"reviewedSha256\":" << json_quote(outcome.hash);
            if (selected_current && !uninstalling)
                std::cout << ",\"reviewedCurrentSha256\":" << json_quote(selected_current->sha256)
                          << ",\"reviewedAppId\":" << json_quote(selected_current->id);
            if (outcome.app)
                std::cout << ",\"app\":" << outcome.app->json();
            else if (!cancelled)
                std::cout << ",\"code\":" << json_quote(outcome.code)
                          << ",\"message\":" << json_quote(outcome.message);
            std::cout << "}\n";
        }
        return cancelled || outcome.app ? 0 : 1;
    }
};
} // namespace
int show_install_dialog(const std::filesystem::path &source, const std::filesystem::path &root, bool json) {
    return Installer(source, root).run(json);
}
int show_uninstall_dialog(const std::filesystem::path &root, const std::string &id, bool json) {
    return Installer({}, root, id).run(json);
}
} // namespace aether::install
