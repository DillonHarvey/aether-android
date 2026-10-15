#include "app_dialog.hpp"
#include "aether/apk/artwork.hpp"
#include "aether/common/text.hpp"
#include "aether/install/diagnostics.hpp"
#include "aether/install/troubleshooting.hpp"
#include "app_dialog_ids.h"
#include "privacy_dialog.hpp"
#include "privacy_ids.h"
#include <Windows.h>
#include <algorithm>
#include <future>
#include <iostream>
#include <shobjidl.h>
#include <wrl/client.h>

namespace aether::install {
namespace {
using Microsoft::WRL::ComPtr;
constexpr UINT_PTR poll_timer = 1;
constexpr std::uint32_t supported = security::installed_clock | security::installed_files;

std::string error_code(const std::exception &error) {
    if (const auto *value = dynamic_cast<const InstallError *>(&error))
        return value->code;
    if (const auto *value = dynamic_cast<const apk::InspectError *>(&error))
        return value->diagnostic.code;
    return "AETHER_SHELL_FAILED";
}
std::wstring display(std::string_view text) { return utf16(apk::clean_display_name(text, "Aether app")); }
std::wstring safe_report_text(std::string_view content) {
    const auto raw = utf16(content);
    std::wstring result;
    for (const auto c : raw) {
        if (c == 0x061c || c == 0x200e || c == 0x200f || (c >= 0x202a && c <= 0x202e) ||
            (c >= 0x2066 && c <= 0x2069))
            continue;
        if (c == L'\n')
            result += L"\r\n";
        else
            result += c < 32 || (c >= 0x7f && c <= 0x9f) || c == 0x2028 || c == 0x2029 ? L' ' : c;
        if (result.size() >= 30000) {
            if (result.back() >= 0xd800 && result.back() <= 0xdbff)
                result.pop_back();
            result += L"\r\n[Display truncated. Save report for the complete findings.]";
            break;
        }
    }
    return result;
}
std::wstring report_text(const AppDiagnostics &report) {
    return safe_report_text(report.text() + "\nSaved timekeeping permission: " +
                            ((report.app.permissions & security::installed_clock) ? "allowed" : "denied") +
                            "\nSaved private-files permission: " +
                            ((report.app.permissions & security::installed_files) ? "allowed" : "denied"));
}
void text(HWND window, int id, const std::wstring &value) {
    const auto control = GetDlgItem(window, id);
    std::wstring old(static_cast<std::size_t>(GetWindowTextLengthW(control)) + 1, L'\0');
    old.resize(static_cast<std::size_t>(GetWindowTextW(control, old.data(), static_cast<int>(old.size()))));
    if (old == value)
        return;
    if (id != IDC_APP_REPORT) {
        SetWindowTextW(control, value.c_str());
        return;
    }
    DWORD start = 0, end = 0;
    SendMessageW(control, EM_GETSEL, reinterpret_cast<WPARAM>(&start), reinterpret_cast<LPARAM>(&end));
    const auto first_line = SendMessageW(control, EM_GETFIRSTVISIBLELINE, 0, 0);
    SendMessageW(control, WM_SETREDRAW, FALSE, 0);
    SetWindowTextW(control, value.c_str());
    SendMessageW(control, EM_SETSEL, std::min<std::size_t>(start, value.size()),
                 static_cast<LPARAM>(std::min<std::size_t>(end, value.size())));
    SendMessageW(control, EM_LINESCROLL, 0, first_line - SendMessageW(control, EM_GETFIRSTVISIBLELINE, 0, 0));
    SendMessageW(control, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(control, nullptr, TRUE);
}
void com_check(HRESULT result) {
    if (FAILED(result))
        throw InstallError("AETHER_DIAGNOSTICS_OUTPUT", "Windows could not select a diagnostics destination");
}
std::optional<std::filesystem::path> choose_output(HWND window, const std::string &id, bool bundle = false) {
    ComPtr<IFileSaveDialog> dialog;
    com_check(CoCreateInstance(CLSID_FileSaveDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&dialog)));
    // No Windows probe file, working-directory change, recent-document entry or
    // overwrite offer. The existing exporter still enforces CREATE_NEW.
    com_check(dialog->SetOptions(FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST | FOS_NOREADONLYRETURN |
                                 FOS_NOTESTFILECREATE | FOS_DONTADDTORECENT | FOS_NOCHANGEDIR |
                                 FOS_STRICTFILETYPES));
    const COMDLG_FILTERSPEC types[] = {
        {bundle ? L"JSON troubleshooting bundle" : L"JSON diagnostics report", L"*.json"}};
    com_check(dialog->SetFileTypes(1, types));
    com_check(dialog->SetDefaultExtension(L"json"));
    com_check(dialog->SetTitle(bundle ? L"Aether - Save troubleshooting to a new file"
                                      : L"Aether - Save diagnostics to a new file"));
    com_check(dialog->SetOkButtonLabel(L"Save new report"));
    const auto filename = std::wstring(bundle ? L"Aether-troubleshooting-" : L"Aether-diagnostics-") +
                          utf16(id.substr(0, 8)) + L".json";
    com_check(dialog->SetFileName(filename.c_str()));
    const auto selected = dialog->Show(window);
    if (selected == HRESULT_FROM_WIN32(ERROR_CANCELLED))
        return {};
    com_check(selected);
    ComPtr<IShellItem> item;
    com_check(dialog->GetResult(&item));
    PWSTR raw = nullptr;
    com_check(item->GetDisplayName(SIGDN_FILESYSPATH, &raw));
    struct Release {
        PWSTR value;
        ~Release() { CoTaskMemFree(value); }
    } release{raw};
    return std::filesystem::path(raw);
}
struct Observation {
    std::optional<AppDiagnostics> report;
    std::string code;
};
struct Outcome {
    std::optional<InstalledApp> app;
    bool exported = false;
    std::wstring message;
    std::string code;
};
struct CollectionResult {
    std::optional<TroubleshootingReport> report;
    std::string code;
};
struct TroubleshootingDialog {
    std::filesystem::path root;
    std::string id;
    std::future<Observation> &parent_read;
    bool &parent_collecting;
    TroubleshootingOptions choices;
    std::optional<TroubleshootingReport> shown;
    std::future<CollectionResult> collection;
    std::future<Outcome> write;
    bool choosing = false, closed = false;
    unsigned exports = 0;
    std::wstring action = L"Select details, then collect a preview.";

    bool busy() const { return collection.valid() || write.valid() || choosing; }
    bool can_save() const { return !busy() && shown && choices == shown->options; }
    void render(HWND window) const {
        text(window, IDC_APP_REPORT, safe_report_text(shown ? shown->text() : troubleshooting_plan(choices)));
        text(window, IDC_APP_ACTION_STATUS, action);
        for (const int control : {IDC_BUNDLE_HOST, IDC_BUNDLE_AUDIT, IDC_BUNDLE_COLLECT, IDCANCEL})
            EnableWindow(GetDlgItem(window, control), !busy());
        EnableWindow(GetDlgItem(window, IDC_APP_SAVE), can_save());
    }
    void collect(HWND window) {
        if (busy())
            return;
        parent_collecting = true;
        try {
            collection = std::async(std::launch::async, [path = root, identity = id, options = choices,
                                                         prior = std::move(parent_read)]() mutable {
                try {
                    if (prior.valid())
                        prior.get();
                    PackageStore store(path);
                    return CollectionResult{collect_troubleshooting(store, identity, options), {}};
                } catch (const std::exception &error) {
                    return CollectionResult{{}, error_code(error)};
                }
            });
        } catch (...) {
            parent_collecting = false;
            throw;
        }
        // A failed new collection must never enable export of the old preview.
        shown.reset();
        action = L"Collecting only the selected details...";
        render(window);
    }
    void save(HWND window) {
        if (!can_save())
            return;
        const auto report = *shown;
        choosing = true;
        render(window);
        std::optional<std::filesystem::path> destination;
        try {
            destination = choose_output(window, id, true);
        } catch (...) {
            choosing = false;
            throw;
        }
        choosing = false;
        if (destination) {
            write = std::async(std::launch::async, [report, path = *destination] {
                try {
                    export_troubleshooting(report, path);
                    return Outcome{{}, true, L"Saved the captured bundle. Review it before sharing.", {}};
                } catch (const std::exception &error) {
                    return Outcome{{},
                                   false,
                                   L"Bundle export failed (" + utf16(error_code(error)) +
                                       L"). No automatic retry.",
                                   error_code(error)};
                }
            });
            action = L"Saving the reviewed bundle...";
        }
        render(window);
    }
    void poll(HWND window) {
        if (collection.valid() &&
            collection.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
            parent_collecting = false;
            auto result = collection.get();
            shown = std::move(result.report);
            action = shown ? L"Captured preview ready. Save writes exactly this report to a new file."
                           : L"Collection unavailable (" + utf16(result.code) + L"). Your choices are kept.";
        }
        if (write.valid() && write.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
            const auto result = write.get();
            exports += result.exported;
            action = result.message;
        }
        render(window);
    }
    static INT_PTR CALLBACK callback(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
        auto *self = reinterpret_cast<TroubleshootingDialog *>(GetWindowLongPtrW(window, DWLP_USER));
        if (message == WM_INITDIALOG) {
            self = reinterpret_cast<TroubleshootingDialog *>(lparam);
            SetWindowLongPtrW(window, DWLP_USER, reinterpret_cast<LONG_PTR>(self));
        }
        if (!self)
            return FALSE;
        try {
            if (message == WM_INITDIALOG) {
                SendDlgItemMessageW(window, IDC_APP_REPORT, EM_SETLIMITTEXT, 32767, 0);
                if (!SetTimer(window, poll_timer, 100, nullptr))
                    throw InstallError("AETHER_SHELL_DIALOG", "Cannot observe troubleshooting collection");
                self->render(window);
                SetFocus(GetDlgItem(window, IDCANCEL));
                return FALSE;
            }
            if (message == WM_TIMER && wparam == poll_timer) {
                self->poll(window);
                return TRUE;
            }
            if (message == WM_COMMAND && HIWORD(wparam) == BN_CLICKED) {
                const auto control = LOWORD(wparam);
                if ((control == IDC_BUNDLE_HOST || control == IDC_BUNDLE_AUDIT) && !self->busy()) {
                    self->choices = {IsDlgButtonChecked(window, IDC_BUNDLE_HOST) == BST_CHECKED,
                                     IsDlgButtonChecked(window, IDC_BUNDLE_AUDIT) == BST_CHECKED};
                    self->action = L"Choices changed. Collect a matching preview before saving.";
                    self->render(window);
                } else if (control == IDC_BUNDLE_COLLECT)
                    self->collect(window);
                else if (control == IDC_APP_SAVE)
                    self->save(window);
                else if (control == IDCANCEL && !self->busy())
                    DestroyWindow(window);
                return TRUE;
            }
            if (message == WM_CLOSE) {
                if (!self->busy())
                    DestroyWindow(window);
                return TRUE;
            }
            if (message == WM_DESTROY) {
                KillTimer(window, poll_timer);
                self->closed = true;
                return TRUE;
            }
        } catch (const std::exception &error) {
            self->action = L"Troubleshooting action failed (" + utf16(error_code(error)) + L").";
            self->render(window);
        }
        return FALSE;
    }
    unsigned show(HWND owner) {
        EnableWindow(owner, FALSE);
        struct Restore {
            HWND owner;
            bool &collecting;
            ~Restore() {
                EnableWindow(owner, TRUE);
                collecting = false;
            }
        } restore{owner, parent_collecting};
        const auto window =
            CreateDialogParamW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(IDD_APP_TROUBLESHOOT), owner,
                               callback, reinterpret_cast<LPARAM>(this));
        if (!window)
            throw InstallError("AETHER_SHELL_DIALOG", "Cannot open troubleshooting choices");
        ShowWindow(window, IsIconic(owner) ? SW_SHOWMINNOACTIVE : SW_SHOWNORMAL);
        MSG message{};
        while (!closed) {
            if (GetMessageW(&message, nullptr, 0, 0) <= 0) {
                DestroyWindow(window);
                throw InstallError("AETHER_SHELL_DIALOG", "Troubleshooting message loop ended unexpectedly");
            }
            if (!IsDialogMessageW(window, &message)) {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
        return exports;
    }
};
struct AppDialog {
    std::filesystem::path root;
    std::string id;
    bool settings = false, editing = false, fresh = false, choosing = false, closed = false,
         collecting_bundle = false;
    std::uint32_t draft = 0;
    std::optional<PermissionReview> reviewed;
    std::optional<AppDiagnostics> shown;
    std::future<Observation> read;
    std::future<Outcome> write;
    ULONGLONG last_read = 0;
    std::wstring action;
    std::string read_error, action_code;
    unsigned permission_writes = 0, exports = 0, failed_actions = 0, bundles_exported = 0;

    bool conflict() const {
        return reviewed && shown &&
               (reviewed->sha256 != shown->app.sha256 || reviewed->permissions != shown->app.permissions);
    }
    bool writable() const {
        return settings && fresh && shown && shown->app.state == State::installed &&
               shown->app.shell != ShellState::pending &&
               std::any_of(shown->checks.begin(), shown->checks.end(), [](const auto &check) {
                   return check.name == "package" && check.status == "pass";
               });
    }
    bool can_apply() const {
        return !write.valid() && !choosing && writable() && reviewed && !conflict() &&
               draft != reviewed->permissions;
    }
    void adopt(HWND window) {
        if (!shown)
            return;
        reviewed = PermissionReview{shown->app.sha256, shown->app.permissions};
        draft = reviewed->permissions;
        editing = false;
        if (settings) {
            CheckDlgButton(window, IDC_APP_CLOCK,
                           draft & security::installed_clock ? BST_CHECKED : BST_UNCHECKED);
            CheckDlgButton(window, IDC_APP_FILES,
                           draft & security::installed_files ? BST_CHECKED : BST_UNCHECKED);
        }
    }
    void render(HWND window) const {
        const bool busy = write.valid() || choosing;
        if (shown) {
            text(window, IDC_APP_NAME,
                 display(shown->app.display_name.empty() ? shown->app.package_id : shown->app.display_name));
            text(window, IDC_APP_REPORT, report_text(*shown));
        }
        std::wstring status;
        if (!fresh)
            status = read_error.empty()
                         ? L"Reading app status automatically..."
                         : L"Status unavailable (" + utf16(read_error) +
                               L"). Checking again automatically. The last report remains visible.";
        else if (settings && conflict())
            status = L"The app or saved permissions changed. Your edits are kept. Discard edits to review "
                     L"the current values.";
        else if (settings && !writable())
            status = L"Permissions cannot be changed in this app state. Review this app's diagnostics.";
        else if (settings && editing)
            status = L"Your permission choices stay selected. Apply permissions saves them once.";
        else
            status = L"App status updates automatically. Reports exclude private files, logs and host paths.";
        text(window, IDC_APP_READ_STATUS, status);
        text(window, IDC_APP_ACTION_STATUS, action);
        EnableWindow(GetDlgItem(window, IDC_APP_SAVE), !busy && fresh && shown.has_value());
        EnableWindow(GetDlgItem(window, IDC_APP_TROUBLESHOOT), !busy && fresh && shown.has_value());
        EnableWindow(GetDlgItem(window, IDCANCEL), !write.valid());
        if (settings) {
            EnableWindow(GetDlgItem(window, IDC_APP_CLOCK), !busy && reviewed.has_value());
            EnableWindow(GetDlgItem(window, IDC_APP_FILES), !busy && reviewed.has_value());
            EnableWindow(GetDlgItem(window, IDC_APP_APPLY), can_apply());
            EnableWindow(GetDlgItem(window, IDC_APP_DISCARD), !busy && fresh && editing && shown.has_value());
        }
    }
    void poll(HWND window) {
        if (write.valid()) {
            if (write.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
                return;
            const auto result = write.get();
            action = result.message;
            action_code = result.code;
            if (!result.code.empty())
                ++failed_actions;
            if (result.exported)
                ++exports;
            if (result.app) {
                ++permission_writes;
                reviewed = PermissionReview{result.app->sha256, result.app->permissions};
                draft = result.app->permissions;
                editing = false;
                fresh = false;
            }
            last_read = 0;
        }
        if (read.valid()) {
            if (read.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
                return; // One outstanding read; timer ticks never overlap it.
            auto result = read.get();
            fresh = result.report.has_value();
            read_error = result.code;
            if (result.report) {
                shown = std::move(result.report);
                if (!editing)
                    adopt(window);
            }
        }
        render(window);
        const auto now = GetTickCount64();
        if (!write.valid() && !collecting_bundle && now - last_read >= 1000) {
            last_read = now;
            read = std::async(std::launch::async, [path = root, identity = id] {
                try {
                    PackageStore store(path);
                    return Observation{store.diagnostics(identity), {}};
                } catch (const std::exception &error) {
                    return Observation{{}, error_code(error)};
                }
            });
        }
    }
    void apply(HWND window) {
        if (!can_apply())
            return;
        const auto review = *reviewed;
        const auto permissions = draft;
        // A completed but undisplayed read cannot replace the user's review.
        // Drain that read off the UI thread before the one write attempt.
        write = std::async(std::launch::async, [path = root, identity = id, review, permissions,
                                                prior = std::move(read)]() mutable {
            try {
                if (prior.valid())
                    prior.get();
                PackageStore store(path, PackageStore::Access::existing_write);
                auto app = store.set_permissions(identity, permissions, supported & ~permissions, review);
                return Outcome{
                    std::move(app), false, L"Permissions saved. Changes apply to the next launch.", {}};
            } catch (const std::exception &error) {
                return Outcome{{},
                               false,
                               display(error.what()) + L" (" + utf16(error_code(error)) +
                                   L"). No automatic retry.",
                               error_code(error)};
            }
        });
        action = L"Saving permissions...";
        action_code.clear();
        render(window);
    }
    void save(HWND window) {
        if (write.valid() || choosing || !fresh || !shown)
            return;
        // Export exactly the report displayed when the user chose Save report.
        // Parent polling continues while the Windows destination picker is open.
        const auto report = *shown;
        choosing = true;
        render(window);
        std::optional<std::filesystem::path> destination;
        try {
            destination = choose_output(window, id);
        } catch (...) {
            choosing = false;
            throw;
        }
        choosing = false;
        if (!destination) {
            render(window);
            return;
        }
        write =
            std::async(std::launch::async, [report, path = *destination, prior = std::move(read)]() mutable {
                try {
                    if (prior.valid())
                        prior.get();
                    export_diagnostics(report, path);
                    return Outcome{{}, true, L"Saved the report reviewed when Save report was selected.", {}};
                } catch (const std::exception &error) {
                    return Outcome{{},
                                   false,
                                   display(error.what()) + L" (" + utf16(error_code(error)) +
                                       L"). No automatic retry.",
                                   error_code(error)};
                }
            });
        action = L"Saving diagnostics to the selected new file...";
        action_code.clear();
        render(window);
    }
    void close(HWND window) {
        if (write.valid() || choosing)
            return;
        if (settings && editing && reviewed && draft != reviewed->permissions &&
            MessageBoxW(window, L"Discard your unsaved permission changes and close?",
                        L"Aether - Unsaved settings", MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2) != IDYES)
            return;
        DestroyWindow(window);
    }
    void troubleshoot(HWND window) {
        if (write.valid() || choosing || !fresh || !shown)
            return;
        choosing = true;
        render(window);
        try {
            TroubleshootingDialog dialog{root, id, read, collecting_bundle};
            bundles_exported += dialog.show(window);
        } catch (...) {
            choosing = false;
            throw;
        }
        choosing = false;
        action = L"Troubleshooting closed.";
        render(window);
    }
    static INT_PTR CALLBACK callback(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
        auto *self = reinterpret_cast<AppDialog *>(GetWindowLongPtrW(window, DWLP_USER));
        if (message == WM_INITDIALOG) {
            self = reinterpret_cast<AppDialog *>(lparam);
            SetWindowLongPtrW(window, DWLP_USER, reinterpret_cast<LONG_PTR>(self));
        }
        if (!self)
            return FALSE;
        try {
            if (message == WM_INITDIALOG) {
                SendDlgItemMessageW(window, IDC_APP_REPORT, EM_SETLIMITTEXT, 32767, 0);
                self->render(window);
                if (!SetTimer(window, poll_timer, 100, nullptr))
                    throw InstallError("AETHER_SHELL_DIALOG", "Cannot start automatic app status reads");
                self->poll(window);
                SetFocus(GetDlgItem(window, IDCANCEL));
                return FALSE;
            }
            if (message == WM_TIMER && wparam == poll_timer) {
                self->poll(window);
                return TRUE;
            }
            if (message == WM_COMMAND && HIWORD(wparam) == BN_CLICKED) {
                switch (LOWORD(wparam)) {
                case IDC_PRIVACY_OPEN:
                    if (!self->choosing) {
                        self->choosing = true;
                        struct Reset {
                            bool &value;
                            ~Reset() { value = false; }
                        } reset{self->choosing};
                        show_privacy_dialog(window);
                    }
                    self->render(window);
                    return TRUE;
                case IDC_APP_CLOCK:
                case IDC_APP_FILES:
                    if (self->settings && self->reviewed && !self->write.valid() && !self->choosing) {
                        self->draft = (IsDlgButtonChecked(window, IDC_APP_CLOCK) == BST_CHECKED
                                           ? security::installed_clock
                                           : 0) |
                                      (IsDlgButtonChecked(window, IDC_APP_FILES) == BST_CHECKED
                                           ? security::installed_files
                                           : 0);
                        self->editing = true;
                        self->render(window);
                    }
                    return TRUE;
                case IDC_APP_DISCARD:
                    if (self->settings && !self->write.valid() && !self->choosing && self->fresh) {
                        self->adopt(window);
                        self->render(window);
                    }
                    return TRUE;
                case IDC_APP_APPLY:
                    self->apply(window);
                    return TRUE;
                case IDC_APP_SAVE:
                    self->save(window);
                    return TRUE;
                case IDC_APP_TROUBLESHOOT:
                    self->troubleshoot(window);
                    return TRUE;
                case IDCANCEL:
                    self->close(window);
                    return TRUE;
                }
            }
            if (message == WM_CLOSE) {
                self->close(window);
                return TRUE;
            }
            if (message == WM_DESTROY) {
                KillTimer(window, poll_timer);
                self->closed = true;
                PostQuitMessage(0);
                return TRUE;
            }
        } catch (const std::exception &error) {
            ++self->failed_actions;
            self->action_code = error_code(error);
            self->action = display(error.what()) + L" (" + utf16(self->action_code) + L")";
            self->render(window);
        } catch (...) {
            SetDlgItemTextW(window, IDC_APP_ACTION_STATUS,
                            L"The operation could not complete. No automatic write retry.");
        }
        return FALSE;
    }
};
} // namespace

int show_app_dialog(const std::filesystem::path &root, const std::string &id, bool settings, bool json) {
    const auto initialized = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(initialized))
        throw InstallError("AETHER_SHELL_DIALOG", "Cannot initialize native app controls");
    struct Apartment {
        ~Apartment() { CoUninitialize(); }
    } apartment;
    AppDialog state;
    state.root = root;
    state.id = id;
    state.settings = settings;
    const auto window = CreateDialogParamW(
        GetModuleHandleW(nullptr), MAKEINTRESOURCEW(settings ? IDD_APP_SETTINGS : IDD_APP_DIAGNOSTICS),
        nullptr, AppDialog::callback, reinterpret_cast<LPARAM>(&state));
    if (!window)
        throw InstallError("AETHER_SHELL_DIALOG", "Windows could not open this app's controls");
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    GetStartupInfoW(&startup);
    ShowWindow(window, (startup.dwFlags & STARTF_USESHOWWINDOW) && startup.wShowWindow == SW_SHOWMINNOACTIVE
                           ? SW_SHOWMINNOACTIVE
                           : SW_SHOWNORMAL);
    MSG message{};
    while (!state.closed) {
        const auto result = GetMessageW(&message, nullptr, 0, 0);
        if (result <= 0) {
            if (IsWindow(window))
                DestroyWindow(window);
            if (result < 0)
                throw InstallError("AETHER_SHELL_DIALOG", "The native app-controls message loop failed");
            break;
        }
        if (!IsDialogMessageW(window, &message)) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
    if (json)
        std::cout << "{\"schemaVersion\":1,\"operation\":"
                  << json_quote(settings ? "settings" : "diagnostics")
                  << ",\"closed\":true,\"permissionWrites\":" << state.permission_writes
                  << ",\"reportsExported\":" << state.exports << ",\"failedActions\":" << state.failed_actions
                  << ",\"bundlesExported\":" << state.bundles_exported
                  << ",\"lastActionCode\":" << json_quote(state.action_code)
                  << ",\"reportAvailable\":" << (state.shown ? "true" : "false") << "}\n";
    return 0;
}
} // namespace aether::install
