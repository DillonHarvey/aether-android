#include "aether/common/text.hpp"
#include "aether/host/windows/unique_handle.hpp"
#include "aether/install/runtime_setup.hpp"
#include "aether/install/shell.hpp"
#include "aether/install/store.hpp"
#include "privacy_dialog.hpp"
#include "privacy_ids.h"
#include <Windows.h>
#include <array>
#include <commctrl.h>
#include <functional>
#include <future>
#include <iostream>
#include <optional>
#include <set>
#include <shellapi.h>
#include <shlobj.h>

#pragma comment(                                                                                             \
    linker,                                                                                                  \
    "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

namespace {
using namespace aether;
using namespace aether::install;
constexpr int accept_button = 100, destination_button = 101, repair_button = 102;
struct Arguments {
    std::string operation = "install";
    std::filesystem::path root;
    bool yes = false, json = false, explorer = false;
    DWORD controller = 0;
};
void require(bool ok, const char *message) {
    if (!ok)
        throw InstallError("AETHER_CLI_USAGE", message);
}
std::filesystem::path image_path() {
    std::array<wchar_t, 32768> path{};
    const auto size = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    require(size && size < path.size(), "Cannot resolve the installer path");
    return std::filesystem::path(std::wstring(path.data(), size));
}
Arguments arguments(bool &json) {
    int count = 0;
    auto **raw = CommandLineToArgvW(GetCommandLineW(), &count);
    require(raw != nullptr, "Cannot read installer arguments");
    struct Free {
        wchar_t **value;
        ~Free() { LocalFree(value); }
    } release{raw};
    for (int n = 1; n < count; ++n)
        if (std::wstring_view(raw[n]) == L"--json")
            json = true;
    Arguments result;
    bool operation = false;
    std::set<std::wstring> seen;
    for (int n = 1; n < count; ++n) {
        const std::wstring value(raw[n]);
        if (!value.starts_with(L"--")) {
            require(!operation, "AetherSetup accepts one operation");
            result.operation = utf8(value);
            operation = true;
            continue;
        }
        require(seen.insert(value).second, "An installer option was repeated");
        if (value == L"--json")
            result.json = true;
        else if (value == L"--yes")
            result.yes = true;
        else if (value == L"--offer-explorer")
            result.explorer = true;
        else {
            require((value == L"--root" || value == L"--cleanup-parent") && n + 1 < count,
                    "Use install, upgrade, repair, uninstall or status with --root PATH; --yes is explicit "
                    "unattended consent");
            const std::wstring argument(raw[++n]);
            if (value == L"--root")
                result.root = argument;
            else {
                require(!argument.empty() && argument.size() <= 10 &&
                            argument.find_first_not_of(L"0123456789") == std::wstring::npos,
                        "Invalid controller process ID");
                const auto pid = std::stoull(argument);
                require(pid > 0 && pid <= MAXDWORD, "Invalid controller process ID");
                result.controller = static_cast<DWORD>(pid);
            }
        }
    }
    require(result.operation == "install" || result.operation == "upgrade" || result.operation == "repair" ||
                result.operation == "uninstall" || result.operation == "status",
            "Use AetherSetup install, upgrade, repair, uninstall or status");
    require(!result.explorer || result.operation == "install",
            "Explorer consent is only accepted during installation");
    require(!result.controller || (result.operation == "uninstall" && result.json),
            "A cleanup controller requires uninstall --json");
    require(result.operation != "status" || (!result.yes && !result.controller), "Status is read-only");
    if (result.root.empty()) {
        if (result.operation == "install" || result.operation == "upgrade" || result.operation == "repair") {
            PWSTR path = nullptr;
            require(SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_DEFAULT, nullptr, &path)),
                    "Cannot resolve your local application directory");
            result.root = std::filesystem::path(path) / L"Programs" / L"Aether";
            CoTaskMemFree(path);
        } else
            result.root = image_path().parent_path();
    }
    if (!operation &&
        GetFileAttributesW((result.root / L"runtime.registry").c_str()) != INVALID_FILE_ATTRIBUTES)
        result.operation = "upgrade";
    require(!result.explorer || result.operation == "install",
            "Upgrades preserve Explorer registration; Explorer consent is only accepted for a fresh install");
    return result;
}
struct Review {
    Arguments &args;
    std::future<RuntimeSetupStatus> read;
    ULONGLONG started = 0;
    std::wstring content;
    bool available = false, explorer = false;
    explicit Review(Arguments &value) : args(value), explorer(value.explorer) {}
    void refresh(HWND window) {
        if (read.valid() && read.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
            const auto status = read.get();
            available = status.available;
            std::wstring next =
                (args.operation == "install" ? L"Install location: " : L"Runtime location: ") +
                args.root.wstring() + L"\n\n" + utf16(status.detail);
            if (args.operation == "install" || args.operation == "upgrade" || args.operation == "repair")
                next += L"\n\nUnsigned development build. Android compatibility is limited. "
                        L"Setup does not run an Android app.";
            if (next != content) {
                content = std::move(next);
                SendMessageW(window, TDM_SET_ELEMENT_TEXT, TDE_CONTENT,
                             reinterpret_cast<LPARAM>(content.c_str()));
            }
            SendMessageW(window, TDM_ENABLE_BUTTON, accept_button, available);
        }
        if (!read.valid() && GetTickCount64() - started >= 1000) {
            started = GetTickCount64();
            const auto root = args.root;
            const bool installing = args.operation == "install";
            const bool upgrading = args.operation == "upgrade";
            const bool repairing = args.operation == "repair";
            read = std::async(std::launch::async, [root, installing, upgrading, repairing] {
                return repairing   ? inspect_runtime_repair(root)
                       : upgrading ? inspect_runtime_upgrade(root)
                                   : inspect_runtime_setup(root, installing);
            });
        }
    }
    void destination(HWND window) {
        IFileOpenDialog *picker = nullptr;
        if (FAILED(
                CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&picker))))
            return;
        struct Release {
            IFileOpenDialog *value;
            ~Release() { value->Release(); }
        } release{picker};
        (void)picker->SetOptions(FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST | FOS_NOCHANGEDIR);
        (void)picker->SetTitle(L"Choose a parent folder for the new Aether directory");
        if (SUCCEEDED(picker->Show(window))) {
            IShellItem *item = nullptr;
            if (SUCCEEDED(picker->GetResult(&item))) {
                PWSTR path = nullptr;
                if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &path))) {
                    // The new runtime directory itself must not exist.
                    args.root = std::filesystem::path(path) / L"Aether";
                    CoTaskMemFree(path);
                    if (read.valid()) {
                        (void)read.get();
                    }
                    available = false;
                    started = 0;
                    SendMessageW(window, TDM_ENABLE_BUTTON, accept_button, FALSE);
                }
                item->Release();
            }
        }
    }
};
HRESULT CALLBACK review_callback(HWND window, UINT notification, WPARAM first, LPARAM, LONG_PTR context) {
    auto &review = *reinterpret_cast<Review *>(context);
    try {
        if (notification == TDN_CREATED) {
            STARTUPINFOW startup{};
            startup.cb = sizeof(startup);
            GetStartupInfoW(&startup);
            if ((startup.dwFlags & STARTF_USESHOWWINDOW) && startup.wShowWindow == SW_SHOWMINNOACTIVE)
                ShowWindow(window, SW_SHOWMINNOACTIVE);
            SendMessageW(window, TDM_ENABLE_BUTTON, accept_button, FALSE);
            review.refresh(window);
        } else if (notification == TDN_TIMER)
            review.refresh(window);
        else if (notification == TDN_VERIFICATION_CLICKED)
            review.explorer = first != 0;
        else if (notification == TDN_BUTTON_CLICKED) {
            if (first == IDC_PRIVACY_OPEN) {
                show_privacy_dialog(window);
                return S_FALSE;
            }
            if (first == destination_button) {
                review.destination(window);
                return S_FALSE;
            }
            if (first == accept_button && !review.available)
                return S_FALSE;
        }
    } catch (const std::exception &error) {
        review.available = false;
        review.content = utf16(error.what());
        SendMessageW(window, TDM_SET_ELEMENT_TEXT, TDE_CONTENT,
                     reinterpret_cast<LPARAM>(review.content.c_str()));
        SendMessageW(window, TDM_ENABLE_BUTTON, accept_button, FALSE);
    }
    return notification == TDN_BUTTON_CLICKED && first == IDC_PRIVACY_OPEN ? S_FALSE : S_OK;
}
bool consent(Arguments &args) {
    Review review(args);
    const bool installing = args.operation == "install";
    const bool upgrading = args.operation == "upgrade";
    const bool repairing = args.operation == "repair";
    const TASKDIALOG_BUTTON buttons[] = {
        {accept_button, installing  ? L"Install"
                        : upgrading ? L"Upgrade"
                        : repairing ? L"Repair"
                                    : L"Uninstall"},
        {IDC_PRIVACY_OPEN, L"Privacy..."},
        {upgrading ? repair_button : destination_button,
         upgrading ? L"Repair installed version..." : L"Choose location..."}};
    TASKDIALOGCONFIG dialog{sizeof(dialog)};
    dialog.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION | TDF_CALLBACK_TIMER | TDF_SIZE_TO_CONTENT |
                     TDF_CAN_BE_MINIMIZED | (args.explorer ? TDF_VERIFICATION_FLAG_CHECKED : 0);
    dialog.dwCommonButtons = TDCBF_CANCEL_BUTTON;
    dialog.pszWindowTitle = L"Aether runtime setup";
    dialog.pszMainInstruction = installing  ? L"Install Aether runtime?"
                                : upgrading ? L"Upgrade Aether runtime?"
                                : repairing ? L"Repair Aether runtime?"
                                            : L"Uninstall Aether runtime?";
    dialog.pszContent = L"Checking this installation...";
    dialog.pszVerificationText =
        installing ? L"Offer Aether package icons and Install with Aether (keep my selected default apps)"
                   : nullptr;
    dialog.cButtons = installing || upgrading ? 3 : 2;
    dialog.pButtons = buttons;
    dialog.nDefaultButton = IDCANCEL;
    dialog.pfCallback = review_callback;
    dialog.lpCallbackData = reinterpret_cast<LONG_PTR>(&review);
    int button = IDCANCEL;
    BOOL explorer = args.explorer ? TRUE : FALSE;
    const auto result = TaskDialogIndirect(&dialog, &button, nullptr, &explorer);
    if (FAILED(result))
        throw InstallError("AETHER_SETUP_UI", "Windows could not open the runtime setup confirmation");
    args.explorer = review.explorer;
    if (button == repair_button) {
        if (review.read.valid())
            (void)review.read.get();
        args.operation = "repair";
        return consent(args); // The repair review retains its own explicit confirmation.
    }
    return button == accept_button;
}
struct Outcome {
    std::string json;
    std::wstring message;
    int status = 0;
};
Outcome perform(const std::function<std::string()> &action) {
    try {
        return {action(), {}, 0};
    } catch (const std::exception &error) {
        const auto *install = dynamic_cast<const InstallError *>(&error);
        return {"{\"schemaVersion\":1,\"state\":\"failed\",\"code\":" +
                    json_quote(install ? install->code : "AETHER_SETUP_FAILED") +
                    ",\"message\":" + json_quote(error.what()) + '}',
                utf16(error.what()), 1};
    }
}
struct Commit {
    std::function<std::string()> action;
    bool installing, upgrading, repairing, handoff, done = false;
    std::future<Outcome> write;
    Outcome outcome;
    static HRESULT CALLBACK callback(HWND window, UINT event, WPARAM, LPARAM, LONG_PTR context) {
        auto &self = *reinterpret_cast<Commit *>(context);
        try {
            if (event == TDN_CREATED) {
                STARTUPINFOW startup{};
                startup.cb = sizeof(startup);
                GetStartupInfoW(&startup);
                if ((startup.dwFlags & STARTF_USESHOWWINDOW) && startup.wShowWindow == SW_SHOWMINNOACTIVE)
                    ShowWindow(window, SW_SHOWMINNOACTIVE);
                SendMessageW(window, TDM_ENABLE_BUTTON, IDCLOSE, FALSE);
                SendMessageW(window, TDM_SET_PROGRESS_BAR_MARQUEE, TRUE, 30);
                self.write = std::async(std::launch::async, [&self] { return perform(self.action); });
            } else if (event == TDN_TIMER && self.write.valid() &&
                       self.write.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
                self.outcome = self.write.get();
                self.done = true;
                SendMessageW(window, TDM_SET_PROGRESS_BAR_MARQUEE, FALSE, 0);
                SendMessageW(window, TDM_ENABLE_BUTTON, IDCLOSE, TRUE);
                if (self.handoff && !self.outcome.status) {
                    SendMessageW(window, TDM_CLICK_BUTTON, IDCLOSE, 0);
                    return S_OK;
                }
                const auto title = self.outcome.status ? L"Aether setup is incomplete"
                                   : self.installing   ? L"Aether runtime is installed"
                                   : self.upgrading    ? L"Aether runtime is upgraded"
                                   : self.repairing    ? L"Aether runtime is repaired"
                                                       : L"Aether runtime was removed";
                SendMessageW(window, TDM_SET_ELEMENT_TEXT, TDE_MAIN_INSTRUCTION,
                             reinterpret_cast<LPARAM>(title));
                if (!self.outcome.status)
                    self.outcome.message =
                        self.installing || self.upgrading || self.repairing
                            ? L"You can close this window. No Android app was started.\n\n"
                              L"For package icons, enable Explorer integration and choose Aether in Windows "
                              L"Default apps or Open with. Your selected default apps are kept until you "
                              L"change them."
                            : L"The shared runtime and its Windows registration were removed. "
                              L"Package journals were kept.";
                SendMessageW(window, TDM_SET_ELEMENT_TEXT, TDE_CONTENT,
                             reinterpret_cast<LPARAM>(self.outcome.message.c_str()));
            } else if (event == TDN_BUTTON_CLICKED && !self.done)
                return S_FALSE;
        } catch (const std::exception &error) {
            const auto *install = dynamic_cast<const InstallError *>(&error);
            self.outcome = {"{\"schemaVersion\":1,\"state\":\"failed\",\"code\":" +
                                json_quote(install ? install->code : "AETHER_SETUP_FAILED") +
                                ",\"message\":" + json_quote(error.what()) + '}',
                            utf16(error.what()), 1};
            self.done = true;
            SendMessageW(window, TDM_SET_PROGRESS_BAR_MARQUEE, FALSE, 0);
            SendMessageW(window, TDM_ENABLE_BUTTON, IDCLOSE, TRUE);
            SendMessageW(window, TDM_SET_ELEMENT_TEXT, TDE_MAIN_INSTRUCTION,
                         reinterpret_cast<LPARAM>(L"Aether setup is incomplete"));
            SendMessageW(window, TDM_SET_ELEMENT_TEXT, TDE_CONTENT,
                         reinterpret_cast<LPARAM>(self.outcome.message.c_str()));
        }
        return S_OK;
    }
};
Outcome commit_dialog(std::function<std::string()> action, const std::string &operation, bool handoff) {
    const bool installing = operation == "install", upgrading = operation == "upgrade",
               repairing = operation == "repair";
    Commit commit{std::move(action), installing, upgrading, repairing, handoff};
    TASKDIALOGCONFIG dialog{sizeof(dialog)};
    dialog.dwFlags = TDF_CALLBACK_TIMER | TDF_CAN_BE_MINIMIZED | TDF_SHOW_MARQUEE_PROGRESS_BAR;
    dialog.dwCommonButtons = TDCBF_CLOSE_BUTTON;
    dialog.pszWindowTitle = L"Aether runtime setup result";
    dialog.pszMainInstruction = installing  ? L"Installing Aether runtime"
                                : upgrading ? L"Upgrading Aether runtime"
                                : repairing ? L"Repairing Aether runtime"
                                            : L"Removing Aether runtime";
    dialog.pszContent = L"Checking the installation and applying your confirmed choice. Please wait.";
    dialog.pfCallback = Commit::callback;
    dialog.lpCallbackData = reinterpret_cast<LONG_PTR>(&commit);
    if (FAILED(TaskDialogIndirect(&dialog, nullptr, nullptr, nullptr)))
        throw InstallError("AETHER_SETUP_UI", "Windows could not display the runtime setup result");
    return std::move(commit.outcome);
}
void start_controller(const std::wstring &command) {
    auto mutable_command = command;
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION process{};
    const auto system = windows_powershell();
    if (!CreateProcessW(system.c_str(), mutable_command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                        nullptr, system.parent_path().c_str(), &startup, &process))
        throw InstallError("AETHER_SETUP_CONTROLLER", "Windows could not start the uninstall controller");
    host::UniqueHandle thread(process.hThread), child(process.hProcess);
    // This bootstrap must exit. The controller owns the confirmation/result.
}
} // namespace
int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    bool json = false;
    const auto com = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    struct Com {
        HRESULT value;
        ~Com() {
            if (SUCCEEDED(value))
                CoUninitialize();
        }
    } apartment{com};
    try {
        auto args = arguments(json);
        json = args.json;
        if (args.operation == "status") {
            const auto state = inspect_runtime_setup(args.root, false);
            std::cout << "{\"schemaVersion\":1,\"state\":" << json_quote(state.state)
                      << ",\"available\":" << (state.available ? "true" : "false")
                      << ",\"detail\":" << json_quote(state.detail) << "}\n";
            return state.available ? 0 : 1;
        }
        if (args.operation == "uninstall" && !args.controller &&
            CompareStringOrdinal(args.root.c_str(), -1, image_path().parent_path().c_str(), -1, TRUE) ==
                CSTR_EQUAL) {
            start_controller(runtime_uninstall_command(args.root, args.yes));
            if (json)
                std::cout << "{\"schemaVersion\":1,\"state\":\"controller-started\"}\n";
            return 0;
        }
        RuntimeBundle payload;
        if (args.operation == "install" || args.operation == "upgrade" || args.operation == "repair") {
            payload = read_runtime_bundle(image_path());
            if (payload.compatibility > install::current_runtime_compatibility ||
                ((args.operation == "upgrade" || args.operation == "repair") &&
                 payload.compatibility != install::current_runtime_compatibility))
                throw InstallError(
                    "AETHER_RUNTIME_COMPATIBILITY",
                    "This distribution does not declare a supported runtime compatibility contract");
        }
        if (!args.yes && !consent(args)) {
            std::cout << "{\"schemaVersion\":1,\"state\":\"cancelled\"}\n";
            return 2;
        }
        const auto action = [&]() -> std::string {
            if (args.operation == "install") {
                install_runtime(args.root, payload.files, args.explorer);
                return "{\"schemaVersion\":1,\"state\":\"ready\",\"root\":" +
                       json_quote(utf8(args.root.wstring())) + '}';
            }
            if (args.operation == "upgrade")
                return upgrade_runtime(args.root, payload);
            if (args.operation == "repair")
                return repair_runtime(args.root, payload);
            return remove_runtime(args.root, args.controller);
        };
        const auto outcome =
            args.yes ? perform(action) : commit_dialog(action, args.operation, args.controller != 0);
        std::cout << outcome.json << '\n';
        return outcome.status;
    } catch (const std::exception &error) {
        const auto *install = dynamic_cast<const InstallError *>(&error);
        const std::string code = install ? install->code : "AETHER_SETUP_FAILED";
        std::cout << "{\"schemaVersion\":1,\"state\":\"failed\",\"code\":" << json_quote(code)
                  << ",\"message\":" << json_quote(error.what()) << "}\n";
        if (!json)
            MessageBoxW(nullptr, utf16(error.what()).c_str(), L"Aether runtime setup", MB_OK | MB_ICONERROR);
        return 1;
    }
}
