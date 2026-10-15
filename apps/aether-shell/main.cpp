#include "aether/common/text.hpp"
#include "aether/install/cli.hpp"
#include "aether/install/runtime.hpp"
#include "aether/install/store.hpp"
#include "app_dialog.hpp"
#include "install_dialog.hpp"
#include "privacy_dialog.hpp"
#include <Windows.h>
#include <commctrl.h>
#include <future>
#include <iostream>
#include <optional>
#include <set>
#include <shellapi.h>

#pragma comment(                                                                                             \
    linker,                                                                                                  \
    "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='amd64' publicKeyToken='6595b64144ccf1df' language='*'\"")

namespace {
using namespace aether;
using namespace aether::install;
constexpr int keep_button = 100, delete_button = 101;
struct Observation {
    std::wstring content;
    bool available = false;
};
struct Confirmation {
    std::filesystem::path root;
    std::string id;
    std::future<Observation> read;
    std::wstring shown;
    bool available = true;
    ULONGLONG last_read = 0;
    Confirmation(std::filesystem::path path, std::string identity)
        : root(std::move(path)), id(std::move(identity)) {}

    Observation observe() const {
        try {
            PackageStore store(root);
            const auto app = store.info(id);
            if (app.state == State::updating || app.state == State::update_committed ||
                app.state == State::update_rolled_back)
                return {L"This app has an unfinished update or update cleanup. Complete Aether's explicit "
                        L"repair before uninstalling it. No removal has been attempted.",
                        false};
            const bool present = app.state == State::installed || app.state == State::data_retained;
            return {
                L"Package: " + utf16(app.package_id) + L"\nVersion: " + utf16(app.version_name) + L"\n\n" +
                    (present ? L"Choose whether to keep this app's private data and diagnostic history. "
                               L"Other apps and the shared Aether runtime will stay installed."
                             : L"This application is no longer installed. You can close this confirmation."),
                present};
        } catch (const std::exception &) {
            return {L"The current app status could not be read. Checking again automatically. "
                    L"Your confirmation stays open; no removal has been attempted.",
                    false};
        }
    }
    void update(HWND window) {
        if (read.valid()) {
            if (read.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
                return; // Coalesce timer ticks while one read is in flight.
            const auto value = read.get();
            if (shown != value.content) {
                shown = value.content;
                SendMessageW(window, TDM_UPDATE_ELEMENT_TEXT, TDE_CONTENT,
                             reinterpret_cast<LPARAM>(shown.c_str()));
            }
            if (available != value.available) {
                available = value.available;
                SendMessageW(window, TDM_ENABLE_BUTTON, keep_button, available);
                SendMessageW(window, TDM_ENABLE_BUTTON, delete_button, available);
            }
        }
        const auto now = GetTickCount64();
        if (now - last_read >= 1000) {
            last_read = now;
            read = std::async(std::launch::async, [this] { return observe(); });
        }
    }
    static HRESULT CALLBACK callback(HWND window, UINT notification, WPARAM choice, LPARAM, LONG_PTR data) {
        auto &self = *reinterpret_cast<Confirmation *>(data);
        try {
            if (notification == TDN_CREATED) {
                SendMessageW(window, TDM_ENABLE_BUTTON, keep_button, self.available);
                SendMessageW(window, TDM_ENABLE_BUTTON, delete_button, self.available);
                STARTUPINFOW startup{};
                startup.cb = sizeof(startup);
                GetStartupInfoW(&startup);
                if ((startup.dwFlags & STARTF_USESHOWWINDOW) && startup.wShowWindow == SW_SHOWMINNOACTIVE)
                    ShowWindow(window, SW_SHOWMINNOACTIVE);
            } else if (notification == TDN_TIMER)
                self.update(window);
            else if (notification == TDN_BUTTON_CLICKED &&
                     (choice == keep_button || choice == delete_button) && !self.available)
                return S_FALSE;
            return S_OK;
        } catch (...) {
            self.available = false;
            SendMessageW(window, TDM_ENABLE_BUTTON, keep_button, FALSE);
            SendMessageW(window, TDM_ENABLE_BUTTON, delete_button, FALSE);
            return S_OK;
        }
    }
};
int confirm(const std::filesystem::path &root, const InstalledApp &app) {
    Confirmation state{root, app.id};
    const auto initial = state.observe();
    state.shown = initial.content;
    state.available = initial.available;
    const auto initial_content = state.shown;
    const auto title = utf16(app.display_name.empty() ? app.package_id : app.display_name);
    const auto instruction = L"Uninstall " + title + L"?";
    const TASKDIALOG_BUTTON buttons[] = {
        {keep_button, L"Uninstall and keep data\nRemove the app and its Windows entries. Keep its private "
                      L"data and diagnostic history."},
        {delete_button, L"Uninstall and delete data\nRemove the app, its Windows entries, private data and "
                        L"diagnostic history."}};
    TASKDIALOGCONFIG config{};
    config.cbSize = sizeof(config);
    config.hInstance = GetModuleHandleW(nullptr);
    config.dwFlags = TDF_USE_COMMAND_LINKS | TDF_ALLOW_DIALOG_CANCELLATION | TDF_CALLBACK_TIMER;
    config.dwCommonButtons = TDCBF_CANCEL_BUTTON;
    config.pszWindowTitle = L"Aether - Uninstall app";
    config.pszMainInstruction = instruction.c_str();
    config.pszContent = initial_content.c_str();
    config.cButtons = static_cast<UINT>(std::size(buttons));
    config.pButtons = buttons;
    config.nDefaultButton = IDCANCEL;
    config.pfCallback = Confirmation::callback;
    config.lpCallbackData = reinterpret_cast<LONG_PTR>(&state);
    int selected = IDCANCEL;
    const auto status = TaskDialogIndirect(&config, &selected, nullptr, nullptr);
    if (FAILED(status))
        throw InstallError("AETHER_SHELL_DIALOG", "Windows could not open the uninstall confirmation");
    return selected;
}
int run(const std::vector<std::string> &arguments, bool json) {
    if (!arguments.empty() && arguments[0] == "privacy") {
        if (arguments.size() > 2 || (arguments.size() == 2 && arguments[1] != "--json"))
            throw InstallError("AETHER_CLI_USAGE", "Use privacy [--json] to read the offline guide");
        show_privacy_dialog();
        if (json)
            std::cout << "{\"schemaVersion\":1,\"operation\":\"privacy\",\"closed\":true}\n";
        return 0;
    }
    if (arguments.empty() ||
        (arguments[0] != "launch" && arguments[0] != "relaunch" && arguments[0] != "uninstall" &&
         arguments[0] != "install" && arguments[0] != "settings" && arguments[0] != "diagnostics"))
        throw InstallError(
            "AETHER_CLI_USAGE",
            "Use privacy, install --apk PATH, or launch/relaunch/uninstall/settings/diagnostics --app-id ID");
    const bool installing = arguments[0] == "install";
    std::string id, root_text, source;
    std::set<std::string> seen;
    for (std::size_t index = 1; index < arguments.size(); ++index) {
        const auto &option = arguments[index];
        if (!seen.insert(option).second)
            throw InstallError("AETHER_CLI_USAGE", "An option was specified more than once");
        if (option == "--json")
            continue;
        if ((option != (installing ? "--apk" : "--app-id") && option != "--store") ||
            index + 1 == arguments.size() || arguments[index + 1].empty() ||
            arguments[index + 1].starts_with('-'))
            throw InstallError("AETHER_CLI_USAGE",
                               "Install requires an APK path; app actions require an installed ID. "
                               "Permission bypass flags are not accepted");
        (option == "--app-id" ? id : option == "--apk" ? source : root_text) = arguments[++index];
    }
    const auto root = root_text.empty() ? default_store_root() : std::filesystem::path(utf16(root_text));
    if (arguments[0] == "relaunch" && !root_text.empty())
        throw InstallError("AETHER_CLI_USAGE",
                           "relaunch resolves its registered store; --store is not accepted");
    if (installing) {
        if (source.empty())
            throw InstallError("AETHER_CLI_USAGE", "install requires --apk PATH");
        auto path = std::filesystem::absolute(std::filesystem::path(utf16(source))).lexically_normal();
        if (path.native().size() >= 32700)
            throw InstallError("AETHER_INSTALL_PATH", "The selected APK path exceeds the Windows path limit");
        // Source paths are independent of the shorter protected store paths.
        // Use the documented extended Unicode syntax for long selected files.
        const auto native = path.native();
        if (native.size() >= MAX_PATH && !native.starts_with(L"\\\\?\\"))
            path = native.starts_with(L"\\\\") ? L"\\\\?\\UNC\\" + native.substr(2) : L"\\\\?\\" + native;
        return show_install_dialog(path, root, json);
    }
    if (!valid_app_id(id))
        throw InstallError("AETHER_INSTALL_ID",
                           "The Windows entry must select a valid installed application ID");
    if (arguments[0] == "launch" || arguments[0] == "relaunch")
        return dispatch_cli(arguments, json).value();
    if (arguments[0] == "settings" || arguments[0] == "diagnostics")
        return show_app_dialog(root, id, arguments[0] == "settings", json);
    const auto app = [&] {
        PackageStore store(root);
        return store.info(id);
    }();
    const auto choice = confirm(root, app);
    if (choice != keep_button && choice != delete_button) {
        if (json)
            std::cout << "{\"schemaVersion\":1,\"operation\":\"uninstall\",\"cancelled\":true}\n";
        return 0;
    }
    PackageStore store(root, PackageStore::Access::write);
    const auto result = store.uninstall(id, choice == keep_button);
    if (json)
        std::cout << "{\"schemaVersion\":1,\"operation\":\"uninstall\",\"cancelled\":false,\"app\":"
                  << result.json() << "}\n";
    return 0;
}
} // namespace

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    bool json = false;
    std::optional<aether::install::RuntimeUseLease> runtime;
    try {
        int count = 0;
        auto **raw = CommandLineToArgvW(GetCommandLineW(), &count);
        if (!raw)
            throw aether::install::InstallError("AETHER_CLI_USAGE", "Cannot read Windows launch arguments");
        struct Release {
            wchar_t **value;
            ~Release() { LocalFree(value); }
        } release{raw};
        std::vector<std::string> arguments;
        for (int index = 1; index < count; ++index) {
            arguments.push_back(aether::utf8(raw[index]));
            json = json || arguments.back() == "--json";
        }
        runtime.emplace();
        return run(arguments, json);
    } catch (const std::exception &error) {
        const auto *installation = dynamic_cast<const aether::install::InstallError *>(&error);
        const auto *inspection = dynamic_cast<const aether::apk::InspectError *>(&error);
        const auto code = installation ? installation->code
                          : inspection ? inspection->diagnostic.code
                                       : "AETHER_SHELL_FAILED";
        if (json)
            std::cout << "{\"schemaVersion\":1,\"code\":" << aether::json_quote(code)
                      << ",\"message\":" << aether::json_quote(error.what()) << "}\n";
        else
            MessageBoxW(nullptr, aether::utf16(std::string(error.what()) + "\n\n" + code).c_str(),
                        L"Aether - Application could not complete", MB_OK | MB_ICONERROR);
        return code == "AETHER_CLI_USAGE" ? 2 : 1;
    }
}
