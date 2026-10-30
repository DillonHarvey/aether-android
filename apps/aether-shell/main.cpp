#include "aether/common/text.hpp"
#include "aether/install/cli.hpp"
#include "aether/install/runtime.hpp"
#include "aether/install/store.hpp"
#include "aether/install/shell.hpp"
#include "aether/install/open_link.hpp"
#include "aether/install/link_activation.hpp"
#include "aether/install/file_activation.hpp"
#include "aether/install/open_file.hpp"
#include "app_dialog.hpp"
#include "install_dialog.hpp"
#include "privacy_dialog.hpp"
#include "notification_activation.hpp"
#include "link_dialog.hpp"
#include <Windows.h>
#include <commctrl.h>
#include <algorithm>
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
AppLaunchObserver failure_observer(bool json, bool &launch_failure_shown) {
    return [json, &launch_failure_shown](const AppLaunchFailure &failure) {
        if (json) return;
        const auto message = std::wstring(L"This app session could not complete.\n\n") +
            utf16(session_failure_code(failure.failure)) +
            L"\n\nReview local diagnostics for this app? No report is saved until you choose Save "
            L"report and a new destination. Private app files, memory and raw logs are excluded. "
            L"Nothing is uploaded. The app will not restart automatically.";
        const auto choice = MessageBoxW(nullptr, message.c_str(), L"Aether - App session ended",
                                        MB_YESNO | MB_ICONERROR | MB_DEFBUTTON2);
        launch_failure_shown = choice != 0;
        if (choice == IDYES) show_app_dialog(failure.store, failure.app_id, false, false, failure.failure);
    };
}
int run(const std::vector<std::string> &arguments, bool json, bool &launch_failure_shown) {
    const auto command = std::find_if(arguments.begin(), arguments.end(), [](const auto &argument) {
        return argument != "--json" && argument != "--verbose";
    });
    if (command != arguments.end() && (*command == "open-link" || *command == "open-file"))
        return dispatch_cli(arguments, json, failure_observer(json, launch_failure_shown),
                            [](const OpenLinkOptions &options) { return show_link_dialog(options); },
                            [](const OpenFileOptions &options) { return show_file_dialog(options); }).value();
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
    if (arguments[0] == "launch" || arguments[0] == "relaunch") {
        const auto observer = failure_observer(json, launch_failure_shown);
        return dispatch_cli(arguments, json, observer).value();
    }
    if (arguments[0] == "settings" || arguments[0] == "diagnostics")
        return show_app_dialog(root, id, arguments[0] == "settings", json);
    return show_uninstall_dialog(root, id, json);
}
} // namespace

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR raw_tail, int) {
    bool json = false;
    bool launch_failure_shown = false;
    bool notification_server = false;
    std::optional<aether::install::RuntimeUseLease> runtime;
    try {
        // This transport is recognized before argv/options or global --json.
        // Its raw payload can never select another command, store or grant.
        const std::wstring_view tail = raw_tail ? std::wstring_view(raw_tail) : std::wstring_view{};
        const std::u16string native_tail(tail.begin(), tail.end());
        if (const auto activation = aether::install::parse_file_activation(native_tail)) {
            aether::install::OpenFileOptions options;
            options.file = activation->file;
            options.app_id = activation->app_id;
            options.store = aether::install::registered_shell_store(activation->app_id);
            options.registered_activation = true;
            runtime.emplace(options.store);
            {
                aether::install::PackageStore store(options.store);
                options.mime_type = aether::install::registered_file_mime(store, activation->app_id, options.file);
            }
            return aether::install::dispatch_open_file(options, false,
                failure_observer(false, launch_failure_shown),
                [](const auto &request) { return aether::install::show_file_dialog(request); });
        }
        if (const auto activation = aether::install::parse_link_activation(native_tail)) {
            aether::install::OpenLinkOptions options;
            options.uri = activation->uri;
            options.app_id = activation->app_id;
            options.store = aether::install::registered_shell_store(activation->app_id);
            options.registered_activation = true;
            runtime.emplace(options.store);
            return aether::install::dispatch_open_link(options, false,
                failure_observer(false, launch_failure_shown),
                [](const auto &request) { return aether::install::show_link_dialog(request); });
        }
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
        notification_server = !arguments.empty() && arguments.front() == "notification-server";
        runtime.emplace();
        if (const auto result = aether::install::run_notification_server(arguments)) return *result;
        return run(arguments, json, launch_failure_shown);
    } catch (const std::exception &error) {
        if (notification_server) return 1; // COM activation failures never open an unsolicited dialog.
        const auto *installation = dynamic_cast<const aether::install::InstallError *>(&error);
        const auto *inspection = dynamic_cast<const aether::apk::InspectError *>(&error);
        const auto code = installation ? installation->code
                          : inspection ? inspection->diagnostic.code
                                       : "AETHER_SHELL_FAILED";
        if (json)
            std::cout << "{\"schemaVersion\":1,\"code\":" << aether::json_quote(code)
                      << ",\"message\":" << aether::json_quote(error.what()) << "}\n";
        else if (!launch_failure_shown)
            MessageBoxW(nullptr, aether::utf16(std::string(error.what()) + "\n\n" + code).c_str(),
                        L"Aether - Application could not complete", MB_OK | MB_ICONERROR);
        return code == "AETHER_CLI_USAGE" ? 2 : 1;
    }
}
