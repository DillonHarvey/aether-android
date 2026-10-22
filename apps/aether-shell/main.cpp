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
    return show_uninstall_dialog(root, id, json);
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
