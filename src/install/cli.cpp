#include "aether/install/cli.hpp"
#include "aether/common/text.hpp"
#include "aether/dex/fixture_hash.hpp"
#include "aether/host/window.hpp"
#include "aether/install/diagnostics.hpp"
#include "aether/install/explorer.hpp"
#include "aether/install/privacy.hpp"
#include "aether/install/runtime.hpp"
#include "aether/install/shell.hpp"
#include "aether/install/store.hpp"
#include "aether/install/troubleshooting.hpp"
#include <array>
#include <iostream>
#include <set>

namespace aether::install {
namespace {
void usage(bool condition, const char *message) {
    if (!condition)
        throw InstallError("AETHER_CLI_USAGE", message);
}
void output(const InstalledApp &app, std::string_view operation, bool json) {
    if (json)
        std::cout << "{\"schemaVersion\":1,\"operation\":" << json_quote(operation)
                  << ",\"app\":" << app.json() << "}\n";
    else
        std::cout << app.package_id << " (" << app.version_name << ")\nApp ID: " << app.id << "\n"
                  << app.json() << "\n";
}
int explorer_cli(const std::vector<std::string> &arguments, bool json) {
    std::set<std::string> seen;
    std::string action, store;
    bool command = false, yes = false;
    for (std::size_t index = 0; index < arguments.size(); ++index) {
        const auto &arg = arguments[index];
        if (arg == "--json" || arg == "--verbose" || arg == "--yes" || arg == "--store") {
            usage(seen.insert(arg).second, "An Explorer option was specified more than once");
            if (arg == "--yes")
                yes = true;
            if (arg == "--store") {
                usage(index + 1 < arguments.size() && !arguments[index + 1].empty() &&
                          !arguments[index + 1].starts_with('-'),
                      "--store requires an absolute local path");
                store = arguments[++index];
            }
        } else if (!command && arg == "explorer")
            command = true;
        else {
            usage(command && action.empty() &&
                      (arg == "status" || arg == "register" || arg == "repair" || arg == "remove"),
                  "Use explorer status, register, repair or remove; modifying commands require --yes");
            action = arg;
        }
    }
    usage(!action.empty(), "explorer requires status, register, repair or remove");
    usage(store.empty() || action == "register", "--store is only accepted by explorer register");
    usage(!yes || action != "status", "explorer status does not accept --yes");
    if (action != "status" && !yes)
        throw InstallError(
            "AETHER_INSTALL_CONFIRMATION_REQUIRED",
            "Explorer handler changes require --yes; existing .apk defaults and UserChoice are preserved");
    const auto operation = action == "status"     ? ExplorerOperation::status
                           : action == "register" ? ExplorerOperation::register_handler
                           : action == "repair"   ? ExplorerOperation::repair
                                                  : ExplorerOperation::remove;
    std::optional<std::filesystem::path> root;
    if (!store.empty())
        root = std::filesystem::path(utf16(store));
    const auto result = explorer_registration(operation, root);
    if (json)
        std::cout << result.json() << '\n';
    else
        std::cout << "Explorer integration: " << result.state
                  << "\nVerified: " << (result.verified ? "yes" : "no")
                  << "\nExisting .apk defaults and UserChoice are unchanged.\n";
    return 0;
}
} // namespace
std::optional<int> dispatch_cli(const std::vector<std::string> &arguments, bool json) {
    std::string command;
    for (const auto &arg : arguments) {
        if (arg == "--json" || arg == "--verbose")
            continue;
        command = arg;
        break;
    }
    if (command == "explorer")
        return explorer_cli(arguments, json);
    if (command == "runtime")
        return runtime_cli(arguments, json);
    if (command == "privacy") {
        std::set<std::string> seen;
        for (const auto &arg : arguments) {
            usage((arg == "privacy" || arg == "--json" || arg == "--verbose") && seen.insert(arg).second,
                  "Use privacy [--json] [--verbose]; no app, store, consent or output option is accepted");
        }
        std::cout << (json ? privacy_json() + '\n' : std::string(privacy_text()));
        return 0;
    }
    if (command != "install" && command != "list" && command != "info" && command != "uninstall" &&
        command != "repair" && command != "launch" && command != "settings" && command != "register" &&
        command != "update" && command != "relaunch" && command != "diagnostics" && command != "troubleshoot")
        return {};
    std::set<std::string> options;
    std::string id, store_path, package, expected_sha256, expected_current_sha256, report_path,
        expected_permissions;
    bool seen_command = false, dry_run = false, yes = false, developer = false;
    bool keep = false, remove = false, windows = false;
    TroubleshootingOptions collection;
    std::uint32_t allow = 0, deny = 0;
    for (std::size_t n = 0; n < arguments.size(); ++n) {
        const auto &arg = arguments[n];
        if (!seen_command && arg == command) {
            seen_command = true;
            continue;
        }
        if (arg.starts_with("--")) {
            usage(options.insert(arg).second, "An option was specified more than once");
            if (arg == "--json" || arg == "--verbose")
                continue;
            if (arg == "--dry-run") {
                dry_run = true;
                continue;
            }
            if (arg == "--yes") {
                yes = true;
                continue;
            }
            if (arg == "--include-host-details" || arg == "--include-audit-summaries") {
                (arg == "--include-host-details" ? collection.host_details : collection.audit_summaries) =
                    true;
                continue;
            }
            if (arg == "--developer-fixture") {
                developer = true;
                continue;
            }
            if (arg == "--windows") {
                windows = true;
                continue;
            }
            if (arg == "--keep-data") {
                keep = true;
                continue;
            }
            if (arg == "--delete-data") {
                remove = true;
                continue;
            }
            if (arg == "--allow-clock" || arg == "--deny-clock" || arg == "--allow-private-files" ||
                arg == "--deny-private-files") {
                const auto bit =
                    arg.ends_with("clock") ? security::installed_clock : security::installed_files;
                (arg.starts_with("--allow-") ? allow : deny) |= bit;
                continue;
            }
            if (arg == "--app-id" || arg == "--store" || arg == "--expected-sha256" ||
                arg == "--expected-current-sha256" || arg == "--output" || arg == "--expected-permissions") {
                usage(n + 1 < arguments.size() && !arguments[n + 1].empty() &&
                          !arguments[n + 1].starts_with('-'),
                      "Option requires a value");
                (arg == "--app-id"                 ? id
                 : arg == "--store"                ? store_path
                 : arg == "--expected-sha256"      ? expected_sha256
                 : arg == "--output"               ? report_path
                 : arg == "--expected-permissions" ? expected_permissions
                                                   : expected_current_sha256) = arguments[++n];
                continue;
            }
            usage(false, "Unknown package-store option");
        }
        usage(!arg.starts_with('-') && package.empty(), "Unexpected package-store argument");
        package = arg;
    }
    usage(!dry_run || command == "install" || command == "update" || command == "troubleshoot",
          "--dry-run requires install, update or troubleshoot");
    usage(report_path.empty() || command == "diagnostics" || command == "troubleshoot",
          "--output requires diagnostics or troubleshoot");
    usage(!(collection.host_details || collection.audit_summaries) || command == "troubleshoot",
          "Optional collection choices require troubleshoot");
    usage(command != "troubleshoot" || !dry_run || (!yes && report_path.empty()),
          "Troubleshooting previews do not accept --yes or --output");
    usage(command != "relaunch" || store_path.empty(),
          "relaunch resolves its registered store; --store is not accepted");
    usage(!developer || command == "install", "--developer-fixture requires install");
    usage(!(keep || remove) || command == "uninstall", "Data-retention options require uninstall");
    usage(!windows || (command == "install" && !dry_run), "--windows requires a confirmed install");
    usage(expected_sha256.empty() || ((command == "install" || command == "update") && !dry_run),
          "--expected-sha256 requires a confirmed installation or update");
    usage(expected_current_sha256.empty() || (command == "update" && !dry_run) ||
              (command == "settings" && (allow || deny) && yes),
          "--expected-current-sha256 requires a confirmed update or permission change");
    usage(expected_permissions.empty() || (command == "settings" && (allow || deny) && yes),
          "--expected-permissions requires a confirmed permission change");
    usage(command != "settings" || expected_current_sha256.empty() == expected_permissions.empty(),
          "Reviewed settings require both --expected-current-sha256 and --expected-permissions");
    std::optional<PermissionReview> permission_review;
    if (!expected_permissions.empty()) {
        std::uint32_t mask = 0;
        if (expected_permissions == "monotonic-clock")
            mask = security::installed_clock;
        else if (expected_permissions == "private-files")
            mask = security::installed_files;
        else if (expected_permissions == "monotonic-clock,private-files")
            mask = security::installed_clock | security::installed_files;
        else
            usage(expected_permissions == "none",
                  "Expected permissions must be none, monotonic-clock, private-files, or "
                  "monotonic-clock,private-files");
        permission_review = PermissionReview{expected_current_sha256, mask};
    }
    usage(!(allow || deny) || command == "settings" || windows,
          "Permission decisions require settings or --windows installation");
    usage(!windows || !deny, "Windows installation uses explicit grants with all other permissions denied");
    usage(!(allow & deny), "Cannot grant and deny the same permission");
    usage(!yes || command == "install" || command == "update" || command == "uninstall" ||
              command == "repair" || command == "register" || command == "troubleshoot" ||
              (command == "settings" && (allow || deny)),
          "--yes requires a modifying command or explicit troubleshooting collection");
    usage((command == "install" || command == "update") ? !package.empty() : package.empty(),
          "install/update require exactly one APK path; other store commands accept no positional arguments");
    usage((command == "info" || command == "uninstall" || command == "launch" || command == "settings" ||
           command == "register" || command == "update" || command == "relaunch" ||
           command == "diagnostics" || command == "troubleshoot")
              ? !id.empty()
              : id.empty(),
          "info/uninstall/launch/settings/register/update/relaunch/diagnostics/troubleshoot require "
          "--app-id; repair "
          "operates on interrupted "
          "transactions");
    if (!id.empty() && !valid_app_id(id))
        throw InstallError("AETHER_INSTALL_ID", "App ID must be exactly 32 lowercase hexadecimal characters");
    if (command == "install") {
        const auto candidate = preview(utf16(package));
        if (dry_run) {
            usage(!yes && !developer, "Install previews do not accept confirmation flags");
            std::cout << (json ? candidate.json() + "\n"
                               : candidate.inspection.text(false) + "\n" + candidate.signing.text() + "\n" +
                                     candidate.reason + "\n");
            return 0;
        }
        if (!candidate.installable || (developer && candidate.inspection.sha256 != dex::fixture::apk_sha256))
            throw InstallError("AETHER_INSTALL_UNSUPPORTED",
                               developer ? "--developer-fixture requires the exact first-party APK"
                                         : candidate.reason);
        if (!yes || (!developer && expected_sha256.empty()))
            throw InstallError("AETHER_INSTALL_CONFIRMATION_REQUIRED",
                               "Inspect with install --dry-run, then confirm with --yes and "
                               "--expected-sha256 HASH (or use Aether's native APK installer)");
        if (!expected_sha256.empty() &&
            (expected_sha256.size() != 64 ||
             expected_sha256.find_first_not_of("0123456789abcdef") != std::string::npos))
            throw InstallError("AETHER_INSTALL_CONFIRMATION_REQUIRED",
                               "Use the lowercase SHA-256 from the package preview");
        if (!expected_sha256.empty() && candidate.inspection.sha256 != expected_sha256)
            throw InstallError("AETHER_INSTALL_SOURCE_CHANGED",
                               "The APK differs from the reviewed checksum; inspect and confirm it again");
    }
    if (command == "uninstall") {
        usage(keep != remove, "uninstall requires exactly one of --keep-data or --delete-data");
        if (!yes)
            throw InstallError(
                "AETHER_INSTALL_CONFIRMATION_REQUIRED",
                "Uninstall was not confirmed; pass --yes with the explicit data-retention choice");
    }
    if (command == "repair" && !yes)
        throw InstallError(
            "AETHER_INSTALL_CONFIRMATION_REQUIRED",
            "Repair changes the registry and cleans interrupted transactions; pass --yes to confirm");
    if (command == "register" && !yes)
        throw InstallError("AETHER_INSTALL_CONFIRMATION_REQUIRED",
                           "Adding Start and Windows Installed apps entries requires --yes");
    if (command == "settings" && (allow || deny) && !yes)
        throw InstallError("AETHER_INSTALL_CONFIRMATION_REQUIRED",
                           "Permission changes require an explicit decision and --yes");
    const auto root = store_path.empty() ? default_store_root() : std::filesystem::path(utf16(store_path));
    if (command == "troubleshoot") {
        if (!yes) {
            if (!report_path.empty())
                throw InstallError(
                    "AETHER_TROUBLESHOOT_CONFIRMATION_REQUIRED",
                    "Review the selected collection choices, then pass --yes to collect or export");
            PackageStore store(root);
            const auto app = store.info(id);
            std::cout << (json ? troubleshooting_preview(app, collection) + '\n'
                               : "App ID: " + app.id + '\n' + troubleshooting_plan(collection) +
                                     "Pass --yes to collect only these choices.\n");
            return 0;
        }
        const auto report = [&] {
            PackageStore store(root);
            return collect_troubleshooting(store, id, collection);
        }();
        if (!report_path.empty())
            export_troubleshooting(report, utf16(report_path));
        std::cout << (json ? report.json() + '\n' : report.text());
        return report.passed() ? 0 : 1;
    }
    if (command == "diagnostics") {
        const auto report = [&] {
            PackageStore store(root);
            return store.diagnostics(id);
        }(); // Release the store before writing an explicitly requested report.
        if (!report_path.empty())
            export_diagnostics(report, utf16(report_path));
        std::cout << (json ? report.json() + '\n' : report.text());
        return report.passed() ? 0 : 1;
    }
    if (command == "update") {
        if (dry_run) {
            usage(!yes, "Update previews do not accept confirmation flags");
            const auto candidate = preview(utf16(package));
            PackageStore store(root);
            const auto review = store.review_update(candidate, id);
            if (json)
                std::cout << review.json(candidate) << '\n';
            else
                std::cout << "App ID: " << review.current.id
                          << "\nCurrent version: " << review.current.version_name << " ("
                          << review.current.version_code << ")\nCurrent SHA-256: " << review.current.sha256
                          << "\nProposed version: " << candidate.inspection.manifest.version_name << " ("
                          << candidate.inspection.manifest.version_code.value_or(0)
                          << ")\nProposed SHA-256: " << candidate.inspection.sha256 << '\n'
                          << candidate.signing.text() << '\n'
                          << review.reason << '\n'
                          << (review.code.empty() ? "" : review.code + "\n");
            return 0;
        }
        if (!yes || expected_sha256.empty() || expected_current_sha256.empty())
            throw InstallError("AETHER_UPDATE_CONFIRMATION_REQUIRED",
                               "Review update --dry-run, then confirm --yes, --expected-current-sha256 and "
                               "--expected-sha256");
        output(update_package(utf16(package), root, id, expected_current_sha256, expected_sha256), "update",
               json);
        return 0;
    }
    if (windows) {
        output(install_windows(utf16(package), root, expected_sha256, allow), "install", json);
        return 0;
    }
    if (command == "launch" || command == "relaunch") {
        auto application = [&] {
            if (command == "relaunch")
                return prepare_shell_relaunch(id);
            PackageStore store(root);
            return store.prepare_launch(id);
        }(); // Release the global registry lock before entering the window message loop.
        const auto report = host::run_installed_window(std::move(application));
        std::cout << (json ? report.json() : report.text(options.contains("--verbose"))) << '\n';
        return report.passed() ? 0 : 1;
    }
    const auto access = command == "list" || command == "info" || (command == "settings" && !(allow || deny))
                            ? PackageStore::Access::read
                        : command == "repair" ? PackageStore::Access::recover
                                              : PackageStore::Access::write;
    PackageStore store(root, access);
    if (command == "install")
        output(developer ? store.install_fixture(utf16(package))
                         : store.install_package(utf16(package), expected_sha256),
               command, json);
    else if (command == "uninstall")
        output(store.uninstall(id, keep), command, json);
    else if (command == "info")
        output(store.info(id), command, json);
    else if (command == "settings")
        output((allow || deny) ? store.set_permissions(id, allow, deny, permission_review) : store.info(id),
               command, json);
    else if (command == "register")
        output(store.register_windows(id), command, json);
    else if (command == "repair") {
        const auto count = store.recover();
        if (json)
            std::cout << "{\"schemaVersion\":1,\"operation\":\"repair\",\"recoveredOperations\":" << count
                      << "}\n";
        else
            std::cout << "Recovered " << count << " interrupted registry/package operations.\n";
    } else {
        const auto apps = store.list();
        if (json) {
            std::cout << "{\"schemaVersion\":1,\"operation\":\"list\",\"contentIntegrity\":\"not-checked-use-"
                         "info\",\"apps\":[";
            bool first = true;
            for (const auto &app : apps) {
                if (!first)
                    std::cout << ',';
                first = false;
                std::cout << app.json();
            }
            std::cout << "]}\n";
        } else {
            for (const auto &app : apps)
                std::cout << app.id << "  " << app.package_id << "  " << app.version_name << "\n";
            std::cout << apps.size() << " registry entries. Use info --app-id to verify package contents.\n";
        }
    }
    return 0;
}
} // namespace aether::install
