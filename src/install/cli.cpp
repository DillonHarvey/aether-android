#include "aether/install/cli.hpp"
#include "aether/common/text.hpp"
#include "aether/dex/fixture_hash.hpp"
#include "aether/host/window.hpp"
#include "aether/install/diagnostics.hpp"
#include "aether/install/explorer.hpp"
#include "aether/install/privacy.hpp"
#include "aether/install/open_link.hpp"
#include "aether/install/open_file.hpp"
#include "aether/install/link_registration.hpp"
#include "aether/security/activity_launch.hpp"
#include "aether/install/runtime.hpp"
#include "aether/install/shell.hpp"
#include "aether/install/store.hpp"
#include "aether/install/troubleshooting.hpp"
#include <array>
#include <algorithm>
#include <iostream>
#include <exception>
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
int open_link_cli(const OpenLinkOptions &options, bool json, const AppLaunchObserver &observer,
                  const OpenLinkHandler &handler) {
    if (!handler) {
        const auto review = [&] {
            PackageStore store(options.store);
            if (options.registered_activation) {
                usage(options.app_id.has_value(), "Registered opening requires an app identity");
                require_registered_link_offer(store, *options.app_id, options.uri);
            }
            return store.review_link(make_open_link_intent(options.uri), open_link_policy(), options.app_id);
        }();
        // A headless query is read-only. URI text, guest result text and raw
        // errors never become output or an implicit launch confirmation.
        if (json) {
            std::cout << "{\"schemaVersion\":1,\"operation\":\"open-link\",\"launched\":false,\"complete\":"
                      << (review.complete ? "true" : "false") << ",\"choices\":[";
            bool first = true;
            for (const auto &row : review.rows) {
                if (!first) std::cout << ',';
                first = false;
                std::cout << "{\"appId\":" << json_quote(row.app_id) << ",\"package\":" << json_quote(row.package_id)
                          << ",\"component\":" << json_quote(row.component_name) << ",\"target\":" << json_quote(row.target_name)
                          << ",\"sha256\":" << json_quote(row.apk_hash) << ",\"selectable\":"
                          << (row.disposition == LinkDisposition::candidate ? "true" : "false")
                          << ",\"code\":" << json_quote(row.code) << '}';
            }
            std::cout << "]}\n";
        } else {
            std::size_t choices = 0;
            for (const auto &row : review.rows) if (row.disposition == LinkDisposition::candidate) ++choices;
            std::cout << choices << " matching Activity choices. No app launched. Use the Aether shell open-link review to select one.\n";
            if (!review.complete) std::cout << "Some installed alternatives could not be admitted or checked.\n";
        }
        return 0;
    }
    auto application = handler(options);
    if (!application) {
        if (json) std::cout << "{\"schemaVersion\":1,\"operation\":\"open-link\",\"cancelled\":true,\"launched\":false}\n";
        return 0;
    }
    if (!application->launch || !application->launch->user_selected)
        throw InstallError("AETHER_OPEN_LINK_REVIEW_INVALID", "The review did not produce a bound matching Activity choice");
    AppLaunchFailure failure{application->data_root.parent_path().parent_path(), application->id};
    const auto notify = [&]() noexcept {
        if (observer) try { observer(failure); } catch (...) { /* Preserve the session result. */ }
    };
    bool passed = false;
    try { passed = host::run_installed_window(std::move(*application)).passed(); }
    catch (...) {
        application.reset();
        notify();
        // Preserve the original exception for trusted inspection while the
        // outward diagnostic cannot echo a URI through an app's error text.
        std::throw_with_nested(std::runtime_error("AETHER_OPEN_LINK_SESSION_FAILED: The selected app session failed; review local diagnostics."));
    }
    application.reset();
    if (!passed) { failure.failure = AppSessionFailure::incomplete; notify(); }
    if (json)
        std::cout << "{\"schemaVersion\":1,\"operation\":\"open-link\",\"launched\":true,\"passed\":"
                  << (passed ? "true" : "false") << "}\n";
    else std::cout << (passed ? "Selected app session completed.\n" : "Selected app session did not complete.\n");
    return passed ? 0 : 1;
}
int open_file_cli(const OpenFileOptions &options, bool json, const AppLaunchObserver &observer,
                  const FileOpenHandler &handler) {
    if (!handler) {
        // Holding the source is metadata preparation, never guest authority.
        // A headless query cannot approve a document or start an Activity.
        const auto source = host::prepare_document_source(options.file, options.mime_type);
        const auto review = [&] {
            PackageStore store(options.store);
            if (options.registered_activation) {
                usage(options.app_id.has_value(), "Registered file opening requires an app identity");
                require_registered_file_offer(store, *options.app_id, options.file, options.mime_type);
            }
            return store.review_link(make_open_file_intent(source.info), open_file_policy(), options.app_id);
        }();
        if (json) {
            std::cout << "{\"schemaVersion\":1,\"operation\":\"open-file\",\"launched\":false,\"readAccessGranted\":false,\"complete\":"
                      << (review.complete ? "true" : "false") << ",\"choices\":[";
            bool first = true;
            for (const auto &row : review.rows) {
                if (!first) std::cout << ',';
                first = false;
                std::cout << "{\"appId\":" << json_quote(row.app_id) << ",\"package\":" << json_quote(row.package_id)
                          << ",\"component\":" << json_quote(row.component_name) << ",\"target\":" << json_quote(row.target_name)
                          << ",\"sha256\":" << json_quote(row.apk_hash) << ",\"selectable\":"
                          << (row.disposition == LinkDisposition::candidate ? "true" : "false")
                          << ",\"code\":" << json_quote(row.code) << '}';
            }
            std::cout << "]}\n";
        } else {
            const auto count = std::count_if(review.rows.begin(), review.rows.end(), [](const auto &row) {
                return row.disposition == LinkDisposition::candidate;
            });
            std::cout << count << " matching Activity choices. No app launched or document access granted. "
                         "Use the Aether shell open-file review to approve read-only access.\n";
            if (!review.complete) std::cout << "Some installed alternatives could not be admitted or checked.\n";
        }
        return 0;
    }
    auto application = handler(options);
    if (!application) {
        if (json) std::cout << "{\"schemaVersion\":1,\"operation\":\"open-file\",\"cancelled\":true,\"launched\":false}\n";
        return 0;
    }
    if (!application->launch || !application->launch->user_selected || !application->read_document ||
        !application->read_document->service || !application->launch->read_document ||
        *application->launch->read_document != application->read_document->info ||
        application->launch->intent.flags != 0x10000001u ||
        (options.app_id && application->id != *options.app_id))
        throw InstallError("AETHER_OPEN_FILE_REVIEW_INVALID", "The review did not produce a bound read-only document and Activity choice");
    application->launch->validate();
    AppLaunchFailure failure{application->data_root.parent_path().parent_path(), application->id};
    const auto notify = [&]() noexcept {
        if (observer) try { observer(failure); } catch (...) { /* Preserve the original session result. */ }
    };
    bool passed = false;
    try { passed = host::run_installed_window(std::move(*application)).passed(); }
    catch (...) {
        application.reset();
        notify();
        std::throw_with_nested(std::runtime_error("AETHER_OPEN_FILE_SESSION_FAILED: The selected app session failed; review local diagnostics."));
    }
    application.reset();
    if (!passed) { failure.failure = AppSessionFailure::incomplete; notify(); }
    if (json)
        std::cout << "{\"schemaVersion\":1,\"operation\":\"open-file\",\"launched\":true,\"passed\":"
                  << (passed ? "true" : "false") << "}\n";
    else std::cout << (passed ? "Selected app session completed.\n" : "Selected app session did not complete.\n");
    return passed ? 0 : 1;
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
int link_handlers_cli(const std::vector<std::string> &arguments, bool json) {
    std::set<std::string> seen;
    std::vector<std::string> schemes;
    std::vector<FileAssociation> files;
    std::string action, id, path;
    bool command = false, yes = false;
    for (std::size_t index = 0; index < arguments.size(); ++index) {
        const auto &arg = arguments[index];
        if (arg == "--scheme") {
            usage(index + 1 < arguments.size() && !arguments[index + 1].empty() &&
                      !arguments[index + 1].starts_with('-'), "--scheme requires a lowercase URI scheme");
            usage(schemes.size() < 32, "At most 32 schemes may be offered");
            schemes.push_back(arguments[++index]);
        } else if (arg == "--file-type") {
            usage(index + 1 < arguments.size() && !arguments[index + 1].empty() &&
                      !arguments[index + 1].starts_with('-'), "--file-type requires .extension=type/subtype");
            usage(files.size() < 32, "At most 32 file types may be offered");
            const auto &pair = arguments[++index];
            const auto equals = pair.find('=');
            usage(equals != std::string::npos && equals > 0 && equals + 1 < pair.size(),
                  "--file-type requires .extension=type/subtype");
            files.push_back({pair.substr(0, equals), pair.substr(equals + 1)});
        } else if (arg == "--json" || arg == "--verbose" || arg == "--yes" ||
                   arg == "--app-id" || arg == "--store") {
            usage(seen.insert(arg).second, "A link-handlers option was specified more than once");
            if (arg == "--yes") yes = true;
            if (arg == "--app-id" || arg == "--store") {
                usage(index + 1 < arguments.size() && !arguments[index + 1].empty() &&
                          !arguments[index + 1].starts_with('-'), "The link-handlers option requires a value");
                (arg == "--app-id" ? id : path) = arguments[++index];
            }
        } else if (!command && arg == "link-handlers") command = true;
        else {
            usage(command && action.empty() &&
                      (arg == "status" || arg == "register" || arg == "repair" || arg == "remove"),
                  "Use link-handlers status|register|repair|remove --app-id ID; changes require --yes");
            action = arg;
        }
    }
    usage(!action.empty() && valid_app_id(id), "link-handlers requires an action and a valid --app-id");
    usage((action == "register") == (!schemes.empty() || !files.empty()),
          "Only register accepts and requires --scheme and/or --file-type values");
    usage(action != "status" || !yes, "Read-only link-handlers status does not accept --yes");
    if (action != "status" && !yes)
        throw InstallError("AETHER_INSTALL_CONFIRMATION_REQUIRED",
                           "Link handler changes require --yes; Windows defaults and UserChoice are preserved");
    const auto root = path.empty() ? registered_shell_store(id) : std::filesystem::path(utf16(path));
    usage(root.is_absolute(), "--store requires an absolute local path");
    RuntimeUseLease runtime(root);
    PackageStore store(root);
    const auto app = [&] {
        if (action != "remove") return store.info(id);
        // Removing an owned offer must not require damaged package bytes to
        // become readable again. The held journal remains authoritative.
        const auto apps = store.list();
        const auto found = std::find_if(apps.begin(), apps.end(), [&](const auto &item) { return item.id == id; });
        // list() omits removed rows, but their journal identity still permits
        // explicit cleanup of an owned orphan offer without reviving the app.
        if (found == apps.end()) return store.info(id);
        return *found;
    }();
    const auto operation = action == "status" ? LinkRegistrationOperation::status
                         : action == "register" ? LinkRegistrationOperation::register_handler
                         : action == "repair" ? LinkRegistrationOperation::repair : LinkRegistrationOperation::remove;
    const auto result = link_registration(operation, app, store.root(), schemes, true, files);
    if (json) std::cout << result.json() << '\n';
    else std::cout << "Link offers: " << result.state << "\nVerified: " << (result.verified ? "yes" : "no")
                   << "\nWindows defaults and UserChoice remain user-controlled.\n";
    return 0;
}
} // namespace
int dispatch_open_link(const OpenLinkOptions &options, bool json,
                       const AppLaunchObserver &observer, const OpenLinkHandler &handler) {
    return open_link_cli(options, json, observer, handler);
}
int dispatch_open_file(const OpenFileOptions &options, bool json,
                       const AppLaunchObserver &observer, const FileOpenHandler &handler) {
    return open_file_cli(options, json, observer, handler);
}
std::optional<int> dispatch_cli(const std::vector<std::string> &arguments, bool json,
                              const AppLaunchObserver &launch_observer, const OpenLinkHandler &open_link_handler,
                              const FileOpenHandler &open_file_handler) {
    std::string command;
    for (const auto &arg : arguments) {
        if (arg == "--json" || arg == "--verbose")
            continue;
        command = arg;
        break;
    }
    if (command == "explorer")
        return explorer_cli(arguments, json);
    if (command == "link-handlers")
        return link_handlers_cli(arguments, json);
    if (command == "runtime")
        return runtime_cli(arguments, json);
    if (command == "open-link") {
        const auto options = parse_open_link_options(arguments);
        return open_link_cli(options, json || options.json, launch_observer, open_link_handler);
    }
    if (command == "open-file") {
        const auto options = parse_open_file_options(arguments);
        return open_file_cli(options, json || options.json, launch_observer, open_file_handler);
    }
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
                arg == "--deny-private-files" || arg == "--allow-wall-clock" || arg == "--deny-wall-clock" ||
                arg == "--allow-audio-playback" || arg == "--deny-audio-playback" ||
                arg == "--allow-notifications" || arg == "--deny-notifications" ||
                arg == "--allow-clipboard" || arg == "--deny-clipboard") {
                const auto bit =
                    arg.ends_with("clipboard") ? security::installed_clipboard :
                    arg.ends_with("notifications") ? security::installed_notifications :
                    arg.ends_with("audio-playback") ? security::installed_audio_playback :
                    arg.ends_with("wall-clock") ? security::installed_wall_clock :
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
        if (expected_permissions != "none") {
            std::string_view remaining = expected_permissions;
            while (!remaining.empty()) {
                const auto comma = remaining.find(',');
                const auto name = remaining.substr(0, comma);
                const auto bit = name == "monotonic-clock" ? security::installed_clock
                               : name == "private-files" ? security::installed_files
                               : name == "wall-clock" ? security::installed_wall_clock
                               : name == "audio-playback" ? security::installed_audio_playback
                               : name == "notifications" ? security::installed_notifications
                               : name == "clipboard" ? security::installed_clipboard : 0;
                usage(bit && !(mask & bit), "Expected permissions contain an unknown or duplicate grant");
                mask |= bit;
                if (comma == std::string_view::npos)
                    break;
                remaining.remove_prefix(comma + 1);
                usage(!remaining.empty(), "Expected permissions contain an empty grant");
            }
        }
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
        // The prepared app supplies the authoritative store, including relaunch
        // from a custom store. Never guess that a registered pin uses the default.
        AppLaunchFailure failure{application.data_root.parent_path().parent_path(), application.id};
        const auto notify = [&]() noexcept {
            if (launch_observer)
                try {
                    launch_observer(failure);
                } catch (...) { /* Reporting must preserve the original launch outcome. */ }
        };
        host::WindowReport report;
        try {
            report = host::run_installed_window(std::move(application));
        } catch (...) {
            notify();
            throw;
        }
        std::cout << (json ? report.json() : report.text(options.contains("--verbose"))) << '\n';
        if (!report.passed()) {
            failure.failure = AppSessionFailure::incomplete;
            notify();
        }
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
