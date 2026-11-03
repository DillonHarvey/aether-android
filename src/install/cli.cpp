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
#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>

namespace aether::install {
namespace {
// UI callbacks enqueue fixed diagnostic codes only. One host-owned writer
// persists them in order; closing/failing a session drains it before reporting.
class SessionFaults {
    AppLaunchFailure &failure_;
    std::string hash_;
    std::uint64_t generation_;
    std::mutex mutex_;
    std::condition_variable wake_;
    std::deque<DiagnosticFault> pending_;
    bool stopping_ = false;
    std::exception_ptr write_error_, event_error_;
    std::uint64_t lost_events_ = 0;
    std::thread writer_;
    // Observations are reduced on the launching/UI thread. The background
    // writer only receives the final bounded summary, never mutable UI state.
    host::WindowObservationReducer window_observations_;
    bool window_summary_attempted_ = false;
    void queue_window_summary() {
        if (window_summary_attempted_) return;
        window_summary_attempted_ = true;
        const auto &summary = window_observations_.summary();
        const auto encoded = summary.observations_seen
            ? host::window_observation_summary_json(summary)
            : std::string("{\"schemaVersion\":1,\"observationsSeen\":0}");
        constexpr std::size_t fragment_bytes = 1536;
        if (encoded.size() > 16 * 1024)
            throw InstallError("AETHER_WINDOW_OBSERVATION_LIMIT", "Window observation summary exceeds existing fault capture bounds");
        const auto parts = (encoded.size() + fragment_bytes - 1) / fragment_bytes;
        for (std::size_t part = 0; part < parts; ++part) {
            auto fault = capture_fault({}, "installed-window-observation", hash_, generation_);
            fault.code = "AETHER_WINDOW_OBSERVATION_PART";
            fault.message = "schema=1; part=" + std::to_string(part + 1) +
                "; parts=" + std::to_string(parts) + "; payload=" +
                encoded.substr(part * fragment_bytes, fragment_bytes);
            {
                std::lock_guard lock(mutex_);
                if (write_error_) std::rethrow_exception(write_error_);
                if (stopping_ || pending_.size() >= 1024)
                    throw InstallError("AETHER_FAULT_QUEUE_FULL", "Window observation summary could not all be retained");
                pending_.push_back(std::move(fault));
            }
            wake_.notify_one();
        }
    }
    void write_loop() noexcept {
        for (;;) {
            DiagnosticFault fault;
            {
                std::unique_lock lock(mutex_);
                wake_.wait(lock, [&] { return stopping_ || !pending_.empty(); });
                if (pending_.empty()) return;
                fault = std::move(pending_.front());
                pending_.pop_front();
            }
            try { retain_fault(failure_.store, failure_.app_id, fault); }
            catch (...) {
                std::lock_guard lock(mutex_);
                if (!write_error_) write_error_ = std::current_exception();
                const auto discarded = static_cast<std::uint64_t>(pending_.size()) + 1;
                lost_events_ = discarded > UINT64_MAX - lost_events_ ? UINT64_MAX : lost_events_ + discarded;
                // No retry of a failed/possibly partial write.
                pending_.clear();
                stopping_ = true;
                return;
            }
        }
    }
  public:
    SessionFaults(AppLaunchFailure &failure, const security::InstalledActivity &application)
        : failure_(failure), hash_(application.diagnostic_package_sha256),
          generation_(application.diagnostic_package_generation) {
        auto start = capture_fault({}, "installed-session", hash_, generation_);
        start.code = "AETHER_SESSION_STARTED";
        start.message = "Session admitted; absence of a later terminal record means completion is unknown.";
        // Reserve durable evidence before any guest execution. Retention failure
        // is explicit and never silently launches an unrecorded session.
        retain_fault(failure_.store, failure_.app_id, start);
        writer_ = std::thread([this] { write_loop(); });
    }
    ~SessionFaults() { drain(); }
    void drain() noexcept {
        { std::lock_guard lock(mutex_); stopping_ = true; }
        wake_.notify_one();
        if (writer_.joinable()) writer_.join();
    }
    void event(std::string_view stage, std::string_view code) {
        try {
            auto fault = capture_fault({}, stage, hash_, generation_);
            fault.code = std::string(code);
            fault.message = "Host observed diagnostic event (fixed code; no input payload collected).";
            {
                std::lock_guard lock(mutex_);
                if (write_error_) std::rethrow_exception(write_error_);
                if (stopping_ || pending_.size() >= 1024)
                    throw InstallError("AETHER_FAULT_QUEUE_FULL", "Fault queue is full; diagnostic events could not all be retained");
                pending_.push_back(std::move(fault));
            }
            wake_.notify_one();
        } catch (...) {
            std::lock_guard lock(mutex_);
            if (lost_events_ != UINT64_MAX) ++lost_events_;
            if (!event_error_) event_error_ = std::current_exception();
            throw;
        }
    }
    void window_observation(const host::WindowObservation &observation) noexcept {
        window_observations_.observe(observation);
    }
    void finish(std::exception_ptr error, const host::WindowReport *report) noexcept {
        try { queue_window_summary(); }
        catch (...) {
            std::lock_guard lock(mutex_);
            if (lost_events_ != UINT64_MAX) ++lost_events_;
            if (!event_error_) event_error_ = std::current_exception();
        }
        drain();
        try {
            auto fault = capture_fault(error, "installed-activity-session", hash_, generation_);
            if (!error) {
                fault.code = report && report->passed() ? "AETHER_SESSION_COMPLETED" : "AETHER_APP_SESSION_INCOMPLETE";
                fault.message = "Session terminal outcome; ";
                if (report) {
                    fault.message += "read_failures=" + std::to_string(report->read_failures) +
                        "; recovered_reads=" + std::to_string(report->recovered_reads) +
                        "; ime_rejected=" + std::to_string(report->ime_rejected) +
                        "; text_edit_failed=" + std::to_string(report->text_edit_failed) +
                        "; text_edit_gaps=" + std::to_string(report->text_edit_gaps) +
                        "; diagnostic_retention_failures=" + std::to_string(report->diagnostic_retention_failures);
                    for (const auto &check : report->checks)
                        if (!check.passed) {
                            if (fault.causes.size() < 16) fault.causes.push_back("Window check did not pass: " + check.name.substr(0, 512));
                            else fault.message_truncated = true;
                        }
                }
            }
            failure_.diagnostic = fault; // Keep evidence available even if disk fails.
            if (lost_events_ || (report && report->diagnostic_retention_failures))
                failure_.retention_error = "AETHER_FAULT_EVENTS_LOST: event capture failures=" +
                    std::to_string(lost_events_ ? lost_events_ : report->diagnostic_retention_failures);
            if (write_error_) std::rethrow_exception(write_error_);
            if (lost_events_) {
                auto lost = capture_fault(event_error_, "diagnostic-event-retention", hash_, generation_);
                lost.code = "AETHER_FAULT_EVENTS_LOST";
                lost.message = "Events not queued/captured=" + std::to_string(lost_events_);
                // The bounded captured event error remains represented as a cause.
                if (event_error_) {
                    const auto captured = capture_fault(event_error_, "diagnostic-event-retention", hash_, generation_);
                    lost.causes.clear();
                    lost.causes.push_back(captured.code + ": additional event capture failure; primary session fault is preserved separately");
                }
                // Keep the full primary exception chain in its own record.
                // Loss evidence is a separate record rather than displacing it.
                retain_fault(failure_.store, failure_.app_id, lost);
            }
            retain_fault(failure_.store, failure_.app_id, fault);
            if (lost_events_ || (report && report->diagnostic_retention_failures))
                failure_.retention_error = "AETHER_FAULT_EVENTS_LOST: event capture failures=" +
                    std::to_string(lost_events_ ? lost_events_ : report->diagnostic_retention_failures);
        } catch (const std::exception &retention) {
            if (!failure_.retention_error.empty()) failure_.retention_error += "; ";
            failure_.retention_error += "AETHER_FAULT_RETENTION_FAILED: " + std::string(retention.what());
            std::cerr << failure_.retention_error << '\n';
        } catch (...) {
            if (!failure_.retention_error.empty()) failure_.retention_error += "; ";
            failure_.retention_error += "AETHER_FAULT_RETENTION_FAILED: non-standard retention failure";
            std::cerr << failure_.retention_error << '\n';
        }
    }
};
void capture_launch_failure(AppLaunchFailure &failure, std::exception_ptr error) noexcept {
    try {
        failure.diagnostic = capture_fault(error, "installed-launch-preparation");
        retain_fault(failure.store, failure.app_id, *failure.diagnostic);
    } catch (const std::exception &retention) {
        failure.retention_error = "AETHER_FAULT_RETENTION_FAILED: " + std::string(retention.what());
        std::cerr << failure.retention_error << '\n';
    } catch (...) {
        failure.retention_error = "AETHER_FAULT_RETENTION_FAILED: non-standard capture failure";
    }
}
host::WindowReport recorded_window(security::InstalledActivity application, AppLaunchFailure &failure) {
    std::optional<SessionFaults> faults;
    try { faults.emplace(failure, application); }
    catch (...) {
        try {
            failure.diagnostic = capture_fault(std::current_exception(), "diagnostic-session-start");
            failure.retention_error = "AETHER_FAULT_RETENTION_FAILED: " + failure.diagnostic->message;
        } catch (...) { failure.retention_error = "AETHER_FAULT_RETENTION_FAILED: diagnostic initialization failed"; }
        throw; // No automatic retry of a failed initial history write.
    }
    try {
        auto report = host::run_installed_window(std::move(application),
            [&](std::string_view stage, std::string_view code) { faults->event(stage, code); },
            [&](const host::WindowObservation &observation) noexcept { faults->window_observation(observation); });
        faults->finish({}, &report);
        return report;
    } catch (...) {
        faults->finish(std::current_exception(), nullptr);
        throw;
    }
}
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
    try { passed = recorded_window(std::move(*application), failure).passed(); }
    catch (...) {
        application.reset();
        notify();
        // Preserve the original exception for trusted inspection while the
        // outward diagnostic cannot echo a URI through an app's error text.
        std::throw_with_nested(std::runtime_error("AETHER_OPEN_LINK_SESSION_FAILED: The selected app session failed; review local diagnostics."));
    }
    application.reset();
    if (!passed || !failure.retention_error.empty()) { failure.failure = AppSessionFailure::incomplete; notify(); passed = false; }
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
    try { passed = recorded_window(std::move(*application), failure).passed(); }
    catch (...) {
        application.reset();
        notify();
        std::throw_with_nested(std::runtime_error("AETHER_OPEN_FILE_SESSION_FAILED: The selected app session failed; review local diagnostics."));
    }
    application.reset();
    if (!passed || !failure.retention_error.empty()) { failure.failure = AppSessionFailure::incomplete; notify(); passed = false; }
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
static std::optional<int> dispatch_cli_impl(const std::vector<std::string> &arguments, bool json,
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
            report = recorded_window(std::move(application), failure);
        } catch (...) {
            notify();
            throw;
        }
        std::cout << (json ? report.json() : report.text(options.contains("--verbose"))) << '\n';
        if (!report.passed() || !failure.retention_error.empty()) {
            failure.failure = AppSessionFailure::incomplete;
            notify();
        }
        return report.passed() && failure.retention_error.empty() ? 0 : 1;
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
std::optional<int> dispatch_cli(const std::vector<std::string> &arguments, bool json,
                              const AppLaunchObserver &launch_observer,
                              const OpenLinkHandler &open_link_handler,
                              const FileOpenHandler &open_file_handler) {
    bool reported = false;
    const AppLaunchObserver observer = [&](const AppLaunchFailure &failure) {
        reported = true;
        if (launch_observer) launch_observer(failure);
    };
    try { return dispatch_cli_impl(arguments, json, observer, open_link_handler, open_file_handler); }
    catch (...) {
        // Preparation/permission/installation errors happen before a live
        // window exists. Retain them too, without recording argument payloads.
        const auto operation_error = std::current_exception();
        try {
        if (!reported) {
            const auto command = std::find_if(arguments.begin(), arguments.end(), [](const auto &value) {
                return value != "--json" && value != "--verbose";
            });
            const bool writable = command != arguments.end() &&
                (*command == "launch" || *command == "relaunch" || *command == "uninstall" ||
                 *command == "settings" || *command == "register" || *command == "update");
            if (writable) {
                std::string id;
                auto store = default_store_root();
                for (std::size_t n = 0; n + 1 < arguments.size(); ++n) {
                    if (arguments[n] == "--app-id") id = arguments[n + 1];
                    if (arguments[n] == "--store") store = std::filesystem::absolute(utf16(arguments[n + 1])).lexically_normal();
                }
                if (valid_app_id(id)) {
                    try {
                        if (*command == "relaunch") store = registered_shell_store(id);
                        AppLaunchFailure failure{store, id};
                        capture_launch_failure(failure, operation_error);
                        // Read-only queries still never write diagnostics. A
                        // failed mutation/launch reports its persistence status.
                        observer(failure);
                    } catch (...) { /* Preserve the actual operation exception. */ }
                }
            }
        }
        } catch (...) { /* Diagnostic setup cannot replace the operation error. */ }
        std::rethrow_exception(operation_error);
    }
}
} // namespace aether::install
