#include "aether/install/troubleshooting.hpp"
#include "aether/build_info.hpp"
#include "aether/common/text.hpp"
#include "aether/security/audit.hpp"
#include "private.hpp"
#include <Windows.h>
#include <algorithm>
#include <charconv>
#include <sstream>

namespace aether::install {
namespace {
constexpr std::size_t session_limit = 16, file_limit = 1024 * 1024;
const char *boolean(bool value) { return value ? "true" : "false"; }
void require(bool value, const char *code) {
    if (!value)
        throw InstallError(code, "The selected audit summaries could not be collected safely");
}
bool missing(const std::filesystem::path &path) {
    if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES)
        return false;
    const auto error = GetLastError();
    require(error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND, "AETHER_TROUBLESHOOT_AUDIT_READ");
    return true;
}
std::string selection(TroubleshootingOptions options) {
    return "{\"hostDetails\":" + std::string(boolean(options.host_details)) +
           ",\"auditSummaries\":" + boolean(options.audit_summaries) + '}';
}
std::string windows_build() {
    std::array<wchar_t, 32> value{};
    DWORD bytes = static_cast<DWORD>(sizeof(value));
    if (RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                     L"CurrentBuildNumber", RRF_RT_REG_SZ, nullptr, value.data(), &bytes) != ERROR_SUCCESS)
        return "unavailable";
    const auto text = utf8(value.data());
    return !text.empty() && text.size() <= 10 && text.find_first_not_of("0123456789") == std::string::npos
               ? text
               : "unavailable";
}
AuditSessionSummary inspect_session(const std::filesystem::path &path, std::uint64_t broker,
                                    const std::string &session) {
    AuditSessionSummary result;
    result.session = session;
    result.state = "unavailable";
    try {
        auto file =
            detail::private_file(path, GENERIC_READ, OPEN_EXISTING, file_limit, FILE_SHARE_READ, true);
        const auto bytes = detail::read_contents(file.get());
        const auto summary = security::inspect_audit(bytes);
        std::uint64_t expected = 0;
        const auto parsed = std::from_chars(session.data(), session.data() + session.size(), expected, 16);
        require(parsed.ec == std::errc{} && parsed.ptr == session.data() + session.size() &&
                    summary.context.app_id == broker && summary.context.session == expected &&
                    summary.context.worker_process &&
                    summary.context.worker_process != summary.context.parent_process,
                "AETHER_TROUBLESHOOT_AUDIT_IDENTITY");
        result.sha256 = apk::sha256(bytes);
        result.records = summary.records;
        result.intents = summary.intents;
        result.outcomes = summary.outcomes;
        result.pending = summary.pending;
        result.aborted = summary.aborted;
        result.state = !summary.ended ? "unfinished" : summary.aborted ? "aborted" : "completed";
        for (std::size_t offset = 0; offset < bytes.size(); offset += security::audit_record_bytes) {
            const auto record =
                security::decode_audit_record(std::span(bytes).subspan(offset, security::audit_record_bytes));
            if (record.kind == security::AuditKind::outcome) {
                ++result.statuses.at(static_cast<std::size_t>(record.entry.status));
                result.uncertain_outcomes += record.flags != 0;
            }
        }
    } catch (const InstallError &error) {
        result.code = error.code;
    } catch (const security::ProtocolError &) {
        result.code = "AETHER_TROUBLESHOOT_AUDIT_CORRUPT";
    }
    return result;
}
void collect_audits(TroubleshootingReport &report, const std::filesystem::path &root) {
    try {
        const auto app_path = root / report.diagnostics.app.id;
        if (missing(app_path)) {
            report.audit_status = "absent";
            return;
        }
        const auto app = detail::hold_directory(app_path, false, true);
        host::UniqueHandle lease;
        if (!missing(app_path / L"session.lock"))
            lease = detail::private_file(app_path / L"session.lock", GENERIC_READ, OPEN_EXISTING, 0);
        const auto audit_path = app_path / L"audit";
        if (missing(audit_path)) {
            report.audit_status = "absent";
            return;
        }
        const auto directory = detail::hold_directory(audit_path, false, true);
        std::vector<std::filesystem::path> paths;
        for (const auto &entry : std::filesystem::directory_iterator(audit_path)) {
            require(paths.size() < session_limit, "AETHER_TROUBLESHOOT_AUDIT_LIMIT");
            const auto name = entry.path().filename().wstring();
            require(name.size() == 30 && name.starts_with(L"session_") && name.ends_with(L".audit") &&
                        name.substr(8, 16).find_first_not_of(L"0123456789abcdef") == std::wstring::npos,
                    "AETHER_TROUBLESHOOT_AUDIT_NAME");
            paths.push_back(entry.path());
        }
        std::sort(paths.begin(), paths.end());
        for (const auto &path : paths) {
            report.sessions.push_back(
                inspect_session(path, security::installed_broker_id(report.diagnostics.app.id),
                                utf8(path.filename().wstring().substr(8, 16))));
            if (!report.sessions.back().code.empty())
                report.collection_complete = false;
        }
        report.audit_status = report.collection_complete ? "collected" : "partial";
    } catch (const std::exception &error) {
        report.collection_complete = false;
        report.audit_status = "unavailable";
        const auto *install = dynamic_cast<const InstallError *>(&error);
        report.audit_code = install ? install->code : "AETHER_TROUBLESHOOT_AUDIT_READ";
        report.sessions.clear();
    }
}
} // namespace

std::string troubleshooting_plan(TroubleshootingOptions options) {
    return "Includes this app's diagnostics and selected optional details.\nWindows and Aether build "
           "details: " +
           std::string(options.host_details ? "selected" : "not selected") +
           "\nAudit session summaries (completion and request/error counts): " +
           (options.audit_summaries ? "selected" : "not selected") +
           "\nAudit limit: 16 sessions, 1 MiB per file. Active or unsafe logs are reported as unavailable.\n"
           "No host paths, usernames, process IDs, absolute timestamps, raw log records, private files, "
           "environment or memory. Nothing is uploaded. Review the captured preview before sharing.\n";
}
std::string troubleshooting_preview(const InstalledApp &app, TroubleshootingOptions options) {
    return "{\"schemaVersion\":1,\"operation\":\"troubleshoot-preview\",\"appId\":" + json_quote(app.id) +
           ",\"packageId\":" + json_quote(app.package_id) + ",\"selection\":" + selection(options) +
           ",\"optionalSourcesRead\":false,\"confirmationRequired\":true,\"plan\":" +
           json_quote(troubleshooting_plan(options)) + '}';
}
TroubleshootingReport collect_troubleshooting(const PackageStore &store, std::string_view id,
                                              TroubleshootingOptions options) {
    TroubleshootingReport report;
    report.diagnostics = store.diagnostics(id);
    report.options = options;
    if (options.host_details) {
        report.windows_build = windows_build();
        SYSTEM_INFO info{};
        GetNativeSystemInfo(&info);
        report.architecture = info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64   ? "x64"
                              : info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64 ? "arm64"
                                                                                            : "other";
    }
    if (options.audit_summaries)
        collect_audits(report, store.root());
    if (options.host_details && report.windows_build == "unavailable")
        report.collection_complete = false;
    return report;
}
bool TroubleshootingReport::passed() const { return collection_complete && diagnostics.passed(); }
std::string TroubleshootingReport::json() const {
    std::ostringstream out;
    out << "{\"schemaVersion\":1,\"operation\":\"troubleshoot\",\"collectionComplete\":"
        << boolean(collection_complete)
        << ",\"readOnlyCollection\":true,\"guestExecution\":false,\"selection\":" << selection(options)
        << ",\"diagnostics\":" << diagnostics.json() << ",\"hostDetails\":";
    if (!options.host_details)
        out << "null";
    else
        out << "{\"windowsBuild\":" << json_quote(windows_build)
            << ",\"nativeArchitecture\":" << json_quote(architecture)
            << ",\"aetherVersion\":" << json_quote(build::version)
            << ",\"configuration\":" << json_quote(build::configuration)
            << ",\"compiler\":" << json_quote(build::compiler) << '}';
    out << ",\"auditSummaries\":{\"status\":" << json_quote(audit_status)
        << ",\"code\":" << json_quote(audit_code) << ",\"maximumSessions\":16,\"maximumFileBytes\":1048576,"
        << "\"contentAuthenticityEstablished\":false,\"sessions\":[";
    for (std::size_t n = 0; n < sessions.size(); ++n) {
        const auto &s = sessions[n];
        out << (n ? "," : "") << "{\"session\":" << json_quote(s.session)
            << ",\"state\":" << json_quote(s.state) << ",\"code\":" << json_quote(s.code)
            << ",\"sha256\":" << json_quote(s.sha256) << ",\"records\":" << s.records
            << ",\"intents\":" << s.intents << ",\"outcomes\":" << s.outcomes
            << ",\"pending\":" << boolean(s.pending) << ",\"aborted\":" << boolean(s.aborted)
            << ",\"uncertainOutcomes\":" << s.uncertain_outcomes << ",\"outcomeCounts\":{";
        constexpr std::array names = {"ok", "denied", "unsupported", "invalid", "quota"};
        for (std::size_t i = 0; i < names.size(); ++i)
            out << (i ? "," : "") << json_quote(names[i]) << ':' << s.statuses[i];
        out << "}}";
    }
    out << "]},\"excluded\":[\"host-paths\",\"usernames\",\"process-ids\",\"absolute-timestamps\","
           "\"raw-audit-records\",\"private-app-files\",\"environment\",\"memory\"],\"uploaded\":false}";
    return out.str();
}
std::string TroubleshootingReport::text() const {
    std::ostringstream out;
    out << "Captured troubleshooting bundle: "
        << (collection_complete ? "collection complete" : "some details unavailable") << "\n"
        << troubleshooting_plan(options) << '\n'
        << diagnostics.text();
    if (options.host_details)
        out << "\nWindows build: " << windows_build << "; architecture: " << architecture
            << "\nAether: " << build::version << " " << build::configuration << "; " << build::compiler
            << '\n';
    if (options.audit_summaries) {
        out << "\nAudit summaries: " << audit_status << ' ' << audit_code << '\n';
        for (const auto &s : sessions) {
            out << "Session " << s.session << ": " << s.state << ' ' << s.code << "; records=" << s.records
                << ", intents=" << s.intents << ", outcomes=" << s.outcomes
                << ", pending=" << boolean(s.pending) << ", uncertain=" << s.uncertain_outcomes
                << "\n  ok/denied/unsupported/invalid/quota:";
            for (const auto count : s.statuses)
                out << ' ' << count;
            out << '\n';
        }
        out << "Audit structure/identity checks do not authenticate who wrote its contents.\n";
    }
    return out.str();
}
void export_troubleshooting(const TroubleshootingReport &report, const std::filesystem::path &destination) {
    detail::export_report_json(report.json(), destination);
}
} // namespace aether::install
